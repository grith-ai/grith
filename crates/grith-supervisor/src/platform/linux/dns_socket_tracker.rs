// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Process/FD-table scoped state used by the DNS inspector.
//!
//! Linux file descriptors belong to an FD table, while duplicated and
//! fork-inherited descriptors refer to a shared open file description.  DNS
//! routing state therefore cannot live directly in an FD map: reconnecting a
//! socket through one alias changes the peer for every alias.  The tracker
//! models the kernel relationship explicitly:
//!
//! ```text
//! tgid -> FdTableId
//! FdTableId + fd -> SocketId
//! SocketId -> SocketState
//! ```
//!
//! `CLONE_FILES` shares an `FdTableId`. A normal fork snapshots the descriptor
//! map into a new table but preserves each `SocketId`.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SocketType {
    Stream,
    Datagram,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FdTableId(pub(crate) u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SocketId(pub(crate) u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct DnsRouteId(pub(crate) u64);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum DnsRoute {
    #[default]
    None,
    InlineDns {
        resolver: Option<SocketAddr>,
    },
    ConnectedProxy {
        route_id: DnsRouteId,
        original_resolver: SocketAddr,
        proxy_endpoint: SocketAddr,
    },
}

impl DnsRoute {
    pub(crate) fn route_id(&self) -> Option<DnsRouteId> {
        match self {
            Self::ConnectedProxy { route_id, .. } => Some(*route_id),
            Self::None | Self::InlineDns { .. } => None,
        }
    }

    pub(crate) fn is_dns(&self) -> bool {
        !matches!(self, Self::None)
    }

    pub(crate) fn is_connected_proxy(&self) -> bool {
        matches!(self, Self::ConnectedProxy { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QueryMetadata {
    pub id: u16,
    pub domain: String,
    pub qtype: u16,
}

#[derive(Debug)]
pub(crate) struct SocketState {
    pub socket_type: SocketType,
    /// The application-selected peer. For a proxy-routed socket this remains
    /// the original resolver, not the loopback proxy endpoint.
    pub connected_destination: Option<SocketAddr>,
    pub dns_route: DnsRoute,
    pub outstanding_queries: HashMap<u16, Vec<QueryMetadata>>,
    /// Number of descriptor entries across distinct FD tables that refer to
    /// this socket. Multiple TGIDs sharing one `FdTableId` do not multiply it.
    descriptor_refs: usize,
    /// Temporary references held by pending syscall-exit transactions. This
    /// prevents a sibling close/reuse race from destroying route state before
    /// the stopped syscall can be reconciled.
    operation_refs: usize,
    /// A connect/reconnect/disconnect transaction exclusively owns peer and
    /// route mutation while true.
    connect_in_progress: bool,
}

impl SocketState {
    fn new(socket_type: SocketType) -> Self {
        Self {
            socket_type,
            connected_destination: None,
            dns_route: DnsRoute::None,
            outstanding_queries: HashMap::new(),
            descriptor_refs: 0,
            operation_refs: 0,
            connect_in_progress: false,
        }
    }

    fn replace_route(&mut self, route: DnsRoute) -> Option<DnsRouteId> {
        let new_route_id = route.route_id();
        let old = std::mem::replace(&mut self.dns_route, route);
        let old_route_id = old.route_id();
        if old_route_id != new_route_id {
            self.outstanding_queries.clear();
            old_route_id
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Default)]
struct FdTable {
    sockets: HashMap<i32, SocketId>,
}

/// Result of committing a route to a shared socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RouteTransition {
    pub socket_id: SocketId,
    /// A previous connected-proxy route which no longer owns the socket and
    /// should be released by the caller.
    pub released_route: Option<DnsRouteId>,
}

/// Tracks descriptor tables separately from shared socket state.
#[derive(Debug)]
pub(crate) struct DnsSocketTracker {
    process_tables: HashMap<u32, FdTableId>,
    tables: HashMap<FdTableId, FdTable>,
    sockets: HashMap<SocketId, SocketState>,
    next_table_id: u64,
    next_socket_id: u64,
}

impl Default for DnsSocketTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsSocketTracker {
    pub(crate) fn new() -> Self {
        Self {
            process_tables: HashMap::new(),
            tables: HashMap::new(),
            sockets: HashMap::new(),
            next_table_id: 1,
            next_socket_id: 1,
        }
    }

    fn allocate_table_id(&mut self) -> FdTableId {
        let id = FdTableId(self.next_table_id);
        self.next_table_id = self
            .next_table_id
            .checked_add(1)
            .expect("DNS FD-table identity exhausted");
        id
    }

    fn allocate_socket_id(&mut self) -> SocketId {
        let id = SocketId(self.next_socket_id);
        self.next_socket_id = self
            .next_socket_id
            .checked_add(1)
            .expect("DNS socket identity exhausted");
        id
    }

    fn ensure_process(&mut self, tgid: u32) -> FdTableId {
        if let Some(id) = self.process_tables.get(&tgid) {
            return *id;
        }
        let id = self.allocate_table_id();
        self.process_tables.insert(tgid, id);
        self.tables.insert(id, FdTable::default());
        id
    }

    fn table_id(&self, tgid: u32) -> Option<FdTableId> {
        self.process_tables.get(&tgid).copied()
    }

    pub(crate) fn socket_id(&self, tgid: u32, fd: i32) -> Option<SocketId> {
        let table_id = self.table_id(tgid)?;
        self.tables.get(&table_id)?.sockets.get(&fd).copied()
    }

    /// Every fd `tgid` currently has a tracked socket for. Used to re-derive
    /// connected-datagram stepping from surviving sockets (incl. dup'd aliases,
    /// which share socket identity but are distinct fd numbers) rather than from
    /// the fd the `connect` happened on (go-live review B13 alias variants).
    pub(crate) fn tracked_fds(&self, tgid: u32) -> Vec<i32> {
        self.table_id(tgid)
            .and_then(|id| self.tables.get(&id))
            .map(|table| table.sockets.keys().copied().collect())
            .unwrap_or_default()
    }

    pub(crate) fn socket_matches(&self, tgid: u32, fd: i32, socket_id: SocketId) -> bool {
        self.socket_id(tgid, fd) == Some(socket_id)
    }

    pub(crate) fn socket(&self, tgid: u32, fd: i32) -> Option<&SocketState> {
        let socket_id = self.socket_id(tgid, fd)?;
        self.sockets.get(&socket_id)
    }

    pub(crate) fn socket_mut(&mut self, tgid: u32, fd: i32) -> Option<&mut SocketState> {
        let socket_id = self.socket_id(tgid, fd)?;
        self.sockets.get_mut(&socket_id)
    }

    #[cfg(test)]
    pub(crate) fn socket_by_id(&self, socket_id: SocketId) -> Option<&SocketState> {
        self.sockets.get(&socket_id)
    }

    fn increment_descriptor_ref(&mut self, socket_id: SocketId) {
        self.sockets
            .get_mut(&socket_id)
            .expect("FD table must not reference an unknown SocketId")
            .descriptor_refs += 1;
    }

    fn decrement_descriptor_ref(&mut self, socket_id: SocketId) -> Option<DnsRouteId> {
        let remove = {
            let state = self
                .sockets
                .get_mut(&socket_id)
                .expect("FD table must not reference an unknown SocketId");
            debug_assert!(state.descriptor_refs > 0);
            state.descriptor_refs -= 1;
            state.descriptor_refs == 0 && state.operation_refs == 0
        };
        if remove {
            self.sockets
                .remove(&socket_id)
                .and_then(|state| state.dns_route.route_id())
        } else {
            None
        }
    }

    /// Assign an FD entry to a shared socket and return a route released by
    /// replacing the FD's previous final alias.
    fn assign_fd(
        &mut self,
        table_id: FdTableId,
        fd: i32,
        socket_id: SocketId,
    ) -> Option<DnsRouteId> {
        let previous = self
            .tables
            .get_mut(&table_id)
            .expect("known process must have an FD table")
            .sockets
            .insert(fd, socket_id);
        if previous == Some(socket_id) {
            return None;
        }
        self.increment_descriptor_ref(socket_id);
        previous.and_then(|old| self.decrement_descriptor_ref(old))
    }

    /// A successful `socket()` proves any previous descriptor state was stale.
    /// The returned route, if any, lost its final alias and must be torn down.
    pub(crate) fn observe_socket(
        &mut self,
        tgid: u32,
        fd: i32,
        socket_type: SocketType,
    ) -> Option<DnsRouteId> {
        let table_id = self.ensure_process(tgid);
        let socket_id = self.allocate_socket_id();
        self.sockets
            .insert(socket_id, SocketState::new(socket_type));
        self.assign_fd(table_id, fd, socket_id)
    }

    pub(crate) fn socket_type(&self, tgid: u32, fd: i32) -> Option<SocketType> {
        self.socket(tgid, fd).map(|s| s.socket_type)
    }

    pub(crate) fn dns_route(&self, tgid: u32, fd: i32) -> Option<&DnsRoute> {
        self.socket(tgid, fd).map(|s| &s.dns_route)
    }

    pub(crate) fn is_connected_proxy(&self, tgid: u32, fd: i32) -> bool {
        self.dns_route(tgid, fd)
            .is_some_and(DnsRoute::is_connected_proxy)
    }

    /// Return whether any tracked open-file description still owns a managed
    /// connected-DNS route.
    ///
    /// A live route changes the kernel socket peer to a session-local loopback
    /// endpoint. Detaching while one exists would let the process outlive the
    /// endpoint and strand its DNS socket, so detach paths use this as a
    /// conservative session-fatal gate.
    pub(crate) fn has_connected_proxy_routes(&self) -> bool {
        self.sockets
            .values()
            .any(|socket| socket.dns_route.is_connected_proxy())
    }

    /// Preserve the current call-site behaviour by committing a successful
    /// direct connect immediately. New connect-exit code should call this only
    /// after observing success.
    ///
    /// Returns a connected-proxy route displaced by the new peer.
    #[cfg(test)]
    pub(crate) fn connect(
        &mut self,
        tgid: u32,
        fd: i32,
        destination: SocketAddr,
    ) -> Option<DnsRouteId> {
        let socket_id = self.socket_id(tgid, fd)?;
        self.connect_socket(socket_id, destination)
    }

    pub(crate) fn connect_socket(
        &mut self,
        socket_id: SocketId,
        destination: SocketAddr,
    ) -> Option<DnsRouteId> {
        let socket = self.sockets.get_mut(&socket_id)?;
        socket.connected_destination = Some(destination);
        let route = if socket.socket_type == SocketType::Datagram && destination.port() == 53 {
            DnsRoute::InlineDns {
                resolver: Some(destination),
            }
        } else {
            DnsRoute::None
        };
        socket.replace_route(route)
    }

    /// Commit a successful `connect(AF_UNSPEC)`/datagram disconnect.
    #[cfg(test)]
    pub(crate) fn disconnect(&mut self, tgid: u32, fd: i32) -> Option<DnsRouteId> {
        let socket_id = self.socket_id(tgid, fd)?;
        self.disconnect_socket(socket_id)
    }

    pub(crate) fn disconnect_socket(&mut self, socket_id: SocketId) -> Option<DnsRouteId> {
        let socket = self.sockets.get_mut(&socket_id)?;
        socket.connected_destination = None;
        socket.replace_route(DnsRoute::None)
    }

    /// Install a ready connected-proxy route on the socket currently referenced
    /// by `(tgid, fd)`. Returns `None` for an unknown or non-datagram socket.
    #[cfg(test)]
    pub(crate) fn set_connected_proxy(
        &mut self,
        tgid: u32,
        fd: i32,
        route_id: DnsRouteId,
        original_resolver: SocketAddr,
        proxy_endpoint: SocketAddr,
    ) -> Option<RouteTransition> {
        let socket_id = self.socket_id(tgid, fd)?;
        self.set_connected_proxy_for_socket(socket_id, route_id, original_resolver, proxy_endpoint)
    }

    /// SocketId form used by pending connect-exit state. It remains valid while
    /// the caller holds an operation pin even if a sibling closes or reuses the
    /// numeric FD.
    pub(crate) fn set_connected_proxy_for_socket(
        &mut self,
        socket_id: SocketId,
        route_id: DnsRouteId,
        original_resolver: SocketAddr,
        proxy_endpoint: SocketAddr,
    ) -> Option<RouteTransition> {
        let socket = self.sockets.get_mut(&socket_id)?;
        if socket.socket_type != SocketType::Datagram {
            return None;
        }
        socket.connected_destination = Some(original_resolver);
        let released_route = socket.replace_route(DnsRoute::ConnectedProxy {
            route_id,
            original_resolver,
            proxy_endpoint,
        });
        Some(RouteTransition {
            socket_id,
            released_route,
        })
    }

    pub(crate) fn discover_dns(&mut self, tgid: u32, fd: i32, destination: SocketAddr) -> bool {
        if self.socket(tgid, fd).is_none() {
            // A successful UDP-style send with an explicit sockaddr supplies
            // enough evidence for attach/inherited descriptors which predate
            // socket() observation.
            self.observe_socket(tgid, fd, SocketType::Datagram);
        }
        let Some(socket) = self.socket_mut(tgid, fd) else {
            return false;
        };
        if socket.socket_type != SocketType::Datagram || destination.port() != 53 {
            return false;
        }
        // A proxy-owned socket must never be moved back to the in-line owner by
        // message parsing. Explicit destinations on such sockets are handled by
        // the syscall owner gate.
        if !socket.dns_route.is_connected_proxy() {
            socket.dns_route = DnsRoute::InlineDns {
                resolver: Some(destination),
            };
        }
        true
    }

    pub(crate) fn is_dns(&self, tgid: u32, fd: i32) -> bool {
        self.dns_route(tgid, fd).is_some_and(DnsRoute::is_dns)
    }

    pub(crate) fn connected_destination(&self, tgid: u32, fd: i32) -> Option<SocketAddr> {
        self.socket(tgid, fd)?.connected_destination
    }

    #[cfg(test)]
    pub(crate) fn remember_query(&mut self, tgid: u32, fd: i32, query: QueryMetadata) {
        let Some(socket_id) = self.socket_id(tgid, fd) else {
            return;
        };
        self.remember_query_for_socket(socket_id, query);
    }

    pub(crate) fn remember_query_for_socket(&mut self, socket_id: SocketId, query: QueryMetadata) {
        let Some(socket) = self.sockets.get_mut(&socket_id) else {
            return;
        };
        if !matches!(socket.dns_route, DnsRoute::InlineDns { .. }) {
            return;
        }
        let entries = socket.outstanding_queries.entry(query.id).or_default();
        // Keep one entry per allowed send, including identical retries. A
        // denied concurrent retry can then remove exactly one staged entry
        // without deleting an earlier allowed transaction.
        entries.push(query);
    }

    /// Remove response-correlation state for a query whose send was denied.
    pub(crate) fn forget_query_for_socket(&mut self, socket_id: SocketId, query: &QueryMetadata) {
        let Some(socket) = self.sockets.get_mut(&socket_id) else {
            return;
        };
        let Some(entries) = socket.outstanding_queries.get_mut(&query.id) else {
            return;
        };
        if let Some(index) = entries.iter().rposition(|entry| {
            entry.domain.eq_ignore_ascii_case(&query.domain) && entry.qtype == query.qtype
        }) {
            entries.remove(index);
        }
        if entries.is_empty() {
            socket.outstanding_queries.remove(&query.id);
        }
    }

    #[cfg(test)]
    pub(crate) fn take_matching_query(
        &mut self,
        tgid: u32,
        fd: i32,
        id: u16,
        domain: &str,
        qtype: u16,
    ) -> Option<QueryMetadata> {
        let socket = self.socket_mut(tgid, fd)?;
        Self::take_matching_query_from_state(socket, id, domain, qtype)
    }

    pub(crate) fn take_matching_query_for_socket(
        &mut self,
        socket_id: SocketId,
        id: u16,
        domain: &str,
        qtype: u16,
    ) -> Option<QueryMetadata> {
        let socket = self.sockets.get_mut(&socket_id)?;
        Self::take_matching_query_from_state(socket, id, domain, qtype)
    }

    fn take_matching_query_from_state(
        socket: &mut SocketState,
        id: u16,
        domain: &str,
        qtype: u16,
    ) -> Option<QueryMetadata> {
        if !matches!(socket.dns_route, DnsRoute::InlineDns { .. }) {
            return None;
        }
        let entries = socket.outstanding_queries.get_mut(&id)?;
        let index = entries
            .iter()
            .position(|entry| entry.domain.eq_ignore_ascii_case(domain) && entry.qtype == qtype)?;
        let query = entries.remove(index);
        if entries.is_empty() {
            socket.outstanding_queries.remove(&id);
        }
        Some(query)
    }

    /// Duplicate an FD mapping without cloning the underlying socket state.
    #[cfg(test)]
    pub(crate) fn duplicate(&mut self, tgid: u32, old_fd: i32, new_fd: i32) -> Option<DnsRouteId> {
        let Some(socket_id) = self.socket_id(tgid, old_fd) else {
            return self.close(tgid, new_fd);
        };
        self.duplicate_socket(tgid, socket_id, new_fd)
    }

    /// Commit a successful dup using the source identity captured and held at
    /// syscall entry, rather than re-reading a numeric FD a sibling may have
    /// closed or reused.
    pub(crate) fn duplicate_socket(
        &mut self,
        tgid: u32,
        socket_id: SocketId,
        new_fd: i32,
    ) -> Option<DnsRouteId> {
        if !self.sockets.contains_key(&socket_id) {
            return self.close(tgid, new_fd);
        }
        let table_id = self.ensure_process(tgid);
        self.assign_fd(table_id, new_fd, socket_id)
    }

    /// Remove one descriptor alias. A route is returned only when no descriptor
    /// or pending-operation pin still references its shared socket.
    pub(crate) fn close(&mut self, tgid: u32, fd: i32) -> Option<DnsRouteId> {
        let table_id = self.table_id(tgid)?;
        let socket_id = self.tables.get_mut(&table_id)?.sockets.remove(&fd)?;
        self.decrement_descriptor_ref(socket_id)
    }

    pub(crate) fn close_range(&mut self, tgid: u32, first: u32, last: u32) -> Vec<DnsRouteId> {
        let Some(table_id) = self.table_id(tgid) else {
            return Vec::new();
        };
        let to_remove: Vec<i32> = self
            .tables
            .get(&table_id)
            .into_iter()
            .flat_map(|table| table.sockets.keys())
            .copied()
            .filter(|fd| (*fd as i64) >= first as i64 && (*fd as i64) <= last as i64)
            .collect();
        let mut released = Vec::new();
        for fd in to_remove {
            let socket_id = self
                .tables
                .get_mut(&table_id)
                .and_then(|table| table.sockets.remove(&fd))
                .expect("collected FD must still exist");
            if let Some(route_id) = self.decrement_descriptor_ref(socket_id) {
                released.push(route_id);
            }
        }
        released
    }

    /// If an execing process shared its FD table with another TGID, Linux
    /// unshares it before closing `FD_CLOEXEC` entries. Mirror that before
    /// reconciliation so one process's exec cannot remove the other's FDs.
    fn unshare_table_for_exec(&mut self, tgid: u32) -> Option<FdTableId> {
        let current = self.table_id(tgid)?;
        let is_shared = self
            .process_tables
            .iter()
            .any(|(other_tgid, table_id)| *other_tgid != tgid && *table_id == current);
        if !is_shared {
            return Some(current);
        }

        let snapshot = self.tables.get(&current).cloned().unwrap_or_default();
        let new_id = self.allocate_table_id();
        for socket_id in snapshot.sockets.values().copied() {
            self.increment_descriptor_ref(socket_id);
        }
        self.tables.insert(new_id, snapshot);
        self.process_tables.insert(tgid, new_id);
        Some(new_id)
    }

    /// Reconcile the table after exec, when all `FD_CLOEXEC` descriptors have
    /// been closed atomically by the kernel.
    pub(crate) fn retain_fds(&mut self, tgid: u32, live_fds: &HashSet<i32>) -> Vec<DnsRouteId> {
        let Some(table_id) = self.unshare_table_for_exec(tgid) else {
            return Vec::new();
        };
        let to_remove: Vec<i32> = self
            .tables
            .get(&table_id)
            .into_iter()
            .flat_map(|table| table.sockets.keys())
            .copied()
            .filter(|fd| !live_fds.contains(fd))
            .collect();
        let mut released = Vec::new();
        for fd in to_remove {
            let socket_id = self
                .tables
                .get_mut(&table_id)
                .and_then(|table| table.sockets.remove(&fd))
                .expect("collected FD must still exist");
            if let Some(route_id) = self.decrement_descriptor_ref(socket_id) {
                released.push(route_id);
            }
        }
        released
    }

    /// Register an inherited descriptor table for a newly-created process.
    ///
    /// `shared=true` models `CLONE_FILES`. A normal fork receives a new table
    /// whose FD entries still point at the parent's `SocketId`s.
    pub(crate) fn inherit_process(
        &mut self,
        parent_tgid: u32,
        child_tgid: u32,
        shared: bool,
    ) -> Vec<DnsRouteId> {
        if parent_tgid == child_tgid {
            self.ensure_process(parent_tgid);
            return Vec::new();
        }

        let released = self.remove_process(child_tgid);
        let parent_id = self.ensure_process(parent_tgid);
        if shared {
            self.process_tables.insert(child_tgid, parent_id);
            return released;
        }

        let child_id = self.allocate_table_id();
        let snapshot = self.tables.get(&parent_id).cloned().unwrap_or_default();
        for socket_id in snapshot.sockets.values().copied() {
            self.increment_descriptor_ref(socket_id);
        }
        self.tables.insert(child_id, snapshot);
        self.process_tables.insert(child_tgid, child_id);
        released
    }

    pub(crate) fn remove_process(&mut self, tgid: u32) -> Vec<DnsRouteId> {
        let Some(table_id) = self.process_tables.remove(&tgid) else {
            return Vec::new();
        };
        if self.process_tables.values().any(|id| *id == table_id) {
            return Vec::new();
        }

        let socket_ids = self
            .tables
            .remove(&table_id)
            .map(|table| table.sockets.into_values().collect::<Vec<_>>())
            .unwrap_or_default();
        let mut released = Vec::new();
        for socket_id in socket_ids {
            if let Some(route_id) = self.decrement_descriptor_ref(socket_id) {
                released.push(route_id);
            }
        }
        released
    }

    /// Pin a shared socket for a pending syscall-exit transaction.
    ///
    /// Connect transactions are exclusive per underlying socket. Two aliases
    /// racing `connect(2)` cannot be reconciled by exit order alone, so the
    /// second transaction is rejected until the first unpins.
    pub(crate) fn pin_socket(&mut self, tgid: u32, fd: i32) -> Option<SocketId> {
        let socket_id = self.socket_id(tgid, fd)?;
        let state = self.sockets.get_mut(&socket_id)?;
        if state.operation_refs != 0 || state.connect_in_progress {
            return None;
        }
        state.operation_refs += 1;
        state.connect_in_progress = true;
        Some(socket_id)
    }

    /// Release a pending-operation pin. A route is returned when the pin was
    /// the final reference after all descriptor aliases had already closed.
    pub(crate) fn unpin_socket(&mut self, socket_id: SocketId) -> Option<DnsRouteId> {
        let remove = {
            let state = self.sockets.get_mut(&socket_id)?;
            debug_assert!(state.operation_refs > 0);
            debug_assert!(state.connect_in_progress);
            if state.operation_refs == 0 || !state.connect_in_progress {
                return None;
            }
            state.connect_in_progress = false;
            state.operation_refs -= 1;
            state.operation_refs == 0 && state.descriptor_refs == 0
        };
        if remove {
            self.sockets
                .remove(&socket_id)
                .and_then(|state| state.dns_route.route_id())
        } else {
            None
        }
    }

    /// Hold the underlying socket identity across a promoted receive exit.
    /// Multiple receives may coexist, but peer mutation is excluded until all
    /// holds complete.
    pub(crate) fn hold_socket(&mut self, tgid: u32, fd: i32) -> Option<SocketId> {
        let socket_id = self.socket_id(tgid, fd)?;
        let state = self.sockets.get_mut(&socket_id)?;
        if state.connect_in_progress {
            return None;
        }
        state.operation_refs = state.operation_refs.checked_add(1)?;
        Some(socket_id)
    }

    /// Hold only lifetime/identity, including while a connect transaction is
    /// in progress. Used by dup entry/exit tracking.
    pub(crate) fn hold_socket_identity(&mut self, tgid: u32, fd: i32) -> Option<SocketId> {
        let socket_id = self.socket_id(tgid, fd)?;
        let state = self.sockets.get_mut(&socket_id)?;
        state.operation_refs = state.operation_refs.checked_add(1)?;
        Some(socket_id)
    }

    pub(crate) fn release_socket_hold(&mut self, socket_id: SocketId) -> Option<DnsRouteId> {
        let remove = {
            let state = self.sockets.get_mut(&socket_id)?;
            debug_assert!(state.operation_refs > 0);
            if state.operation_refs == 0 {
                return None;
            }
            state.operation_refs -= 1;
            state.operation_refs == 0 && state.descriptor_refs == 0
        };
        if remove {
            self.sockets
                .remove(&socket_id)
                .and_then(|state| state.dns_route.route_id())
        } else {
            None
        }
    }

    pub(crate) fn clear(&mut self) -> Vec<DnsRouteId> {
        let released = self
            .sockets
            .values()
            .filter_map(|state| state.dns_route.route_id())
            .collect();
        self.process_tables.clear();
        self.tables.clear();
        self.sockets.clear();
        released
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn resolver() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)
    }

    fn other_resolver() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 53)
    }

    fn proxy(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn install_proxy(
        tracker: &mut DnsSocketTracker,
        tgid: u32,
        fd: i32,
        route: u64,
    ) -> RouteTransition {
        tracker
            .set_connected_proxy(tgid, fd, DnsRouteId(route), resolver(), proxy(40_000))
            .expect("datagram socket should accept a proxy route")
    }

    #[test]
    fn threads_in_one_tgid_share_dns_state() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        assert!(tracker.discover_dns(10, 4, resolver()));
        assert!(tracker.is_dns(10, 4));
    }

    #[test]
    fn unrelated_processes_do_not_alias_numeric_fd() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        tracker.discover_dns(10, 4, resolver());
        tracker.observe_socket(20, 4, SocketType::Datagram);
        assert!(tracker.is_dns(10, 4));
        assert!(!tracker.is_dns(20, 4));
        assert_ne!(tracker.socket_id(10, 4), tracker.socket_id(20, 4));
    }

    #[test]
    fn dup_aliases_share_route_and_query_state() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        tracker.discover_dns(10, 4, resolver());
        tracker.duplicate(10, 4, 7);
        assert_eq!(tracker.socket_id(10, 4), tracker.socket_id(10, 7));

        tracker.remember_query(
            10,
            4,
            QueryMetadata {
                id: 7,
                domain: "one.example".into(),
                qtype: 1,
            },
        );
        assert!(tracker
            .take_matching_query(10, 7, 7, "one.example", 1)
            .is_some());

        install_proxy(&mut tracker, 10, 7, 41);
        assert!(tracker.is_connected_proxy(10, 4));
    }

    #[test]
    fn proxy_route_releases_only_after_last_dup_alias_closes() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        tracker.duplicate(10, 4, 7);
        install_proxy(&mut tracker, 10, 4, 41);

        assert_eq!(tracker.close(10, 4), None);
        assert!(tracker.is_connected_proxy(10, 7));
        assert_eq!(tracker.close(10, 7), Some(DnsRouteId(41)));
    }

    #[test]
    fn socket_fd_reuse_releases_old_final_route_and_gets_new_identity() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        let old_id = tracker.socket_id(10, 4).unwrap();
        install_proxy(&mut tracker, 10, 4, 41);

        assert_eq!(
            tracker.observe_socket(10, 4, SocketType::Stream),
            Some(DnsRouteId(41))
        );
        assert_ne!(tracker.socket_id(10, 4), Some(old_id));
        assert!(!tracker.is_dns(10, 4));
    }

    #[test]
    fn normal_fork_snapshots_fd_table_but_shares_socket_identity() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        tracker.inherit_process(10, 20, false);
        assert_eq!(tracker.socket_id(10, 4), tracker.socket_id(20, 4));

        install_proxy(&mut tracker, 20, 4, 41);
        assert!(tracker.is_connected_proxy(10, 4));

        // Descriptor tables are distinct: closing the child FD does not remove
        // the parent's mapping or release the shared route.
        assert_eq!(tracker.close(20, 4), None);
        assert!(tracker.is_connected_proxy(10, 4));
        assert_eq!(tracker.close(10, 4), Some(DnsRouteId(41)));
    }

    #[test]
    fn clone_files_shares_the_fd_table_itself() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        tracker.inherit_process(10, 30, true);
        install_proxy(&mut tracker, 10, 4, 41);

        assert_eq!(tracker.close(30, 4), Some(DnsRouteId(41)));
        assert!(tracker.socket(10, 4).is_none());
    }

    #[test]
    fn transaction_matching_handles_same_id_and_does_not_consume_on_spoof() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        tracker.discover_dns(10, 4, resolver());
        for (domain, qtype) in [("one.example", 1), ("two.example", 28)] {
            tracker.remember_query(
                10,
                4,
                QueryMetadata {
                    id: 7,
                    domain: domain.into(),
                    qtype,
                },
            );
        }
        assert!(tracker
            .take_matching_query(10, 4, 7, "spoof.example", 1)
            .is_none());
        assert_eq!(
            tracker
                .take_matching_query(10, 4, 7, "two.example", 28)
                .unwrap()
                .domain,
            "two.example"
        );
        assert_eq!(
            tracker
                .take_matching_query(10, 4, 7, "one.example", 1)
                .unwrap()
                .domain,
            "one.example"
        );
    }

    #[test]
    fn denied_query_can_remove_staged_response_correlation() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        tracker.discover_dns(10, 4, resolver());
        let socket_id = tracker.socket_id(10, 4).unwrap();
        let query = QueryMetadata {
            id: 7,
            domain: "denied.example".into(),
            qtype: 1,
        };
        tracker.remember_query_for_socket(socket_id, query.clone());
        tracker.forget_query_for_socket(socket_id, &query);

        assert!(tracker
            .take_matching_query(10, 4, 7, "denied.example", 1)
            .is_none());
    }

    #[test]
    fn denied_identical_retry_preserves_earlier_allowed_transaction() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        tracker.discover_dns(10, 4, resolver());
        let socket_id = tracker.socket_id(10, 4).unwrap();
        let query = QueryMetadata {
            id: 7,
            domain: "retry.example".into(),
            qtype: 1,
        };
        tracker.remember_query_for_socket(socket_id, query.clone());
        tracker.remember_query_for_socket(socket_id, query.clone());
        tracker.forget_query_for_socket(socket_id, &query);

        assert!(tracker
            .take_matching_query(10, 4, 7, "retry.example", 1)
            .is_some());
        assert!(tracker
            .take_matching_query(10, 4, 7, "retry.example", 1)
            .is_none());
    }

    #[test]
    fn proxy_owned_socket_never_records_inline_transactions() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        install_proxy(&mut tracker, 10, 4, 41);
        tracker.remember_query(
            10,
            4,
            QueryMetadata {
                id: 7,
                domain: "one.example".into(),
                qtype: 1,
            },
        );
        assert!(tracker
            .take_matching_query(10, 4, 7, "one.example", 1)
            .is_none());
        assert!(tracker.discover_dns(10, 4, other_resolver()));
        assert!(tracker.is_connected_proxy(10, 4));
    }

    #[test]
    fn exec_reconciliation_removes_closed_descriptors() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        tracker.observe_socket(10, 5, SocketType::Datagram);
        tracker.discover_dns(10, 4, resolver());
        tracker.discover_dns(10, 5, resolver());
        tracker.retain_fds(10, &HashSet::from([5]));
        assert!(!tracker.is_dns(10, 4));
        assert!(tracker.is_dns(10, 5));
    }

    #[test]
    fn exec_unshares_a_clone_files_table_before_reconciliation() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        tracker.observe_socket(10, 5, SocketType::Datagram);
        tracker.inherit_process(10, 20, true);

        tracker.retain_fds(20, &HashSet::from([5]));
        assert!(tracker.socket(20, 4).is_none());
        assert!(tracker.socket(20, 5).is_some());
        assert!(tracker.socket(10, 4).is_some());
        assert!(tracker.socket(10, 5).is_some());
        assert_ne!(tracker.table_id(10), tracker.table_id(20));
    }

    #[test]
    fn connect_disconnect_and_reconnect_report_route_transitions() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);

        assert_eq!(tracker.connect(10, 4, resolver()), None);
        assert!(matches!(
            tracker.dns_route(10, 4),
            Some(DnsRoute::InlineDns {
                resolver: Some(addr)
            }) if *addr == resolver()
        ));

        install_proxy(&mut tracker, 10, 4, 41);
        assert_eq!(
            tracker.connect(10, 4, SocketAddr::from(([192, 0, 2, 1], 443))),
            Some(DnsRouteId(41))
        );
        assert!(!tracker.is_dns(10, 4));

        let transition = tracker
            .set_connected_proxy(10, 4, DnsRouteId(42), other_resolver(), proxy(40_001))
            .unwrap();
        assert_eq!(transition.released_route, None);
        assert_eq!(tracker.connected_destination(10, 4), Some(other_resolver()));
        assert_eq!(tracker.disconnect(10, 4), Some(DnsRouteId(42)));
        assert_eq!(tracker.connected_destination(10, 4), None);
    }

    #[test]
    fn replacing_proxy_route_reports_old_route() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        install_proxy(&mut tracker, 10, 4, 41);
        let transition = tracker
            .set_connected_proxy(10, 4, DnsRouteId(42), other_resolver(), proxy(40_001))
            .unwrap();
        assert_eq!(transition.released_route, Some(DnsRouteId(41)));
    }

    #[test]
    fn close_range_reports_only_routes_whose_final_alias_was_removed() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        tracker.duplicate(10, 4, 9);
        tracker.observe_socket(10, 5, SocketType::Datagram);
        install_proxy(&mut tracker, 10, 4, 41);
        install_proxy(&mut tracker, 10, 5, 42);

        assert_eq!(tracker.close_range(10, 4, 5), vec![DnsRouteId(42)]);
        assert!(tracker.is_connected_proxy(10, 9));
        assert_eq!(tracker.close(10, 9), Some(DnsRouteId(41)));
    }

    #[test]
    fn removing_last_process_releases_routes_but_shared_table_owner_does_not() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        tracker.inherit_process(10, 20, true);
        install_proxy(&mut tracker, 10, 4, 41);

        assert!(tracker.remove_process(20).is_empty());
        assert_eq!(tracker.remove_process(10), vec![DnsRouteId(41)]);
    }

    #[test]
    fn pending_operation_pin_defers_final_route_release() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        install_proxy(&mut tracker, 10, 4, 41);
        let socket_id = tracker.pin_socket(10, 4).unwrap();
        assert!(tracker.socket_matches(10, 4, socket_id));

        assert_eq!(tracker.close(10, 4), None);
        assert!(tracker.socket_by_id(socket_id).is_some());
        assert_eq!(tracker.unpin_socket(socket_id), Some(DnsRouteId(41)));
        assert!(tracker.socket_by_id(socket_id).is_none());
    }

    #[test]
    fn pending_operation_pin_is_exclusive_across_aliases() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        tracker.duplicate(10, 4, 9);

        let socket_id = tracker.pin_socket(10, 4).unwrap();
        assert_eq!(tracker.pin_socket(10, 4), None);
        assert_eq!(tracker.pin_socket(10, 9), None);

        assert_eq!(tracker.unpin_socket(socket_id), None);
        assert_eq!(tracker.pin_socket(10, 9), Some(socket_id));
    }

    #[test]
    fn receive_hold_preserves_identity_and_blocks_connect_transaction() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        tracker.duplicate(10, 4, 9);

        let socket_id = tracker.hold_socket(10, 4).unwrap();
        assert_eq!(tracker.hold_socket(10, 9), Some(socket_id));
        assert_eq!(tracker.pin_socket(10, 4), None);
        assert_eq!(tracker.close(10, 4), None);
        assert_eq!(tracker.close(10, 9), None);
        assert_eq!(tracker.release_socket_hold(socket_id), None);
        assert_eq!(tracker.release_socket_hold(socket_id), None);
        assert!(tracker.socket_by_id(socket_id).is_none());
    }

    #[test]
    fn dup_commit_uses_entry_socket_identity_after_source_fd_closes() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        install_proxy(&mut tracker, 10, 4, 41);

        let socket_id = tracker.hold_socket_identity(10, 4).unwrap();
        assert_eq!(tracker.close(10, 4), None);
        assert_eq!(tracker.duplicate_socket(10, socket_id, 9), None);
        assert_eq!(tracker.release_socket_hold(socket_id), None);
        assert!(tracker.is_connected_proxy(10, 9));
        assert_eq!(tracker.close(10, 9), Some(DnsRouteId(41)));
    }

    #[test]
    fn duplicate_unknown_source_closes_and_releases_target() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 7, SocketType::Datagram);
        install_proxy(&mut tracker, 10, 7, 41);
        assert_eq!(tracker.duplicate(10, 99, 7), Some(DnsRouteId(41)));
        assert!(tracker.socket(10, 7).is_none());
    }

    #[test]
    fn ipv6_route_preserves_original_resolver_and_proxy_endpoint() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        let resolver = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53);
        let endpoint = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 40_000);
        tracker
            .set_connected_proxy(10, 4, DnsRouteId(41), resolver, endpoint)
            .unwrap();
        assert!(matches!(
            tracker.dns_route(10, 4),
            Some(DnsRoute::ConnectedProxy {
                route_id: DnsRouteId(41),
                original_resolver,
                proxy_endpoint,
            }) if *original_resolver == resolver && *proxy_endpoint == endpoint
        ));
    }

    #[test]
    fn clear_reports_every_live_proxy_route() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        tracker.observe_socket(10, 5, SocketType::Datagram);
        install_proxy(&mut tracker, 10, 4, 41);
        install_proxy(&mut tracker, 10, 5, 42);
        let mut released = tracker.clear();
        released.sort_by_key(|id| id.0);
        assert_eq!(released, vec![DnsRouteId(41), DnsRouteId(42)]);
        assert!(tracker.socket(10, 4).is_none());
    }

    #[test]
    fn route_presence_tracks_install_replace_and_final_close() {
        let mut tracker = DnsSocketTracker::new();
        tracker.observe_socket(10, 4, SocketType::Datagram);
        assert!(!tracker.has_connected_proxy_routes());

        install_proxy(&mut tracker, 10, 4, 41);
        assert!(tracker.has_connected_proxy_routes());

        assert_eq!(tracker.disconnect(10, 4), Some(DnsRouteId(41)));
        assert!(!tracker.has_connected_proxy_routes());

        install_proxy(&mut tracker, 10, 4, 42);
        assert!(tracker.has_connected_proxy_routes());
        assert_eq!(tracker.close(10, 4), Some(DnsRouteId(42)));
        assert!(!tracker.has_connected_proxy_routes());
    }
}
