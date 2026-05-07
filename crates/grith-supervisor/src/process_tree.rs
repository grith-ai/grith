// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Process tree tracking for supervised process hierarchies.
//!
//! The supervisor needs to track the full tree of processes spawned by the
//! supervised tool (e.g., `claude-code` may spawn `node`, which spawns `git`).
//! This module maintains the parent-child relationships and per-process state,
//! enabling operations like freeze-tree (freeze a process and all descendants).

use crate::error::{Error, Result};
use std::collections::HashMap;
use tracing::warn;

/// State of a supervised process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Process is running normally.
    Running,
    /// Process has been frozen (SIGSTOP / cgroup freeze) pending a digest decision.
    Frozen,
    /// Process has exited (zombie or fully reaped).
    Exited,
}

/// Information about a single process in the supervised tree.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// The process ID.
    pub pid: u32,
    /// PID of the parent process (0 for the root).
    pub parent_pid: u32,
    /// The command that started this process (e.g., "/usr/bin/node").
    pub command: String,
    /// The full command-line arguments (set on exec, empty for fork placeholders).
    pub args: Vec<String>,
    /// Current lifecycle state.
    pub state: ProcessState,
}

/// Tracks the full parent-child process tree rooted at the supervised process.
#[derive(Debug, Clone)]
pub struct ProcessTree {
    /// PID of the root supervised process.
    root_pid: u32,
    /// All tracked processes indexed by PID.
    processes: HashMap<u32, ProcessInfo>,
}

impl ProcessTree {
    /// Create a new process tree rooted at the given PID.
    pub fn new(root_pid: u32, command: impl Into<String>) -> Self {
        let mut processes = HashMap::new();
        processes.insert(
            root_pid,
            ProcessInfo {
                pid: root_pid,
                parent_pid: 0,
                command: command.into(),
                args: Vec::new(),
                state: ProcessState::Running,
            },
        );
        Self {
            root_pid,
            processes,
        }
    }

    /// The PID of the root process.
    pub fn root_pid(&self) -> u32 {
        self.root_pid
    }

    /// Add a child process to the tree.
    ///
    /// Returns an error if `parent_pid` is not already in the tree. This
    /// can happen with out-of-order fork events (e.g., the child's first
    /// syscall arrives before the parent's PTRACE_EVENT_FORK notification).
    pub fn add_child(
        &mut self,
        parent_pid: u32,
        child_pid: u32,
        command: impl Into<String>,
    ) -> Result<()> {
        if !self.processes.contains_key(&parent_pid) {
            warn!(
                parent_pid,
                child_pid,
                "cannot add child: parent pid not found in process tree \
                 (out-of-order fork event?)"
            );
            return Err(Error::ProcessTreeError(format!(
                "parent pid {parent_pid} not found in tree"
            )));
        }
        self.processes.insert(
            child_pid,
            ProcessInfo {
                pid: child_pid,
                parent_pid,
                command: command.into(),
                args: Vec::new(),
                state: ProcessState::Running,
            },
        );
        Ok(())
    }

    /// Update the command name and args of a process (e.g., after exec replaces the image).
    pub fn update_command(&mut self, pid: u32, command: impl Into<String>, args: Vec<String>) {
        if let Some(info) = self.processes.get_mut(&pid) {
            info.command = command.into();
            info.args = args;
        }
    }

    /// Update the state of a process.
    pub fn update_state(&mut self, pid: u32, state: ProcessState) -> Result<()> {
        let info = self
            .processes
            .get_mut(&pid)
            .ok_or_else(|| Error::ProcessTreeError(format!("pid {pid} not found in tree")))?;
        info.state = state;
        Ok(())
    }

    /// Freeze a process and all of its descendants (set state to `Frozen`).
    /// Returns the list of PIDs that were frozen.
    pub fn freeze_tree(&mut self, pid: u32) -> Result<Vec<u32>> {
        let descendants = self.descendants_of(pid)?;
        let mut frozen = Vec::new();
        for &d in &descendants {
            if let Some(info) = self.processes.get_mut(&d) {
                if info.state == ProcessState::Running {
                    info.state = ProcessState::Frozen;
                    frozen.push(d);
                }
            }
        }
        // Freeze the target itself
        if let Some(info) = self.processes.get_mut(&pid) {
            if info.state == ProcessState::Running {
                info.state = ProcessState::Frozen;
                frozen.push(pid);
            }
        }
        Ok(frozen)
    }

    /// Thaw a process and all of its descendants (set state back to `Running`).
    /// Returns the list of PIDs that were thawed.
    pub fn thaw_tree(&mut self, pid: u32) -> Result<Vec<u32>> {
        let descendants = self.descendants_of(pid)?;
        let mut thawed = Vec::new();
        for &d in &descendants {
            if let Some(info) = self.processes.get_mut(&d) {
                if info.state == ProcessState::Frozen {
                    info.state = ProcessState::Running;
                    thawed.push(d);
                }
            }
        }
        if let Some(info) = self.processes.get_mut(&pid) {
            if info.state == ProcessState::Frozen {
                info.state = ProcessState::Running;
                thawed.push(pid);
            }
        }
        Ok(thawed)
    }

    /// Remove all processes in the `Exited` state from the tree.
    /// Returns the number of processes removed.
    pub fn remove_exited(&mut self) -> usize {
        let before = self.processes.len();
        self.processes
            .retain(|_, info| info.state != ProcessState::Exited);
        before - self.processes.len()
    }

    /// Get the immediate children of a process.
    pub fn children_of(&self, pid: u32) -> Vec<u32> {
        self.processes
            .values()
            .filter(|info| info.parent_pid == pid)
            .map(|info| info.pid)
            .collect()
    }

    /// Get all PIDs currently tracked in the tree.
    pub fn all_pids(&self) -> Vec<u32> {
        self.processes.keys().copied().collect()
    }

    /// Check if a process is in the `Frozen` state.
    pub fn is_frozen(&self, pid: u32) -> bool {
        self.processes
            .get(&pid)
            .map(|info| info.state == ProcessState::Frozen)
            .unwrap_or(false)
    }

    /// Get information about a process by PID.
    pub fn get(&self, pid: u32) -> Option<&ProcessInfo> {
        self.processes.get(&pid)
    }

    /// Get all descendants of a given PID (children, grandchildren, etc.).
    fn descendants_of(&self, pid: u32) -> Result<Vec<u32>> {
        if !self.processes.contains_key(&pid) {
            return Err(Error::ProcessTreeError(format!(
                "pid {pid} not found in tree"
            )));
        }
        let mut result = Vec::new();
        let mut stack = vec![pid];
        while let Some(current) = stack.pop() {
            let children = self.children_of(current);
            for child in children {
                result.push(child);
                stack.push(child);
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tree_has_root() {
        let tree = ProcessTree::new(100, "/usr/bin/node");
        assert_eq!(tree.root_pid(), 100);
        let root = tree.get(100).unwrap();
        assert_eq!(root.pid, 100);
        assert_eq!(root.parent_pid, 0);
        assert_eq!(root.command, "/usr/bin/node");
        assert_eq!(root.state, ProcessState::Running);
    }

    #[test]
    fn add_child_creates_process() {
        let mut tree = ProcessTree::new(100, "node");
        tree.add_child(100, 101, "git").unwrap();
        let child = tree.get(101).unwrap();
        assert_eq!(child.pid, 101);
        assert_eq!(child.parent_pid, 100);
        assert_eq!(child.command, "git");
        assert_eq!(child.state, ProcessState::Running);
    }

    #[test]
    fn add_child_to_nonexistent_parent_fails() {
        let mut tree = ProcessTree::new(100, "node");
        let result = tree.add_child(999, 101, "git");
        assert!(result.is_err());
    }

    #[test]
    fn update_state_changes_process_state() {
        let mut tree = ProcessTree::new(100, "node");
        tree.update_state(100, ProcessState::Frozen).unwrap();
        assert_eq!(tree.get(100).unwrap().state, ProcessState::Frozen);
    }

    #[test]
    fn update_state_nonexistent_pid_fails() {
        let mut tree = ProcessTree::new(100, "node");
        let result = tree.update_state(999, ProcessState::Exited);
        assert!(result.is_err());
    }

    #[test]
    fn freeze_tree_freezes_pid_and_descendants() {
        let mut tree = ProcessTree::new(100, "node");
        tree.add_child(100, 101, "git").unwrap();
        tree.add_child(100, 102, "npm").unwrap();
        tree.add_child(101, 103, "ssh").unwrap();

        let frozen = tree.freeze_tree(100).unwrap();
        assert_eq!(frozen.len(), 4);
        assert!(tree.is_frozen(100));
        assert!(tree.is_frozen(101));
        assert!(tree.is_frozen(102));
        assert!(tree.is_frozen(103));
    }

    #[test]
    fn freeze_tree_skips_already_frozen() {
        let mut tree = ProcessTree::new(100, "node");
        tree.add_child(100, 101, "git").unwrap();
        tree.update_state(101, ProcessState::Frozen).unwrap();

        let frozen = tree.freeze_tree(100).unwrap();
        // Only root should be newly frozen; 101 was already frozen
        assert_eq!(frozen.len(), 1);
        assert!(frozen.contains(&100));
    }

    #[test]
    fn thaw_tree_thaws_pid_and_descendants() {
        let mut tree = ProcessTree::new(100, "node");
        tree.add_child(100, 101, "git").unwrap();
        tree.freeze_tree(100).unwrap();

        let thawed = tree.thaw_tree(100).unwrap();
        assert_eq!(thawed.len(), 2);
        assert!(!tree.is_frozen(100));
        assert!(!tree.is_frozen(101));
    }

    #[test]
    fn thaw_tree_skips_running_processes() {
        let mut tree = ProcessTree::new(100, "node");
        tree.add_child(100, 101, "git").unwrap();
        // Only freeze the child
        tree.update_state(101, ProcessState::Frozen).unwrap();

        let thawed = tree.thaw_tree(100).unwrap();
        // Only 101 should be thawed; 100 was already running
        assert_eq!(thawed.len(), 1);
        assert!(thawed.contains(&101));
    }

    #[test]
    fn remove_exited_cleans_up() {
        let mut tree = ProcessTree::new(100, "node");
        tree.add_child(100, 101, "git").unwrap();
        tree.add_child(100, 102, "npm").unwrap();
        tree.update_state(101, ProcessState::Exited).unwrap();

        let removed = tree.remove_exited();
        assert_eq!(removed, 1);
        assert!(tree.get(101).is_none());
        assert!(tree.get(100).is_some());
        assert!(tree.get(102).is_some());
    }

    #[test]
    fn children_of_returns_direct_children() {
        let mut tree = ProcessTree::new(100, "node");
        tree.add_child(100, 101, "git").unwrap();
        tree.add_child(100, 102, "npm").unwrap();
        tree.add_child(101, 103, "ssh").unwrap();

        let mut children = tree.children_of(100);
        children.sort();
        assert_eq!(children, vec![101, 102]);

        let grandchildren = tree.children_of(101);
        assert_eq!(grandchildren, vec![103]);
    }

    #[test]
    fn children_of_nonexistent_returns_empty() {
        let tree = ProcessTree::new(100, "node");
        assert!(tree.children_of(999).is_empty());
    }

    #[test]
    fn all_pids_returns_all_tracked() {
        let mut tree = ProcessTree::new(100, "node");
        tree.add_child(100, 101, "git").unwrap();
        tree.add_child(100, 102, "npm").unwrap();

        let mut pids = tree.all_pids();
        pids.sort();
        assert_eq!(pids, vec![100, 101, 102]);
    }

    #[test]
    fn is_frozen_returns_false_for_unknown_pid() {
        let tree = ProcessTree::new(100, "node");
        assert!(!tree.is_frozen(999));
    }

    #[test]
    fn is_frozen_reflects_state() {
        let mut tree = ProcessTree::new(100, "node");
        assert!(!tree.is_frozen(100));
        tree.update_state(100, ProcessState::Frozen).unwrap();
        assert!(tree.is_frozen(100));
        tree.update_state(100, ProcessState::Running).unwrap();
        assert!(!tree.is_frozen(100));
    }

    #[test]
    fn deep_tree_freeze_and_thaw() {
        let mut tree = ProcessTree::new(1, "root");
        tree.add_child(1, 2, "child1").unwrap();
        tree.add_child(2, 3, "grandchild1").unwrap();
        tree.add_child(3, 4, "great-grandchild1").unwrap();

        let frozen = tree.freeze_tree(2).unwrap();
        assert_eq!(frozen.len(), 3); // 2, 3, 4
        assert!(!tree.is_frozen(1)); // root not frozen
        assert!(tree.is_frozen(2));
        assert!(tree.is_frozen(3));
        assert!(tree.is_frozen(4));

        let thawed = tree.thaw_tree(2).unwrap();
        assert_eq!(thawed.len(), 3);
        assert!(!tree.is_frozen(2));
        assert!(!tree.is_frozen(3));
        assert!(!tree.is_frozen(4));
    }

    #[test]
    fn freeze_nonexistent_pid_fails() {
        let mut tree = ProcessTree::new(100, "node");
        let result = tree.freeze_tree(999);
        assert!(result.is_err());
    }
}
