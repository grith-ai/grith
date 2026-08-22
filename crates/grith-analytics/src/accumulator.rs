// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Deterministic, single-UTC-day analytics accumulator.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, NaiveDate, Timelike, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::contract::{
    merge_bounds, AnalyticsEvent, Category, DaySnapshot, DestinationKind, DestinationRollupRow,
    FilterRollupRow, LlmRollupRow, RecordClass, SecurityEvent, SessionDayRow, SnapshotState,
    UsageRollupRow, Verdict,
};
use crate::limits::{
    MAX_ABS_SCORE_MICROS, MAX_DESTINATION_ROWS, MAX_FILTER_ROWS, MAX_LLM_ROWS, MAX_SAFE_INTEGER,
    MAX_SESSION_ROWS, MAX_TOTAL_ROLLUP_ROWS, MAX_USAGE_ROWS,
};
use crate::normalize::{canonical_filter_ids, score_micros_to_bin, NormalizationError};

#[derive(Debug, thiserror::Error)]
pub enum AccumulatorError {
    #[error("event {event_id} belongs to {actual}, not accumulator day {expected}")]
    WrongDay {
        event_id: Uuid,
        expected: NaiveDate,
        actual: NaiveDate,
    },
    #[error("event {0} was replayed with different content")]
    EventConflict(Uuid),
    #[error("decision event {0} is missing its initial verdict or score")]
    IncompleteDecision(Uuid),
    #[error("non-decision event {0} carries decision-only filter data")]
    UnexpectedFilterData(Uuid),
    #[error("decision event {0} is missing filter_set_version")]
    MissingFilterSetVersion(Uuid),
    #[error("event {0} evaluated-filter ids are not canonical sorted unique ids")]
    NonCanonicalFilterSet(Uuid),
    #[error("event {event_id} has invalid contribution for filter {filter_id}")]
    InvalidFilterContribution { event_id: Uuid, filter_id: String },
    #[error("event {0} carries a score outside the signed +/-100 score-unit bound")]
    ScoreOutOfRange(Uuid),
    #[error("llm_usage event {0} is missing LLM accounting fields")]
    MissingLlmUsage(Uuid),
    #[error("non-llm event {0} carries LLM accounting fields")]
    UnexpectedLlmUsage(Uuid),
    #[error("destination event {0} requires an initial policy verdict")]
    DestinationWithoutVerdict(Uuid),
    #[error("security projection for {0} does not match its source event")]
    SecurityEventMismatch(Uuid),
    #[error("security event {0} was replayed at the same revision with different content")]
    SecurityEventConflict(Uuid),
    #[error("counter overflow while accumulating {0}")]
    CounterOverflow(&'static str),
    #[error("rollup row limit exceeded for {family}: {actual} > {limit}")]
    RowLimit {
        family: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error(transparent)]
    Normalization(#[from] NormalizationError),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct UsageKey {
    bucket_start: DateTime<Utc>,
    project: String,
    profile_id: String,
    config_hash: String,
    supervised_tool: String,
    record_class: RecordClass,
    category: Category,
    verdict: Option<Verdict>,
    score_bucket: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FilterKey {
    project: String,
    profile_id: String,
    config_hash: String,
    filter_set_version: u16,
    filter_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SessionKey {
    session_id: Uuid,
    project: String,
    profile_id: String,
    config_hash: String,
    supervised_tool: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LlmKey {
    project: String,
    provider: String,
    model: String,
    currency: String,
    price_source: String,
    pricing_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DestinationKey {
    kind: DestinationKind,
    destination_hmac: String,
    hmac_key_version: u16,
    approved_display_label: Option<String>,
    verdict: Verdict,
}

#[derive(Debug, Clone)]
pub struct DayAccumulator {
    day: NaiveDate,
    // One entry per ingested event for intra-day dedup. Accumulators are
    // transient (built per day-rebuild, then dropped), so this peaks at
    // ~50 bytes x the day's event count and never persists.
    event_digests: BTreeMap<Uuid, [u8; 32]>,
    source_event_count: u64,
    first_event_at: Option<DateTime<Utc>>,
    last_event_at: Option<DateTime<Utc>>,
    first_chain_sequence: Option<u64>,
    last_chain_sequence: Option<u64>,
    last_chain_hash: Option<String>,
    usage: BTreeMap<UsageKey, UsageRollupRow>,
    filters: BTreeMap<FilterKey, FilterRollupRow>,
    sessions: BTreeMap<SessionKey, SessionDayRow>,
    llm: BTreeMap<LlmKey, LlmRollupRow>,
    destinations: BTreeMap<DestinationKey, DestinationRollupRow>,
    security_events: BTreeMap<Uuid, SecurityEvent>,
}

impl DayAccumulator {
    pub fn new(day: NaiveDate) -> Self {
        Self {
            day,
            event_digests: BTreeMap::new(),
            source_event_count: 0,
            first_event_at: None,
            last_event_at: None,
            first_chain_sequence: None,
            last_chain_sequence: None,
            last_chain_hash: None,
            usage: BTreeMap::new(),
            filters: BTreeMap::new(),
            sessions: BTreeMap::new(),
            llm: BTreeMap::new(),
            destinations: BTreeMap::new(),
            security_events: BTreeMap::new(),
        }
    }

    pub fn day(&self) -> NaiveDate {
        self.day
    }

    pub fn source_event_count(&self) -> u64 {
        self.source_event_count
    }

    /// Apply one safe analytics event. An identical event-ID replay is a no-op;
    /// different content under the same ID is a hard conflict.
    pub fn ingest(&mut self, event: &AnalyticsEvent) -> Result<bool, AccumulatorError> {
        let actual_day = event.occurred_at.date_naive();
        if actual_day != self.day {
            return Err(AccumulatorError::WrongDay {
                event_id: event.event_id,
                expected: self.day,
                actual: actual_day,
            });
        }

        self.validate_event(event)?;
        let digest: [u8; 32] = Sha256::digest(serde_json::to_vec(event)?).into();
        if let Some(existing) = self.event_digests.get(&event.event_id) {
            return if existing == &digest {
                Ok(false)
            } else {
                Err(AccumulatorError::EventConflict(event.event_id))
            };
        }

        self.add_usage(event)?;
        self.add_filters(event)?;
        self.add_session(event)?;
        self.add_llm(event)?;
        self.add_destination(event)?;
        self.add_security_event(event)?;

        self.source_event_count = checked_add(self.source_event_count, 1, "source_event_count")?;
        merge_bounds(
            &mut self.first_event_at,
            &mut self.last_event_at,
            event.occurred_at,
        );
        if let Some(sequence) = event.chain_sequence {
            self.first_chain_sequence = Some(
                self.first_chain_sequence
                    .map_or(sequence, |current| current.min(sequence)),
            );
            if self
                .last_chain_sequence
                .is_none_or(|current| sequence >= current)
            {
                self.last_chain_sequence = Some(sequence);
                self.last_chain_hash.clone_from(&event.chain_hash);
            }
        }
        self.event_digests.insert(event.event_id, digest);
        self.check_row_limits()?;
        Ok(true)
    }

    pub fn snapshot(
        &self,
        day_revision: u64,
        read_model_generation: u64,
        state: SnapshotState,
    ) -> Result<(DaySnapshot, Vec<SecurityEvent>), AccumulatorError> {
        let mut snapshot = DaySnapshot {
            day: self.day,
            day_revision,
            read_model_generation,
            state,
            source_event_count: self.source_event_count,
            first_event_at: self.first_event_at,
            last_event_at: self.last_event_at,
            first_chain_sequence: self.first_chain_sequence,
            last_chain_sequence: self.last_chain_sequence,
            last_chain_hash: self.last_chain_hash.clone(),
            usage_rows: self.usage.values().cloned().collect(),
            filter_rows: self.filters.values().cloned().collect(),
            session_rows: self.sessions.values().cloned().collect(),
            llm_rows: self.llm.values().cloned().collect(),
            destination_rows: self.destinations.values().cloned().collect(),
            row_checksum_sha256: String::new(),
        };
        snapshot.refresh_checksum()?;
        Ok((snapshot, self.security_events.values().cloned().collect()))
    }

    fn validate_event(&self, event: &AnalyticsEvent) -> Result<(), AccumulatorError> {
        if event
            .score_micros
            .is_some_and(|score| score.unsigned_abs() > MAX_ABS_SCORE_MICROS as u64)
        {
            return Err(AccumulatorError::ScoreOutOfRange(event.event_id));
        }
        match event.record_class {
            RecordClass::Decision => {
                if event.initial_verdict.is_none() || event.score_micros.is_none() {
                    return Err(AccumulatorError::IncompleteDecision(event.event_id));
                }
                let Some(filter_set_version) = event.filter_set_version else {
                    return Err(AccumulatorError::MissingFilterSetVersion(event.event_id));
                };
                if filter_set_version == 0 {
                    return Err(AccumulatorError::MissingFilterSetVersion(event.event_id));
                }
                let canonical = canonical_filter_ids(&event.evaluated_filter_ids)?;
                if canonical != event.evaluated_filter_ids {
                    return Err(AccumulatorError::NonCanonicalFilterSet(event.event_id));
                }
                let evaluated: BTreeSet<&str> = event
                    .evaluated_filter_ids
                    .iter()
                    .map(String::as_str)
                    .collect();
                let mut contribution_ids = BTreeSet::new();
                let mut previous_id: Option<&str> = None;
                for contribution in &event.positive_filter_contributions {
                    // The frozen canonical rule: sorted by normalized filter
                    // ID, unique, strictly positive, references an evaluated
                    // ID. Order matters because the dedup digest hashes the
                    // serialized event.
                    if contribution.score_micros <= 0
                        || contribution.score_micros > MAX_ABS_SCORE_MICROS
                        || !evaluated.contains(contribution.filter_id.as_str())
                        || !contribution_ids.insert(contribution.filter_id.as_str())
                        || previous_id.is_some_and(|prev| prev >= contribution.filter_id.as_str())
                    {
                        return Err(AccumulatorError::InvalidFilterContribution {
                            event_id: event.event_id,
                            filter_id: contribution.filter_id.clone(),
                        });
                    }
                    previous_id = Some(contribution.filter_id.as_str());
                }
            }
            _ if event.filter_set_version.is_some()
                || !event.evaluated_filter_ids.is_empty()
                || !event.positive_filter_contributions.is_empty() =>
            {
                return Err(AccumulatorError::UnexpectedFilterData(event.event_id));
            }
            _ => {}
        }

        match (event.record_class, event.llm_usage.is_some()) {
            (RecordClass::LlmUsage, false) => {
                return Err(AccumulatorError::MissingLlmUsage(event.event_id));
            }
            (RecordClass::LlmUsage, true) | (_, false) => {}
            (_, true) => return Err(AccumulatorError::UnexpectedLlmUsage(event.event_id)),
        }

        if event.destination.is_some() && event.initial_verdict.is_none() {
            return Err(AccumulatorError::DestinationWithoutVerdict(event.event_id));
        }
        if let Some(security) = &event.security_event {
            if security.event_id != event.event_id
                || security.occurred_at != event.occurred_at
                || security.initial_verdict != event.initial_verdict
            {
                return Err(AccumulatorError::SecurityEventMismatch(event.event_id));
            }
        }
        Ok(())
    }

    fn add_usage(&mut self, event: &AnalyticsEvent) -> Result<(), AccumulatorError> {
        let naive_hour = event
            .occurred_at
            .date_naive()
            .and_hms_opt(event.occurred_at.hour(), 0, 0)
            .expect("event hour is valid");
        let bucket_start = naive_hour.and_utc();
        let score_bucket = event.score_micros.map(score_micros_to_bin);
        let key = UsageKey {
            bucket_start,
            project: event.project.clone(),
            profile_id: event.profile_id.clone(),
            config_hash: event.config_hash.clone(),
            supervised_tool: event.supervised_tool.clone(),
            record_class: event.record_class,
            category: event.category,
            verdict: event.initial_verdict,
            score_bucket,
        };
        let row = self.usage.entry(key).or_insert_with(|| UsageRollupRow {
            bucket_start,
            project: event.project.clone(),
            profile_id: event.profile_id.clone(),
            config_hash: event.config_hash.clone(),
            supervised_tool: event.supervised_tool.clone(),
            record_class: event.record_class,
            category: event.category,
            verdict: event.initial_verdict,
            score_bin_version: 1,
            score_bucket,
            event_count: 0,
            score_sum_micros: 0,
            first_event_at: event.occurred_at,
            last_event_at: event.occurred_at,
        });
        row.event_count = checked_add(row.event_count, 1, "usage.event_count")?;
        row.score_sum_micros = row
            .score_sum_micros
            .checked_add(event.score_micros.unwrap_or(0))
            .ok_or(AccumulatorError::CounterOverflow("usage.score_sum_micros"))?;
        if row.score_sum_micros.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(AccumulatorError::CounterOverflow("usage.score_sum_micros"));
        }
        row.first_event_at = row.first_event_at.min(event.occurred_at);
        row.last_event_at = row.last_event_at.max(event.occurred_at);
        Ok(())
    }

    fn add_filters(&mut self, event: &AnalyticsEvent) -> Result<(), AccumulatorError> {
        if event.record_class != RecordClass::Decision {
            return Ok(());
        }
        let version = event
            .filter_set_version
            .expect("decision validation requires filter version");
        let positive: BTreeSet<&str> = event
            .positive_filter_contributions
            .iter()
            .map(|value| value.filter_id.as_str())
            .collect();
        let denied = event.initial_verdict == Some(Verdict::Deny);
        for filter_id in &event.evaluated_filter_ids {
            let key = FilterKey {
                project: event.project.clone(),
                profile_id: event.profile_id.clone(),
                config_hash: event.config_hash.clone(),
                filter_set_version: version,
                filter_id: filter_id.clone(),
            };
            let row = self.filters.entry(key).or_insert_with(|| FilterRollupRow {
                day: self.day,
                project: event.project.clone(),
                profile_id: event.profile_id.clone(),
                config_hash: event.config_hash.clone(),
                filter_set_version: version,
                filter_id: filter_id.clone(),
                evaluated_events: 0,
                triggered_events: 0,
                denied_evaluated_events: 0,
                denied_positive_contributions: 0,
            });
            row.evaluated_events = checked_add(row.evaluated_events, 1, "filter.evaluated")?;
            if positive.contains(filter_id.as_str()) {
                row.triggered_events = checked_add(row.triggered_events, 1, "filter.triggered")?;
            }
            if denied {
                row.denied_evaluated_events =
                    checked_add(row.denied_evaluated_events, 1, "filter.denied_evaluated")?;
                if positive.contains(filter_id.as_str()) {
                    row.denied_positive_contributions = checked_add(
                        row.denied_positive_contributions,
                        1,
                        "filter.denied_positive",
                    )?;
                }
            }
        }
        Ok(())
    }

    fn add_session(&mut self, event: &AnalyticsEvent) -> Result<(), AccumulatorError> {
        let Some(session_id) = event.session_id else {
            return Ok(());
        };
        let key = SessionKey {
            session_id,
            project: event.project.clone(),
            profile_id: event.profile_id.clone(),
            config_hash: event.config_hash.clone(),
            supervised_tool: event.supervised_tool.clone(),
        };
        let row = self.sessions.entry(key).or_insert_with(|| SessionDayRow {
            day: self.day,
            session_id,
            project: event.project.clone(),
            profile_id: event.profile_id.clone(),
            config_hash: event.config_hash.clone(),
            supervised_tool: event.supervised_tool.clone(),
            first_event_at: event.occurred_at,
            last_event_at: event.occurred_at,
            decision_count: 0,
            queue_count: 0,
            deny_count: 0,
            llm_calls: 0,
            prompt_tokens: 0,
            completion_tokens: 0,
            cost_micros: 0,
        });
        row.first_event_at = row.first_event_at.min(event.occurred_at);
        row.last_event_at = row.last_event_at.max(event.occurred_at);
        if event.record_class == RecordClass::Decision {
            row.decision_count = checked_add(row.decision_count, 1, "session.decisions")?;
            if event.initial_verdict == Some(Verdict::Queue) {
                row.queue_count = checked_add(row.queue_count, 1, "session.queue")?;
            }
            if event.initial_verdict == Some(Verdict::Deny) {
                row.deny_count = checked_add(row.deny_count, 1, "session.deny")?;
            }
        }
        if let Some(llm) = &event.llm_usage {
            row.llm_calls = checked_add(row.llm_calls, 1, "session.llm_calls")?;
            row.prompt_tokens =
                checked_add(row.prompt_tokens, llm.prompt_tokens, "session.prompt")?;
            row.completion_tokens = checked_add(
                row.completion_tokens,
                llm.completion_tokens,
                "session.completion",
            )?;
            row.cost_micros = checked_add(row.cost_micros, llm.cost_micros, "session.cost")?;
        }
        Ok(())
    }

    fn add_llm(&mut self, event: &AnalyticsEvent) -> Result<(), AccumulatorError> {
        let Some(llm) = &event.llm_usage else {
            return Ok(());
        };
        let key = LlmKey {
            project: event.project.clone(),
            provider: llm.provider.clone(),
            model: llm.model.clone(),
            currency: llm.currency.clone(),
            price_source: llm.price_source.clone(),
            pricing_version: llm.pricing_version.clone(),
        };
        let row = self.llm.entry(key).or_insert_with(|| LlmRollupRow {
            day: self.day,
            project: event.project.clone(),
            provider: llm.provider.clone(),
            model: llm.model.clone(),
            currency: llm.currency.clone(),
            price_source: llm.price_source.clone(),
            pricing_version: llm.pricing_version.clone(),
            calls: 0,
            prompt_tokens: 0,
            completion_tokens: 0,
            cost_micros: 0,
        });
        row.calls = checked_add(row.calls, 1, "llm.calls")?;
        row.prompt_tokens = checked_add(row.prompt_tokens, llm.prompt_tokens, "llm.prompt")?;
        row.completion_tokens = checked_add(
            row.completion_tokens,
            llm.completion_tokens,
            "llm.completion",
        )?;
        row.cost_micros = checked_add(row.cost_micros, llm.cost_micros, "llm.cost")?;
        Ok(())
    }

    fn add_destination(&mut self, event: &AnalyticsEvent) -> Result<(), AccumulatorError> {
        let Some(destination) = &event.destination else {
            return Ok(());
        };
        let verdict = event
            .initial_verdict
            .ok_or(AccumulatorError::DestinationWithoutVerdict(event.event_id))?;
        let key = DestinationKey {
            kind: destination.kind,
            destination_hmac: destination.destination_hmac.clone(),
            hmac_key_version: destination.hmac_key_version,
            approved_display_label: destination.approved_display_label.clone(),
            verdict,
        };
        let row = self
            .destinations
            .entry(key)
            .or_insert_with(|| DestinationRollupRow {
                day: self.day,
                kind: destination.kind,
                destination_hmac: destination.destination_hmac.clone(),
                hmac_key_version: destination.hmac_key_version,
                approved_display_label: destination.approved_display_label.clone(),
                verdict,
                event_count: 0,
                first_event_at: event.occurred_at,
                last_event_at: event.occurred_at,
            });
        row.event_count = checked_add(row.event_count, 1, "destination.events")?;
        row.first_event_at = row.first_event_at.min(event.occurred_at);
        row.last_event_at = row.last_event_at.max(event.occurred_at);
        Ok(())
    }

    fn add_security_event(&mut self, event: &AnalyticsEvent) -> Result<(), AccumulatorError> {
        let Some(incoming) = &event.security_event else {
            return Ok(());
        };
        match self.security_events.get(&incoming.event_id) {
            None => {
                self.security_events
                    .insert(incoming.event_id, incoming.clone());
            }
            Some(existing) if incoming.event_revision < existing.event_revision => {}
            Some(existing) if incoming.event_revision == existing.event_revision => {
                if incoming != existing {
                    return Err(AccumulatorError::SecurityEventConflict(incoming.event_id));
                }
            }
            Some(existing) => {
                // A higher revision may only add or change resolution fields;
                // every other field is contract-immutable after first sight.
                let mut frozen = incoming.clone();
                frozen.event_revision = existing.event_revision;
                frozen.resolution.clone_from(&existing.resolution);
                if &frozen != existing {
                    return Err(AccumulatorError::SecurityEventConflict(incoming.event_id));
                }
                self.security_events
                    .insert(incoming.event_id, incoming.clone());
            }
        }
        Ok(())
    }

    fn check_row_limits(&self) -> Result<(), AccumulatorError> {
        check_family("usage", self.usage.len(), MAX_USAGE_ROWS)?;
        check_family("filter", self.filters.len(), MAX_FILTER_ROWS)?;
        check_family("session", self.sessions.len(), MAX_SESSION_ROWS)?;
        check_family("llm", self.llm.len(), MAX_LLM_ROWS)?;
        check_family("destination", self.destinations.len(), MAX_DESTINATION_ROWS)?;
        // Security events are deliberately not capped per day:
        // MAX_SECURITY_EVENTS bounds one snapshot REQUEST's array (uploads
        // chunk a storm day across requests), and a day cap here would turn a
        // deny storm into a permanently unmaterializable day.
        let total = self.usage.len()
            + self.filters.len()
            + self.sessions.len()
            + self.llm.len()
            + self.destinations.len();
        check_family("total", total, MAX_TOTAL_ROLLUP_ROWS)
    }
}

fn checked_add(current: u64, delta: u64, field: &'static str) -> Result<u64, AccumulatorError> {
    let value = current
        .checked_add(delta)
        .ok_or(AccumulatorError::CounterOverflow(field))?;
    if value > MAX_SAFE_INTEGER {
        Err(AccumulatorError::CounterOverflow(field))
    } else {
        Ok(value)
    }
}

fn check_family(family: &'static str, actual: usize, limit: usize) -> Result<(), AccumulatorError> {
    if actual > limit {
        Err(AccumulatorError::RowLimit {
            family,
            actual,
            limit,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::contract::{CompletenessTier, FilterContribution, LlmUsageEvent, SecurityEventType};

    fn event(id: u128, hour: u32, verdict: Verdict, score: i64) -> AnalyticsEvent {
        let occurred_at = Utc.with_ymd_and_hms(2026, 8, 20, hour, 15, 0).unwrap();
        let event_id = Uuid::from_u128(id);
        AnalyticsEvent {
            event_id,
            occurred_at,
            session_id: Some(Uuid::from_u128(99)),
            project: "grith".into(),
            profile_id: "codex".into(),
            config_hash: "a".repeat(64),
            supervised_tool: "codex".into(),
            completeness: CompletenessTier::All,
            record_class: RecordClass::Decision,
            category: Category::FileRead,
            initial_verdict: Some(verdict),
            score_micros: Some(score),
            filter_set_version: Some(1),
            evaluated_filter_ids: vec!["allowlist".into(), "secret-scan".into()],
            positive_filter_contributions: vec![FilterContribution {
                filter_id: "secret-scan".into(),
                score_micros: 2_000_000,
            }],
            llm_usage: None,
            destination: None,
            security_event: None,
            chain_sequence: Some(id as u64),
            chain_hash: Some(format!("{id:064x}")),
        }
    }

    #[test]
    fn decision_denominators_and_replay_are_exact() {
        let day = NaiveDate::from_ymd_opt(2026, 8, 20).unwrap();
        let mut accumulator = DayAccumulator::new(day);
        let deny = event(1, 10, Verdict::Deny, 9_000_000);
        let allow = event(2, 10, Verdict::Allow, 1_000_000);
        assert!(accumulator.ingest(&deny).unwrap());
        assert!(!accumulator.ingest(&deny).unwrap());
        assert!(accumulator.ingest(&allow).unwrap());

        let (snapshot, _) = accumulator.snapshot(1, 1, SnapshotState::Partial).unwrap();
        assert_eq!(snapshot.source_event_count, 2);
        assert_eq!(
            snapshot
                .usage_rows
                .iter()
                .map(|row| row.event_count)
                .sum::<u64>(),
            2
        );
        let allowlist = snapshot
            .filter_rows
            .iter()
            .find(|row| row.filter_id == "allowlist")
            .unwrap();
        assert_eq!(allowlist.evaluated_events, 2);
        assert_eq!(allowlist.triggered_events, 0);
        assert_eq!(allowlist.denied_evaluated_events, 1);
        assert_eq!(allowlist.denied_positive_contributions, 0);
        let secret = snapshot
            .filter_rows
            .iter()
            .find(|row| row.filter_id == "secret-scan")
            .unwrap();
        assert_eq!(secret.evaluated_events, 2);
        assert_eq!(secret.triggered_events, 2);
        assert_eq!(secret.denied_positive_contributions, 1);
    }

    #[test]
    fn llm_usage_does_not_enter_decision_denominator() {
        let day = NaiveDate::from_ymd_opt(2026, 8, 20).unwrap();
        let mut accumulator = DayAccumulator::new(day);
        let mut llm = event(3, 11, Verdict::Allow, 0);
        llm.record_class = RecordClass::LlmUsage;
        llm.category = Category::Llm;
        llm.initial_verdict = None;
        llm.score_micros = None;
        llm.filter_set_version = None;
        llm.evaluated_filter_ids.clear();
        llm.positive_filter_contributions.clear();
        llm.llm_usage = Some(LlmUsageEvent {
            provider: "openai".into(),
            model: "gpt-5".into(),
            prompt_tokens: 100,
            completion_tokens: 25,
            cost_micros: 1_250,
            currency: "USD".into(),
            price_source: "builtin".into(),
            pricing_version: "2026-08-20".into(),
        });
        accumulator.ingest(&llm).unwrap();
        let (snapshot, _) = accumulator.snapshot(1, 1, SnapshotState::Partial).unwrap();
        assert_eq!(snapshot.llm_rows[0].calls, 1);
        assert_eq!(snapshot.session_rows[0].decision_count, 0);
        assert_eq!(snapshot.session_rows[0].llm_calls, 1);
        assert_eq!(snapshot.usage_rows[0].verdict, None);
    }

    #[test]
    fn security_resolution_revision_preserves_initial_verdict() {
        let day = NaiveDate::from_ymd_opt(2026, 8, 20).unwrap();
        let mut accumulator = DayAccumulator::new(day);
        let mut queued = event(4, 12, Verdict::Queue, 5_000_000);
        queued.security_event = Some(SecurityEvent {
            event_id: queued.event_id,
            event_revision: 1,
            occurred_at: queued.occurred_at,
            event_type: SecurityEventType::Queue,
            initial_verdict: Some(Verdict::Queue),
            resolution: None,
            session_id: queued.session_id,
            project: queued.project.clone(),
            profile_id: queued.profile_id.clone(),
            supervised_tool: queued.supervised_tool.clone(),
            category: queued.category,
            score_micros: queued.score_micros,
            top_filter_ids: vec!["secret-scan".into()],
            enforcement_outcome_code: Some("queued_for_review".into()),
            gap_count: None,
            chain_sequence: queued.chain_sequence,
            chain_hash: queued.chain_hash.clone(),
        });
        accumulator.ingest(&queued).unwrap();
        let (_, events) = accumulator.snapshot(1, 1, SnapshotState::Partial).unwrap();
        assert_eq!(events[0].initial_verdict, Some(Verdict::Queue));
        assert_eq!(events[0].event_revision, 1);
    }

    #[test]
    fn canonical_checksum_is_independent_of_ingest_order() {
        let day = NaiveDate::from_ymd_opt(2026, 8, 20).unwrap();
        let one = event(10, 9, Verdict::Allow, 1_000_000);
        let two = event(11, 10, Verdict::Deny, 9_000_000);
        let mut forward = DayAccumulator::new(day);
        forward.ingest(&one).unwrap();
        forward.ingest(&two).unwrap();
        let mut reverse = DayAccumulator::new(day);
        reverse.ingest(&two).unwrap();
        reverse.ingest(&one).unwrap();
        let (forward, _) = forward.snapshot(4, 2, SnapshotState::Final).unwrap();
        let (reverse, _) = reverse.snapshot(99, 8, SnapshotState::Partial).unwrap();
        assert_eq!(forward.row_checksum_sha256, reverse.row_checksum_sha256);
    }

    #[test]
    fn signed_score_bounds_are_enforced_before_accumulation() {
        let day = NaiveDate::from_ymd_opt(2026, 8, 20).unwrap();
        let mut accumulator = DayAccumulator::new(day);
        let too_high = event(20, 9, Verdict::Deny, MAX_ABS_SCORE_MICROS + 1);
        assert!(matches!(
            accumulator.ingest(&too_high),
            Err(AccumulatorError::ScoreOutOfRange(_))
        ));
        assert_eq!(accumulator.source_event_count(), 0);

        let mut bad_contribution = event(21, 9, Verdict::Deny, -MAX_ABS_SCORE_MICROS);
        bad_contribution.positive_filter_contributions[0].score_micros = MAX_ABS_SCORE_MICROS + 1;
        assert!(matches!(
            accumulator.ingest(&bad_contribution),
            Err(AccumulatorError::InvalidFilterContribution { .. })
        ));
        assert_eq!(accumulator.source_event_count(), 0);
    }
}
