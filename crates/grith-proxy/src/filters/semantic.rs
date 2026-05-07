// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Semantic context analysis filter stub (Phase 3).

use crate::filters::{FilterPhase, SecurityFilter};
use crate::types::{FilterResult, ToolCallContext};
use tracing::warn;

/// Stub filter for semantic context analysis.
///
/// This filter will eventually use an embedding model to perform
/// semantic similarity analysis on tool call arguments and detect
/// semantically suspicious patterns. For the v1.5 MVP, this is a
/// placeholder that is always inactive.
///
/// When fully implemented, this filter will:
/// - Encode tool call arguments using a local embedding model
/// - Compare embeddings against known-safe and known-dangerous patterns
/// - Score based on semantic similarity to dangerous templates
///
/// Runs in Phase 3 (Context).
pub struct SemanticFilter {
    _placeholder: (),
}

impl SemanticFilter {
    pub fn new() -> Self {
        warn!(
            "SemanticFilter is inactive: no embedding model configured. \
             This filter will not contribute to scoring until a model is integrated."
        );
        Self { _placeholder: () }
    }
}

impl Default for SemanticFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SecurityFilter for SemanticFilter {
    fn name(&self) -> &str {
        "semantic"
    }

    fn phase(&self) -> FilterPhase {
        FilterPhase::Context
    }

    fn is_ready(&self) -> bool {
        // Not active in v1.5 MVP. The embedding model integration
        // will be added in a future release.
        false
    }

    async fn evaluate(&self, _ctx: &ToolCallContext) -> crate::error::Result<FilterResult> {
        // Always return no-match since the filter is not active.
        Ok(FilterResult::no_match("semantic"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ToolCallType;
    use uuid::Uuid;

    fn make_ctx(call_type: ToolCallType) -> ToolCallContext {
        ToolCallContext::new("test", call_type, Uuid::new_v4())
    }

    #[tokio::test]
    async fn test_is_not_ready() {
        let filter = SemanticFilter::new();
        assert!(!filter.is_ready());
    }

    #[tokio::test]
    async fn test_always_returns_no_match() {
        let filter = SemanticFilter::new();
        let ctx = make_ctx(ToolCallType::ShellExec {
            command: "rm".into(),
            args: vec!["-rf".into(), "/".into()],
        });
        let result = filter.evaluate(&ctx).await.unwrap();
        assert!(!result.matched);
        assert_eq!(result.score, 0.0);
    }

    #[tokio::test]
    async fn test_filter_identity() {
        let filter = SemanticFilter::new();
        assert_eq!(filter.name(), "semantic");
        assert_eq!(filter.phase(), FilterPhase::Context);
    }

    #[tokio::test]
    async fn test_default_constructor() {
        let filter = SemanticFilter::default();
        assert!(!filter.is_ready());
        assert_eq!(filter.name(), "semantic");
    }
}
