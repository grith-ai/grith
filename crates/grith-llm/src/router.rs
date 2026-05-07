// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! LLM request router with fixed, rule-based, and semantic routing strategies.

use crate::error::{Error, Result};
use crate::provider::LlmProvider;
use crate::types::*;
use std::sync::Arc;

/// LLM router -- selects the appropriate provider based on a routing strategy.
///
/// L-14: Providers are stored in a `Vec` (insertion-ordered) rather than a
/// `HashMap` so that fallback iteration order is deterministic and matches
/// the order in which providers were registered.
pub struct LlmRouter {
    providers: Vec<(String, Arc<dyn LlmProvider>)>,
    strategy: RoutingStrategy,
}

/// A semantic route definition: maps a named route with keyword triggers to a provider.
#[derive(Debug, Clone)]
pub struct SemanticRoute {
    pub name: String,
    pub description: String,
    pub keywords: Vec<String>,
    pub provider: String,
}

/// Strategy for selecting which LLM provider to use.
#[derive(Debug, Clone)]
pub enum RoutingStrategy {
    /// Always use a single provider.
    Fixed { provider: String },
    /// Route based on estimated task complexity.
    RuleBased {
        simple_provider: String,
        complex_provider: String,
        /// Token threshold below which a request is "simple".
        simple_threshold: usize,
        /// Keywords that indicate a complex request.
        complex_keywords: Vec<String>,
    },
    /// Route based on semantic matching of request content against route definitions.
    Semantic {
        simple_provider: String,
        complex_provider: String,
        /// Semantic route definitions: (route_name, description, provider_name)
        routes: Vec<SemanticRoute>,
    },
}

impl LlmRouter {
    pub fn new(strategy: RoutingStrategy) -> Self {
        Self {
            providers: Vec::new(),
            strategy,
        }
    }

    /// Create a router that always uses a single provider.
    pub fn fixed(provider_name: impl Into<String>, provider: Arc<dyn LlmProvider>) -> Self {
        let name = provider_name.into();
        let mut router = Self::new(RoutingStrategy::Fixed {
            provider: name.clone(),
        });
        router.providers.push((name, provider));
        router
    }

    /// Create a router that uses semantic matching to select providers.
    pub fn semantic(
        simple_provider: impl Into<String>,
        complex_provider: impl Into<String>,
        routes: Vec<SemanticRoute>,
    ) -> Self {
        Self::new(RoutingStrategy::Semantic {
            simple_provider: simple_provider.into(),
            complex_provider: complex_provider.into(),
            routes,
        })
    }

    /// Register a provider with the router.
    ///
    /// If a provider with the same name already exists, it is replaced
    /// (preserving its position in the insertion order).
    pub fn register_provider(&mut self, name: impl Into<String>, provider: Arc<dyn LlmProvider>) {
        let name = name.into();
        if let Some(entry) = self.providers.iter_mut().find(|(n, _)| *n == name) {
            entry.1 = provider;
        } else {
            self.providers.push((name, provider));
        }
    }

    /// Select a provider based on the routing strategy and request.
    pub fn route(&self, request: &CompletionRequest) -> Result<&Arc<dyn LlmProvider>> {
        let provider_name = match &self.strategy {
            RoutingStrategy::Fixed { provider } => provider.clone(),
            RoutingStrategy::RuleBased {
                simple_provider,
                complex_provider,
                simple_threshold,
                complex_keywords,
            } => {
                if is_complex(request, *simple_threshold, complex_keywords) {
                    complex_provider.clone()
                } else {
                    simple_provider.clone()
                }
            }
            RoutingStrategy::Semantic {
                simple_provider,
                routes,
                ..
            } => semantic_match(request, routes, simple_provider),
        };

        self.providers
            .iter()
            .find(|(n, _)| *n == provider_name)
            .map(|(_, p)| p)
            .ok_or(Error::NoProvider)
    }

    /// Send a completion request, routing to the appropriate provider.
    /// Falls back to other providers in registration order if the primary one fails.
    pub async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse> {
        let primary = self.route(request)?;
        match primary.complete(request).await {
            Ok(resp) => Ok(resp),
            Err(primary_err) => {
                let primary_name = primary.name().to_string();
                // Try fallback providers in registration (deterministic) order
                for (name, provider) in &self.providers {
                    if *name == primary_name {
                        continue;
                    }
                    if let Ok(resp) = provider.complete(request).await {
                        tracing::warn!(
                            primary = primary_name,
                            fallback = name.as_str(),
                            "primary provider failed, using fallback"
                        );
                        return Ok(resp);
                    }
                }
                Err(primary_err)
            }
        }
    }

    /// Send a streaming completion request to the routed provider.
    pub async fn complete_stream(&self, request: &CompletionRequest) -> Result<CompletionStream> {
        let provider = self.route(request)?;
        provider.complete_stream(request).await
    }

    /// Get a provider by name.
    pub fn get_provider(&self, name: &str) -> Option<&Arc<dyn LlmProvider>> {
        self.providers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, p)| p)
    }

    /// List all registered provider names (in registration order).
    pub fn provider_names(&self) -> Vec<&str> {
        self.providers.iter().map(|(n, _)| n.as_str()).collect()
    }
}

/// Determine if a request is "complex" based on token estimate and keywords.
fn is_complex(
    request: &CompletionRequest,
    simple_threshold: usize,
    complex_keywords: &[String],
) -> bool {
    // Estimate total tokens from all messages
    let total_text: String = request
        .messages
        .iter()
        .filter_map(|m| m.text())
        .collect::<Vec<_>>()
        .join(" ");

    let estimated_tokens = estimate_tokens(&total_text);

    // If token count exceeds threshold, it's complex
    if estimated_tokens > simple_threshold {
        return true;
    }

    // Check for complex keywords in the text
    let lower = total_text.to_lowercase();
    for keyword in complex_keywords {
        if lower.contains(&keyword.to_lowercase()) {
            return true;
        }
    }

    // If tools are requested, lean towards complex
    if let Some(tools) = &request.tools {
        if tools.len() > 3 {
            return true;
        }
    }

    false
}

/// Match request text against semantic routes using case-insensitive keyword substring matching.
/// Returns the provider name of the route with the most keyword matches,
/// or `fallback` if no routes match.
fn semantic_match(request: &CompletionRequest, routes: &[SemanticRoute], fallback: &str) -> String {
    let total_text: String = request
        .messages
        .iter()
        .filter_map(|m| m.text())
        .collect::<Vec<_>>()
        .join(" ");
    let lower = total_text.to_lowercase();

    let mut best_provider: Option<&str> = None;
    let mut best_count: usize = 0;

    for route in routes {
        let match_count = route
            .keywords
            .iter()
            .filter(|kw| lower.contains(&kw.to_lowercase()))
            .count();
        if match_count > 0 && match_count > best_count {
            best_count = match_count;
            best_provider = Some(&route.provider);
        }
    }

    best_provider.unwrap_or(fallback).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        CompletionChunk, CompletionResponse, CostEstimate, FinishReason, ProviderCapabilities,
        TokenUsage,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A mock provider for testing.
    struct MockProvider {
        provider_name: String,
        call_count: AtomicUsize,
        should_fail: bool,
    }

    impl MockProvider {
        fn new(name: &str) -> Self {
            Self {
                provider_name: name.into(),
                call_count: AtomicUsize::new(0),
                should_fail: false,
            }
        }

        fn failing(name: &str) -> Self {
            Self {
                provider_name: name.into(),
                call_count: AtomicUsize::new(0),
                should_fail: true,
            }
        }
    }

    #[async_trait::async_trait]
    impl LlmProvider for MockProvider {
        async fn complete(&self, _request: &CompletionRequest) -> Result<CompletionResponse> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail {
                return Err(Error::Provider {
                    provider: self.provider_name.clone(),
                    message: "mock failure".into(),
                });
            }
            Ok(CompletionResponse {
                content: Some(format!("response from {}", self.provider_name)),
                tool_calls: vec![],
                usage: TokenUsage::default(),
                model: "mock".into(),
                finish_reason: FinishReason::Stop,
            })
        }

        async fn complete_stream(&self, _request: &CompletionRequest) -> Result<CompletionStream> {
            let chunk = CompletionChunk {
                delta_content: Some("streamed".into()),
                delta_tool_calls: vec![],
                finish_reason: Some(FinishReason::Stop),
            };
            Ok(Box::pin(futures::stream::once(async { Ok(chunk) })))
        }

        fn capabilities(&self) -> ProviderCapabilities {
            ProviderCapabilities {
                supports_streaming: true,
                supports_tools: true,
                supports_vision: false,
                max_tokens: 4096,
            }
        }

        fn cost_estimate(&self, _input: usize, _output: usize) -> CostEstimate {
            CostEstimate {
                input_cost: 0.0,
                output_cost: 0.0,
                total_cost: 0.0,
                currency: "USD".into(),
            }
        }

        fn name(&self) -> &str {
            &self.provider_name
        }
    }

    #[test]
    fn test_fixed_routing() {
        let mock = Arc::new(MockProvider::new("test"));
        let router = LlmRouter::fixed("test", mock);
        let req = CompletionRequest::new(vec![Message::user("hello")]);
        let provider = router.route(&req).unwrap();
        assert_eq!(provider.name(), "test");
    }

    #[test]
    fn test_rule_based_simple() {
        let mut router = LlmRouter::new(RoutingStrategy::RuleBased {
            simple_provider: "fast".into(),
            complex_provider: "smart".into(),
            simple_threshold: 500,
            complex_keywords: vec!["analyze".into(), "refactor".into()],
        });
        router.register_provider("fast", Arc::new(MockProvider::new("fast")));
        router.register_provider("smart", Arc::new(MockProvider::new("smart")));

        let req = CompletionRequest::new(vec![Message::user("hello")]);
        let provider = router.route(&req).unwrap();
        assert_eq!(provider.name(), "fast");
    }

    #[test]
    fn test_rule_based_complex_keyword() {
        let mut router = LlmRouter::new(RoutingStrategy::RuleBased {
            simple_provider: "fast".into(),
            complex_provider: "smart".into(),
            simple_threshold: 500,
            complex_keywords: vec!["analyze".into(), "refactor".into()],
        });
        router.register_provider("fast", Arc::new(MockProvider::new("fast")));
        router.register_provider("smart", Arc::new(MockProvider::new("smart")));

        let req = CompletionRequest::new(vec![Message::user("Please analyze this code carefully")]);
        let provider = router.route(&req).unwrap();
        assert_eq!(provider.name(), "smart");
    }

    #[test]
    fn test_rule_based_complex_tokens() {
        let mut router = LlmRouter::new(RoutingStrategy::RuleBased {
            simple_provider: "fast".into(),
            complex_provider: "smart".into(),
            simple_threshold: 10,
            complex_keywords: vec![],
        });
        router.register_provider("fast", Arc::new(MockProvider::new("fast")));
        router.register_provider("smart", Arc::new(MockProvider::new("smart")));

        // Long message exceeding threshold
        let long_text = "word ".repeat(100);
        let req = CompletionRequest::new(vec![Message::user(long_text)]);
        let provider = router.route(&req).unwrap();
        assert_eq!(provider.name(), "smart");
    }

    #[test]
    fn test_no_provider_error() {
        let router = LlmRouter::new(RoutingStrategy::Fixed {
            provider: "nonexistent".into(),
        });
        let req = CompletionRequest::new(vec![Message::user("hello")]);
        assert!(router.route(&req).is_err());
    }

    #[tokio::test]
    async fn test_complete_with_fallback() {
        let mut router = LlmRouter::new(RoutingStrategy::Fixed {
            provider: "primary".into(),
        });
        router.register_provider("primary", Arc::new(MockProvider::failing("primary")));
        router.register_provider("backup", Arc::new(MockProvider::new("backup")));

        let req = CompletionRequest::new(vec![Message::user("hello")]);
        let resp = router.complete(&req).await.unwrap();
        assert_eq!(resp.content.unwrap(), "response from backup");
    }

    #[tokio::test]
    async fn test_complete_primary_success() {
        let mock = Arc::new(MockProvider::new("primary"));
        let router = LlmRouter::fixed("primary", mock);

        let req = CompletionRequest::new(vec![Message::user("hello")]);
        let resp = router.complete(&req).await.unwrap();
        assert_eq!(resp.content.unwrap(), "response from primary");
    }

    #[test]
    fn test_provider_names() {
        let mut router = LlmRouter::new(RoutingStrategy::Fixed {
            provider: "a".into(),
        });
        router.register_provider("a", Arc::new(MockProvider::new("a")));
        router.register_provider("b", Arc::new(MockProvider::new("b")));

        // L-14: Order is now deterministic (insertion order).
        let names = router.provider_names();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn test_provider_names_deterministic_order() {
        // L-14: Verify that provider iteration order matches registration order.
        let mut router = LlmRouter::new(RoutingStrategy::Fixed {
            provider: "first".into(),
        });
        router.register_provider("first", Arc::new(MockProvider::new("first")));
        router.register_provider("second", Arc::new(MockProvider::new("second")));
        router.register_provider("third", Arc::new(MockProvider::new("third")));

        let names = router.provider_names();
        assert_eq!(names, vec!["first", "second", "third"]);
    }

    #[test]
    fn test_is_complex_many_tools() {
        let tools: Vec<ToolDefinition> = (0..5)
            .map(|i| ToolDefinition {
                name: format!("tool_{i}"),
                description: format!("Tool {i}"),
                parameters: serde_json::json!({}),
            })
            .collect();
        let req = CompletionRequest::new(vec![Message::user("hi")]).with_tools(tools);
        assert!(is_complex(&req, 500, &[]));
    }

    #[test]
    fn test_get_provider() {
        let mock = Arc::new(MockProvider::new("test"));
        let router = LlmRouter::fixed("test", mock);
        assert!(router.get_provider("test").is_some());
        assert!(router.get_provider("nonexistent").is_none());
    }

    // --- Semantic routing tests ---

    fn make_semantic_router() -> LlmRouter {
        let routes = vec![
            SemanticRoute {
                name: "code".into(),
                description: "Code generation tasks".into(),
                keywords: vec!["code".into(), "function".into(), "implement".into()],
                provider: "coder".into(),
            },
            SemanticRoute {
                name: "writing".into(),
                description: "Creative writing tasks".into(),
                keywords: vec!["write".into(), "essay".into(), "story".into()],
                provider: "writer".into(),
            },
        ];
        let mut router = LlmRouter::semantic("default", "complex", routes);
        router.register_provider("default", Arc::new(MockProvider::new("default")));
        router.register_provider("complex", Arc::new(MockProvider::new("complex")));
        router.register_provider("coder", Arc::new(MockProvider::new("coder")));
        router.register_provider("writer", Arc::new(MockProvider::new("writer")));
        router
    }

    #[test]
    fn test_semantic_routing_selects_correct_provider() {
        let router = make_semantic_router();
        let req = CompletionRequest::new(vec![Message::user(
            "Please implement a function to sort a list",
        )]);
        let provider = router.route(&req).unwrap();
        assert_eq!(provider.name(), "coder");
    }

    #[test]
    fn test_semantic_routing_fallback_when_no_match() {
        let router = make_semantic_router();
        let req = CompletionRequest::new(vec![Message::user("hello there")]);
        let provider = router.route(&req).unwrap();
        assert_eq!(provider.name(), "default");
    }

    #[test]
    fn test_semantic_routing_highest_keyword_count_wins() {
        let routes = vec![
            SemanticRoute {
                name: "general".into(),
                description: "General tasks".into(),
                keywords: vec!["code".into()],
                provider: "general".into(),
            },
            SemanticRoute {
                name: "specialist".into(),
                description: "Specialist tasks".into(),
                keywords: vec!["code".into(), "function".into(), "implement".into()],
                provider: "specialist".into(),
            },
        ];
        let mut router = LlmRouter::semantic("default", "complex", routes);
        router.register_provider("default", Arc::new(MockProvider::new("default")));
        router.register_provider("general", Arc::new(MockProvider::new("general")));
        router.register_provider("specialist", Arc::new(MockProvider::new("specialist")));

        // This text matches "code", "function", and "implement" => 3 matches for specialist, 1 for general
        let req =
            CompletionRequest::new(vec![Message::user("implement a code function for parsing")]);
        let provider = router.route(&req).unwrap();
        assert_eq!(provider.name(), "specialist");
    }

    #[test]
    fn test_semantic_route_empty_keywords_never_matches() {
        let routes = vec![SemanticRoute {
            name: "empty".into(),
            description: "Route with no keywords".into(),
            keywords: vec![],
            provider: "empty_provider".into(),
        }];
        let mut router = LlmRouter::semantic("default", "complex", routes);
        router.register_provider("default", Arc::new(MockProvider::new("default")));
        router.register_provider(
            "empty_provider",
            Arc::new(MockProvider::new("empty_provider")),
        );

        let req = CompletionRequest::new(vec![Message::user("this could be anything at all")]);
        let provider = router.route(&req).unwrap();
        // Should fall back to default since empty keywords never match
        assert_eq!(provider.name(), "default");
    }
}
