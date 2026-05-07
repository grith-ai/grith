// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Anthropic Messages API provider implementation.

use crate::error::{check_http_response, Error, Result};
use crate::provider::LlmProvider;
use crate::types::*;
use serde::{Deserialize, Serialize};

/// L-15: Anthropic API version string.
///
/// This is the version sent in the `anthropic-version` header on every request.
/// Anthropic periodically releases new API versions; update this constant when
/// migrating to a newer version. See: <https://docs.anthropic.com/en/api/versioning>
const ANTHROPIC_API_VERSION: &str = "2023-06-01";

/// M-22: Default Anthropic API base URL.
const DEFAULT_ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com";

/// M-23: Default max_tokens value when the caller does not specify one.
///
/// The Anthropic Messages API requires a `max_tokens` field. When the caller
/// does not provide one via `CompletionRequest::max_tokens`, this default is
/// used. Adjust via `AnthropicProvider::with_default_max_tokens` if needed.
const DEFAULT_MAX_TOKENS: usize = 4096;

/// Anthropic Messages API provider.
pub struct AnthropicProvider {
    client: reqwest::Client,
    model: String,
    /// M-22: Configurable base URL for the Anthropic API endpoint.
    base_url: String,
    /// L-16: Approximate cost per 1K input tokens in USD.
    ///
    /// NOTE: These pricing figures are approximate and may be outdated.
    /// Anthropic may change pricing at any time. Always check the official
    /// pricing page for current rates: <https://www.anthropic.com/pricing>
    input_cost_per_1k: f64,
    /// L-16: Approximate cost per 1K output tokens in USD.
    ///
    /// NOTE: These pricing figures are approximate and may be outdated.
    /// See the note on `input_cost_per_1k` above.
    output_cost_per_1k: f64,
    /// M-23: Configurable default max_tokens value.
    default_max_tokens: usize,
}

impl AnthropicProvider {
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        Self::with_base_url(api_key, model, DEFAULT_ANTHROPIC_BASE_URL)
    }

    /// M-22: Create a provider with a custom base URL (e.g. for proxies or testing).
    pub fn with_base_url(
        api_key: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Result<Self> {
        let key = api_key.into();
        let mut headers = reqwest::header::HeaderMap::new();

        // Fail fast if the API key contains invalid header characters.
        let header_value = reqwest::header::HeaderValue::from_str(&key).map_err(|e| {
            Error::Config(format!(
                "invalid Anthropic API key (non-ASCII or control characters): {e}"
            ))
        })?;
        headers.insert("x-api-key", header_value);

        // L-15: Use the constant for the API version header.
        headers.insert("anthropic-version", ANTHROPIC_API_VERSION.parse().unwrap());
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        // H-28: Add a 60-second timeout to the HTTP client.
        // Fail fast if the client builder fails — never fall back to an
        // unauthenticated client without timeout.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .default_headers(headers)
            .build()
            .map_err(|e| Error::Config(format!("failed to build Anthropic HTTP client: {e}")))?;

        Ok(Self {
            client,
            model: model.into(),
            base_url: base_url.into(),
            // L-16: These pricing figures are approximate and may be outdated.
            // Anthropic may change pricing at any time. Always verify against
            // the official pricing page: https://www.anthropic.com/pricing
            input_cost_per_1k: 0.003,
            output_cost_per_1k: 0.015,
            default_max_tokens: DEFAULT_MAX_TOKENS,
        })
    }

    /// Create from environment variable.
    pub fn from_env(model: impl Into<String>) -> Result<Self> {
        let key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| Error::Config("ANTHROPIC_API_KEY environment variable not set".into()))?;
        Self::new(key, model)
    }

    pub fn with_costs(mut self, input_per_1k: f64, output_per_1k: f64) -> Self {
        self.input_cost_per_1k = input_per_1k;
        self.output_cost_per_1k = output_per_1k;
        self
    }

    /// M-23: Override the default max_tokens value used when the caller does
    /// not specify one in the `CompletionRequest`.
    pub fn with_default_max_tokens(mut self, max_tokens: usize) -> Self {
        self.default_max_tokens = max_tokens;
        self
    }
}

// --- Anthropic API types ---

#[derive(Serialize)]
struct AnthropicRequest {
    model: String,
    messages: Vec<AnthropicMessage>,
    max_tokens: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<AnthropicTool>>,
    stream: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AnthropicMessage {
    role: String,
    content: AnthropicContent,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
enum AnthropicContent {
    Text(String),
    Blocks(Vec<AnthropicBlock>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
enum AnthropicBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
    },
}

#[derive(Serialize)]
struct AnthropicTool {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

#[derive(Deserialize, Debug)]
struct AnthropicResponse {
    content: Vec<AnthropicBlock>,
    model: String,
    stop_reason: Option<String>,
    usage: AnthropicUsage,
}

#[derive(Deserialize, Debug)]
struct AnthropicUsage {
    input_tokens: usize,
    output_tokens: usize,
}

// Streaming event types
#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum AnthropicStreamEvent {
    #[serde(rename = "message_start")]
    MessageStart {
        // Required by serde to correctly deserialize the message_start event.
        #[allow(dead_code)]
        message: AnthropicStreamMessage,
    },
    #[serde(rename = "content_block_start")]
    ContentBlockStart {
        index: usize,
        content_block: AnthropicBlock,
    },
    #[serde(rename = "content_block_delta")]
    ContentBlockDelta {
        // Required by serde to correctly deserialize the content_block_delta event.
        #[allow(dead_code)]
        index: usize,
        delta: AnthropicDelta,
    },
    #[serde(rename = "content_block_stop")]
    ContentBlockStop {
        // Required by serde to correctly deserialize the content_block_stop event.
        #[allow(dead_code)]
        index: usize,
    },
    #[serde(rename = "message_delta")]
    MessageDelta { delta: AnthropicMessageDelta },
    #[serde(rename = "message_stop")]
    MessageStop {},
    #[serde(rename = "ping")]
    Ping {},
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize, Debug)]
struct AnthropicStreamMessage {
    // Required by serde to correctly deserialize the message_start payload.
    #[allow(dead_code)]
    model: String,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum AnthropicDelta {
    #[serde(rename = "text_delta")]
    TextDelta { text: String },
    #[serde(rename = "input_json_delta")]
    InputJsonDelta { partial_json: String },
}

#[derive(Deserialize, Debug)]
struct AnthropicMessageDelta {
    stop_reason: Option<String>,
}

fn build_messages(request: &CompletionRequest) -> Vec<AnthropicMessage> {
    let mut msgs: Vec<AnthropicMessage> = Vec::new();
    // Anthropic uses a separate `system` parameter, so skip system messages here.
    for msg in &request.messages {
        match (&msg.role, &msg.content) {
            (Role::System, _) => {
                // System messages handled via the system parameter.
                continue;
            }
            (Role::Tool, Content::ToolResult(tr)) => {
                // Anthropic requires all tool_result blocks for one turn in a single
                // "user" message. Merge consecutive tool results together.
                let block = AnthropicBlock::ToolResult {
                    tool_use_id: tr.tool_call_id.clone(),
                    content: tr.content.clone(),
                    is_error: tr.is_error,
                };
                let should_merge = matches!(
                    msgs.last(),
                    Some(AnthropicMessage {
                        role,
                        content: AnthropicContent::Blocks(_),
                    }) if role == "user"
                ) && msgs.last().is_some_and(|m| {
                    if let AnthropicContent::Blocks(blocks) = &m.content {
                        blocks
                            .iter()
                            .all(|b| matches!(b, AnthropicBlock::ToolResult { .. }))
                    } else {
                        false
                    }
                });

                if should_merge {
                    if let Some(AnthropicMessage {
                        content: AnthropicContent::Blocks(blocks),
                        ..
                    }) = msgs.last_mut()
                    {
                        blocks.push(block);
                        continue;
                    }
                }
                msgs.push(AnthropicMessage {
                    role: "user".into(),
                    content: AnthropicContent::Blocks(vec![block]),
                });
            }
            (Role::User, _) => {
                msgs.push(AnthropicMessage {
                    role: "user".into(),
                    content: AnthropicContent::Text(msg.text().unwrap_or("").into()),
                });
            }
            (Role::Assistant, Content::Parts(parts)) => {
                // Assistant message with mixed text + tool_use blocks.
                let blocks: Vec<AnthropicBlock> = parts
                    .iter()
                    .map(|part| match part {
                        ContentPart::Text { text } => AnthropicBlock::Text { text: text.clone() },
                        ContentPart::ToolUse(tc) => AnthropicBlock::ToolUse {
                            id: tc.id.clone(),
                            name: tc.name.clone(),
                            input: tc.arguments.clone(),
                        },
                        ContentPart::ToolResult(tr) => AnthropicBlock::ToolResult {
                            tool_use_id: tr.tool_call_id.clone(),
                            content: tr.content.clone(),
                            is_error: tr.is_error,
                        },
                    })
                    .collect();
                msgs.push(AnthropicMessage {
                    role: "assistant".into(),
                    content: AnthropicContent::Blocks(blocks),
                });
            }
            (Role::Assistant, Content::ToolCall(tc)) => {
                // Single tool call from assistant.
                msgs.push(AnthropicMessage {
                    role: "assistant".into(),
                    content: AnthropicContent::Blocks(vec![AnthropicBlock::ToolUse {
                        id: tc.id.clone(),
                        name: tc.name.clone(),
                        input: tc.arguments.clone(),
                    }]),
                });
            }
            (Role::Assistant, _) => {
                msgs.push(AnthropicMessage {
                    role: "assistant".into(),
                    content: AnthropicContent::Text(msg.text().unwrap_or("").into()),
                });
            }
            // M-26: Log a warning for unrecognised role/content combinations
            // instead of silently dropping them.
            (role, content) => {
                tracing::warn!(
                    role = ?role,
                    content_type = std::any::type_name_of_val(content),
                    "unrecognised message role/content combination in Anthropic message builder; dropping message"
                );
            }
        }
    }
    msgs
}

fn build_tools(request: &CompletionRequest) -> Option<Vec<AnthropicTool>> {
    request.tools.as_ref().map(|tools| {
        tools
            .iter()
            .map(|t| AnthropicTool {
                name: t.name.clone(),
                description: t.description.clone(),
                input_schema: t.parameters.clone(),
            })
            .collect()
    })
}

#[async_trait::async_trait]
impl LlmProvider for AnthropicProvider {
    async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse> {
        let api_req = AnthropicRequest {
            model: self.model.clone(),
            messages: build_messages(request),
            // M-23: Use the configurable default_max_tokens instead of hardcoded 4096.
            max_tokens: request.max_tokens.unwrap_or(self.default_max_tokens),
            system: request.system.clone(),
            temperature: request.temperature,
            tools: build_tools(request),
            stream: false,
        };

        // M-22: Use the configurable base_url instead of hardcoded endpoint.
        let resp = self
            .client
            .post(format!("{}/v1/messages", self.base_url))
            .json(&api_req)
            .send()
            .await
            .map_err(Error::Http)?;

        let resp = check_http_response(resp, "anthropic").await?;

        let api_resp: AnthropicResponse = resp.json().await.map_err(Error::Http)?;

        let mut text_parts = Vec::new();
        let mut tool_calls = Vec::new();

        for block in api_resp.content {
            match block {
                AnthropicBlock::Text { text } => text_parts.push(text),
                AnthropicBlock::ToolUse { id, name, input } => {
                    tool_calls.push(ToolCall {
                        id,
                        name,
                        arguments: input,
                    });
                }
                _ => {}
            }
        }

        let content = if text_parts.is_empty() {
            None
        } else {
            Some(text_parts.join(""))
        };

        let finish_reason = match api_resp.stop_reason.as_deref() {
            Some("tool_use") => FinishReason::ToolUse,
            Some("max_tokens") => FinishReason::MaxTokens,
            _ if !tool_calls.is_empty() => FinishReason::ToolUse,
            _ => FinishReason::Stop,
        };

        let prompt_tokens = api_resp.usage.input_tokens;
        let completion_tokens = api_resp.usage.output_tokens;

        Ok(CompletionResponse {
            content,
            tool_calls,
            usage: TokenUsage {
                prompt_tokens,
                completion_tokens,
                total_tokens: prompt_tokens + completion_tokens,
            },
            model: api_resp.model,
            finish_reason,
        })
    }

    async fn complete_stream(&self, request: &CompletionRequest) -> Result<CompletionStream> {
        let api_req = AnthropicRequest {
            model: self.model.clone(),
            messages: build_messages(request),
            // M-23: Use the configurable default_max_tokens instead of hardcoded 4096.
            max_tokens: request.max_tokens.unwrap_or(self.default_max_tokens),
            system: request.system.clone(),
            temperature: request.temperature,
            tools: build_tools(request),
            stream: true,
        };

        // M-22: Use the configurable base_url instead of hardcoded endpoint.
        let resp = self
            .client
            .post(format!("{}/v1/messages", self.base_url))
            .json(&api_req)
            .send()
            .await
            .map_err(Error::Http)?;

        let resp = check_http_response(resp, "anthropic").await?;

        // Track current tool call index for input_json_delta events
        let stream = resp.bytes_stream();
        let mut current_tool_index: usize = 0;
        let mapped = futures::StreamExt::filter_map(stream, move |chunk| {
            let result = match chunk {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    let mut last_chunk = None;
                    for data in crate::sse::parse_sse_data_lines(&text) {
                        if let Ok(event) = serde_json::from_str::<AnthropicStreamEvent>(data) {
                            match event {
                                AnthropicStreamEvent::ContentBlockStart {
                                    index,
                                    content_block: AnthropicBlock::ToolUse { id, name, .. },
                                } => {
                                    current_tool_index = index;
                                    last_chunk = Some(Ok(CompletionChunk {
                                        delta_content: None,
                                        delta_tool_calls: vec![ToolCallDelta {
                                            index,
                                            id: Some(id),
                                            name: Some(name),
                                            arguments_delta: None,
                                        }],
                                        finish_reason: None,
                                    }));
                                }
                                AnthropicStreamEvent::ContentBlockDelta {
                                    delta: AnthropicDelta::TextDelta { text },
                                    ..
                                } => {
                                    last_chunk = Some(Ok(CompletionChunk {
                                        delta_content: Some(text),
                                        delta_tool_calls: vec![],
                                        finish_reason: None,
                                    }));
                                }
                                AnthropicStreamEvent::ContentBlockDelta {
                                    delta: AnthropicDelta::InputJsonDelta { partial_json },
                                    ..
                                } => {
                                    last_chunk = Some(Ok(CompletionChunk {
                                        delta_content: None,
                                        delta_tool_calls: vec![ToolCallDelta {
                                            index: current_tool_index,
                                            id: None,
                                            name: None,
                                            arguments_delta: Some(partial_json),
                                        }],
                                        finish_reason: None,
                                    }));
                                }
                                AnthropicStreamEvent::MessageDelta { delta } => {
                                    let finish = delta.stop_reason.map(|r| match r.as_str() {
                                        "end_turn" => FinishReason::Stop,
                                        "tool_use" => FinishReason::ToolUse,
                                        "max_tokens" => FinishReason::MaxTokens,
                                        _ => FinishReason::Stop,
                                    });
                                    if finish.is_some() {
                                        last_chunk = Some(Ok(CompletionChunk {
                                            delta_content: None,
                                            delta_tool_calls: vec![],
                                            finish_reason: finish,
                                        }));
                                    }
                                }
                                // M-26: Log a warning for unknown stream event patterns
                                // instead of silently dropping them.
                                AnthropicStreamEvent::Unknown => {
                                    tracing::warn!(
                                        raw_data = data,
                                        "unknown Anthropic stream event type; ignoring"
                                    );
                                }
                                // Known event types that we intentionally ignore
                                // (MessageStart, ContentBlockStart for text,
                                // ContentBlockStop, MessageStop, Ping).
                                _ => {}
                            }
                        }
                    }
                    last_chunk
                }
                Err(e) => Some(Err(Error::Http(e))),
            };
            async { result }
        });

        Ok(Box::pin(mapped))
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            supports_streaming: true,
            supports_tools: true,
            supports_vision: true,
            max_tokens: 200_000,
        }
    }

    fn cost_estimate(&self, input_tokens: usize, output_tokens: usize) -> CostEstimate {
        let input_cost = (input_tokens as f64 / 1000.0) * self.input_cost_per_1k;
        let output_cost = (output_tokens as f64 / 1000.0) * self.output_cost_per_1k;
        CostEstimate {
            input_cost,
            output_cost,
            total_cost: input_cost + output_cost,
            currency: "USD".into(),
        }
    }

    fn name(&self) -> &str {
        "anthropic"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = AnthropicProvider::new("test-key", "claude-sonnet-4-5-20250929").unwrap();
        assert_eq!(provider.name(), "anthropic");
        assert!(provider.capabilities().supports_tools);
        assert_eq!(provider.capabilities().max_tokens, 200_000);
    }

    #[test]
    fn test_provider_with_custom_base_url() {
        let provider = AnthropicProvider::with_base_url(
            "test-key",
            "claude-sonnet-4-5-20250929",
            "https://my-proxy.example.com",
        )
        .unwrap();
        assert_eq!(provider.base_url, "https://my-proxy.example.com");
    }

    #[test]
    fn test_provider_with_default_max_tokens() {
        let provider = AnthropicProvider::new("test-key", "claude-sonnet-4-5-20250929")
            .unwrap()
            .with_default_max_tokens(8192);
        assert_eq!(provider.default_max_tokens, 8192);
    }

    #[test]
    fn test_provider_default_base_url() {
        let provider = AnthropicProvider::new("test-key", "claude-sonnet-4-5-20250929").unwrap();
        assert_eq!(provider.base_url, DEFAULT_ANTHROPIC_BASE_URL);
    }

    #[test]
    fn test_invalid_api_key_header_returns_error() {
        // API keys with control characters (e.g. newlines) should return a Config
        // error instead of panicking or silently degrading to an unauthenticated client.
        let result = AnthropicProvider::new("test-key\ninjection", "claude-sonnet-4-5-20250929");
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(
            matches!(err, Error::Config(_)),
            "expected Config error, got: {err:?}"
        );
    }

    #[test]
    fn test_build_messages_basic() {
        let req =
            CompletionRequest::new(vec![Message::user("hello"), Message::assistant("hi there")])
                .with_system("You are helpful");
        let msgs = build_messages(&req);
        // System messages are not included (handled separately)
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "user");
        assert_eq!(msgs[1].role, "assistant");
    }

    #[test]
    fn test_build_messages_tool_result() {
        let req = CompletionRequest::new(vec![
            Message::user("hello"),
            Message::tool_result("call_0", "file contents here"),
        ]);
        let msgs = build_messages(&req);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[1].role, "user"); // Tool results sent as user role in Anthropic
    }

    #[test]
    fn test_build_tools() {
        let tools = vec![ToolDefinition {
            name: "read_file".into(),
            description: "Read a file".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                }
            }),
        }];
        let req = CompletionRequest::new(vec![Message::user("test")]).with_tools(tools);
        let anthropic_tools = build_tools(&req).unwrap();
        assert_eq!(anthropic_tools.len(), 1);
        assert_eq!(anthropic_tools[0].name, "read_file");
    }

    #[test]
    fn test_cost_estimate() {
        let provider = AnthropicProvider::new("test-key", "claude-sonnet-4-5-20250929").unwrap();
        let cost = provider.cost_estimate(1000, 500);
        assert!((cost.input_cost - 0.003).abs() < 0.001);
        assert!((cost.output_cost - 0.0075).abs() < 0.001);
    }

    #[test]
    fn test_anthropic_content_serde() {
        let msg = AnthropicMessage {
            role: "user".into(),
            content: AnthropicContent::Text("hello".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"hello\""));

        let blocks_msg = AnthropicMessage {
            role: "user".into(),
            content: AnthropicContent::Blocks(vec![AnthropicBlock::Text {
                text: "hello".into(),
            }]),
        };
        let json = serde_json::to_string(&blocks_msg).unwrap();
        assert!(json.contains("\"text\""));
    }

    #[test]
    fn test_anthropic_response_parse() {
        let json = r#"{
            "content": [
                {"type": "text", "text": "Hello!"}
            ],
            "model": "claude-sonnet-4-5-20250929",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        }"#;
        let resp: AnthropicResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.model, "claude-sonnet-4-5-20250929");
        assert_eq!(resp.usage.input_tokens, 10);
        assert_eq!(resp.content.len(), 1);
    }

    #[test]
    fn test_anthropic_tool_use_response_parse() {
        let json = r#"{
            "content": [
                {"type": "text", "text": "Let me read that file."},
                {"type": "tool_use", "id": "toolu_01", "name": "read_file", "input": {"path": "/tmp/test.txt"}}
            ],
            "model": "claude-sonnet-4-5-20250929",
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 50, "output_tokens": 30}
        }"#;
        let resp: AnthropicResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.content.len(), 2);
        assert_eq!(resp.stop_reason.as_deref(), Some("tool_use"));
    }

    #[test]
    fn test_api_version_constant() {
        assert_eq!(ANTHROPIC_API_VERSION, "2023-06-01");
    }
}
