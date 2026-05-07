// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Ollama local LLM provider implementation.

use crate::error::{check_http_response, Error, Result};
use crate::provider::LlmProvider;
use crate::types::*;
use serde::{Deserialize, Serialize};

/// Ollama LLM provider.
pub struct OllamaProvider {
    client: reqwest::Client,
    base_url: String,
    model: String,
}

impl OllamaProvider {
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        // H-28: Add a 60-second timeout to the HTTP client.
        // Fail fast if the client builder fails — never fall back to a client
        // without timeout.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| Error::Config(format!("failed to build Ollama HTTP client: {e}")))?;
        Ok(Self {
            client,
            base_url: base_url.into(),
            model: model.into(),
        })
    }

    /// Check if the Ollama server is reachable.
    pub async fn health_check(&self) -> Result<bool> {
        let resp = self
            .client
            .get(format!("{}/api/tags", self.base_url))
            .send()
            .await;
        Ok(resp.is_ok())
    }
}

#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaOptions>,
}

#[derive(Serialize)]
struct OllamaOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_predict: Option<usize>,
}

#[derive(Serialize, Deserialize)]
struct OllamaMessage {
    role: String,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<OllamaToolCall>>,
}

#[derive(Serialize, Deserialize)]
struct OllamaToolCall {
    function: OllamaFunction,
}

#[derive(Serialize, Deserialize)]
struct OllamaFunction {
    name: String,
    arguments: serde_json::Value,
}

#[derive(Deserialize)]
struct OllamaResponse {
    message: OllamaMessage,
    #[serde(default)]
    done: bool,
    #[serde(default)]
    prompt_eval_count: Option<usize>,
    #[serde(default)]
    eval_count: Option<usize>,
}

fn convert_messages(request: &CompletionRequest) -> Vec<OllamaMessage> {
    let mut msgs = Vec::new();
    if let Some(system) = &request.system {
        msgs.push(OllamaMessage {
            role: "system".into(),
            content: system.clone(),
            tool_calls: None,
        });
    }
    for msg in &request.messages {
        let role = match msg.role {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
        };
        let content = msg.text().unwrap_or("").to_string();
        msgs.push(OllamaMessage {
            role: role.into(),
            content,
            tool_calls: None,
        });
    }
    msgs
}

fn convert_tools(request: &CompletionRequest) -> Option<Vec<serde_json::Value>> {
    request.tools.as_ref().map(|tools| {
        tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    }
                })
            })
            .collect()
    })
}

/// M-24: Generate a unique tool call ID using UUID v4.
fn generate_tool_call_id() -> String {
    format!("call_{}", uuid::Uuid::new_v4())
}

#[async_trait::async_trait]
impl LlmProvider for OllamaProvider {
    async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse> {
        let ollama_req = OllamaRequest {
            model: self.model.clone(),
            messages: convert_messages(request),
            stream: false,
            tools: convert_tools(request),
            options: Some(OllamaOptions {
                temperature: request.temperature,
                num_predict: request.max_tokens,
            }),
        };

        let resp = self
            .client
            .post(format!("{}/api/chat", self.base_url))
            .json(&ollama_req)
            .send()
            .await
            .map_err(Error::Http)?;

        let resp = check_http_response(resp, "ollama").await?;

        let ollama_resp: OllamaResponse = resp.json().await.map_err(Error::Http)?;

        // M-24: Use UUID-based IDs instead of sequential call_0, call_1, etc.
        let tool_calls = ollama_resp
            .message
            .tool_calls
            .unwrap_or_default()
            .into_iter()
            .map(|tc| ToolCall {
                id: generate_tool_call_id(),
                name: tc.function.name,
                arguments: tc.function.arguments,
            })
            .collect::<Vec<_>>();

        let finish_reason = if !tool_calls.is_empty() {
            FinishReason::ToolUse
        } else {
            FinishReason::Stop
        };

        let prompt_tokens = ollama_resp.prompt_eval_count.unwrap_or(0);
        let completion_tokens = ollama_resp.eval_count.unwrap_or(0);

        Ok(CompletionResponse {
            content: if ollama_resp.message.content.is_empty() {
                None
            } else {
                Some(ollama_resp.message.content)
            },
            tool_calls,
            usage: TokenUsage {
                prompt_tokens,
                completion_tokens,
                total_tokens: prompt_tokens + completion_tokens,
            },
            model: self.model.clone(),
            finish_reason,
        })
    }

    async fn complete_stream(&self, request: &CompletionRequest) -> Result<CompletionStream> {
        let ollama_req = OllamaRequest {
            model: self.model.clone(),
            messages: convert_messages(request),
            stream: true,
            tools: convert_tools(request),
            options: Some(OllamaOptions {
                temperature: request.temperature,
                num_predict: request.max_tokens,
            }),
        };

        let resp = self
            .client
            .post(format!("{}/api/chat", self.base_url))
            .json(&ollama_req)
            .send()
            .await
            .map_err(Error::Http)?;

        let resp = check_http_response(resp, "ollama").await?;

        // H-27: Track tool call index across stream chunks so we can emit deltas.
        let stream = resp.bytes_stream();
        let mut tool_call_index: usize = 0;
        let mapped = futures::StreamExt::filter_map(stream, move |chunk| {
            let result = match chunk {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    let mut last_chunk = None;
                    for line in text.lines() {
                        if line.is_empty() {
                            continue;
                        }
                        if let Ok(resp) = serde_json::from_str::<OllamaResponse>(line) {
                            // H-27: Parse and emit tool call deltas when available.
                            let delta_tool_calls: Vec<ToolCallDelta> = resp
                                .message
                                .tool_calls
                                .unwrap_or_default()
                                .into_iter()
                                .map(|tc| {
                                    let idx = tool_call_index;
                                    tool_call_index += 1;
                                    ToolCallDelta {
                                        index: idx,
                                        id: Some(generate_tool_call_id()),
                                        name: Some(tc.function.name),
                                        arguments_delta: Some(tc.function.arguments.to_string()),
                                    }
                                })
                                .collect();

                            let finish_reason = if resp.done {
                                if !delta_tool_calls.is_empty() {
                                    Some(FinishReason::ToolUse)
                                } else {
                                    Some(FinishReason::Stop)
                                }
                            } else {
                                None
                            };

                            last_chunk = Some(Ok(CompletionChunk {
                                delta_content: if resp.message.content.is_empty() {
                                    None
                                } else {
                                    Some(resp.message.content)
                                },
                                delta_tool_calls,
                                finish_reason,
                            }));
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
            supports_vision: false,
            max_tokens: 128_000,
        }
    }

    fn cost_estimate(&self, _input_tokens: usize, _output_tokens: usize) -> CostEstimate {
        CostEstimate {
            input_cost: 0.0,
            output_cost: 0.0,
            total_cost: 0.0,
            currency: "USD".into(),
        }
    }

    fn name(&self) -> &str {
        "ollama"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ollama_provider_creation() {
        let provider = OllamaProvider::new("http://localhost:11434", "llama3.1:8b").unwrap();
        assert_eq!(provider.name(), "ollama");
        assert!(provider.capabilities().supports_streaming);
    }

    #[test]
    fn test_convert_messages() {
        let req =
            CompletionRequest::new(vec![Message::user("hello")]).with_system("You are helpful");
        let msgs = convert_messages(&req);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "system");
        assert_eq!(msgs[1].role, "user");
    }

    #[test]
    fn test_cost_estimate_local() {
        let provider = OllamaProvider::new("http://localhost:11434", "llama3.1:8b").unwrap();
        let cost = provider.cost_estimate(1000, 500);
        assert_eq!(cost.total_cost, 0.0);
    }

    #[test]
    fn test_generate_tool_call_id_uniqueness() {
        let id1 = generate_tool_call_id();
        let id2 = generate_tool_call_id();
        assert_ne!(id1, id2);
        assert!(id1.starts_with("call_"));
        assert!(id2.starts_with("call_"));
    }
}
