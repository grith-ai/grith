// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! OpenAI-compatible provider for OpenAI, OpenRouter, LM Studio, vLLM, and others.

use crate::error::{check_http_response, Error, Result};
use crate::provider::LlmProvider;
use crate::types::*;
use serde::{Deserialize, Serialize};

/// OpenAI-compatible LLM provider.
/// Works with: OpenAI, OpenRouter, LM Studio, llama.cpp server, LiteLLM, vLLM.
pub struct OpenAiCompatProvider {
    client: reqwest::Client,
    base_url: String,
    model: String,
    provider_name: String,
    input_cost_per_1k: f64,
    output_cost_per_1k: f64,
}

impl OpenAiCompatProvider {
    pub fn new(
        base_url: impl Into<String>,
        model: impl Into<String>,
        api_key: Option<String>,
    ) -> Result<Self> {
        // H-28: Add a 60-second timeout to the HTTP client.
        let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(60));
        if let Some(key) = api_key {
            let mut headers = reqwest::header::HeaderMap::new();
            let header_value = reqwest::header::HeaderValue::from_str(&format!("Bearer {key}"))
                .map_err(|e| {
                    Error::Config(format!(
                        "invalid API key (non-ASCII or control characters): {e}"
                    ))
                })?;
            headers.insert(reqwest::header::AUTHORIZATION, header_value);
            builder = builder.default_headers(headers);
        }
        // Fail fast if the client builder fails — never fall back to an
        // unauthenticated client without timeout.
        let client = builder
            .build()
            .map_err(|e| Error::Config(format!("failed to build HTTP client: {e}")))?;
        Ok(Self {
            client,
            base_url: base_url.into(),
            model: model.into(),
            provider_name: "openai-compat".into(),
            input_cost_per_1k: 0.0,
            output_cost_per_1k: 0.0,
        })
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.provider_name = name.into();
        self
    }

    pub fn with_costs(mut self, input_per_1k: f64, output_per_1k: f64) -> Self {
        self.input_cost_per_1k = input_per_1k;
        self.output_cost_per_1k = output_per_1k;
        self
    }

    /// Create an OpenAI provider from environment variable.
    pub fn openai(model: impl Into<String>) -> Result<Self> {
        let key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| Error::Config("OPENAI_API_KEY environment variable not set".into()))?;
        Ok(Self::new("https://api.openai.com", model, Some(key))?
            .with_name("openai")
            .with_costs(0.005, 0.015))
    }

    /// Create an OpenRouter provider from environment variable.
    pub fn openrouter(model: impl Into<String>) -> Result<Self> {
        let key = std::env::var("OPENROUTER_API_KEY")
            .map_err(|_| Error::Config("OPENROUTER_API_KEY environment variable not set".into()))?;
        Ok(Self::new("https://openrouter.ai/api", model, Some(key))?.with_name("openrouter"))
    }
}

#[derive(Serialize)]
struct OpenAiRequest {
    model: String,
    messages: Vec<OpenAiMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<serde_json::Value>>,
    stream: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct OpenAiMessage {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<OpenAiToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct OpenAiToolCall {
    id: String,
    #[serde(rename = "type")]
    call_type: String,
    function: OpenAiFunction,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct OpenAiFunction {
    name: String,
    arguments: String,
}

#[derive(Deserialize, Debug)]
struct OpenAiResponse {
    choices: Vec<OpenAiChoice>,
    usage: Option<OpenAiUsage>,
    model: Option<String>,
}

#[derive(Deserialize, Debug)]
struct OpenAiChoice {
    message: Option<OpenAiMessage>,
    delta: Option<OpenAiDelta>,
    finish_reason: Option<String>,
}

#[derive(Deserialize, Debug)]
struct OpenAiDelta {
    content: Option<String>,
    tool_calls: Option<Vec<OpenAiDeltaToolCall>>,
}

#[derive(Deserialize, Debug)]
struct OpenAiDeltaToolCall {
    index: usize,
    id: Option<String>,
    function: Option<OpenAiDeltaFunction>,
}

#[derive(Deserialize, Debug)]
struct OpenAiDeltaFunction {
    name: Option<String>,
    arguments: Option<String>,
}

#[derive(Deserialize, Debug)]
struct OpenAiUsage {
    prompt_tokens: usize,
    completion_tokens: usize,
    total_tokens: usize,
}

fn build_messages(request: &CompletionRequest) -> Vec<OpenAiMessage> {
    let mut msgs = Vec::new();
    if let Some(system) = &request.system {
        msgs.push(OpenAiMessage {
            role: "system".into(),
            content: Some(system.clone()),
            tool_calls: None,
            tool_call_id: None,
        });
    }
    for msg in &request.messages {
        let role = match msg.role {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
        };
        match &msg.content {
            Content::ToolResult(tr) => {
                msgs.push(OpenAiMessage {
                    role: "tool".into(),
                    content: Some(tr.content.clone()),
                    tool_calls: None,
                    tool_call_id: Some(tr.tool_call_id.clone()),
                });
            }
            _ => {
                msgs.push(OpenAiMessage {
                    role: role.into(),
                    content: Some(msg.text().unwrap_or("").into()),
                    tool_calls: None,
                    tool_call_id: None,
                });
            }
        }
    }
    msgs
}

fn build_tools(request: &CompletionRequest) -> Option<Vec<serde_json::Value>> {
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

#[async_trait::async_trait]
impl LlmProvider for OpenAiCompatProvider {
    async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse> {
        let api_req = OpenAiRequest {
            model: self.model.clone(),
            messages: build_messages(request),
            temperature: request.temperature,
            max_tokens: request.max_tokens,
            tools: build_tools(request),
            stream: false,
        };

        let resp = self
            .client
            .post(format!("{}/v1/chat/completions", self.base_url))
            .json(&api_req)
            .send()
            .await
            .map_err(Error::Http)?;

        let resp = check_http_response(resp, &self.provider_name).await?;

        let api_resp: OpenAiResponse = resp.json().await.map_err(Error::Http)?;
        let choice = api_resp
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| Error::Provider {
                provider: self.provider_name.clone(),
                message: "no choices in response".into(),
            })?;

        let msg = choice.message.unwrap_or(OpenAiMessage {
            role: "assistant".into(),
            content: None,
            tool_calls: None,
            tool_call_id: None,
        });

        let tool_calls: Vec<ToolCall> = msg
            .tool_calls
            .unwrap_or_default()
            .into_iter()
            .map(|tc| {
                // M-25: Log a warning when tool arguments JSON is malformed
                // instead of silently converting to null.
                let args: serde_json::Value = serde_json::from_str(&tc.function.arguments)
                    .unwrap_or_else(|e| {
                        tracing::warn!(
                            tool_name = tc.function.name,
                            raw_arguments = tc.function.arguments,
                            error = %e,
                            "malformed tool arguments JSON from provider; defaulting to null"
                        );
                        serde_json::Value::Null
                    });
                ToolCall {
                    id: tc.id,
                    name: tc.function.name,
                    arguments: args,
                }
            })
            .collect();

        let finish_reason = match choice.finish_reason.as_deref() {
            Some("tool_calls") => FinishReason::ToolUse,
            Some("length") => FinishReason::MaxTokens,
            _ if !tool_calls.is_empty() => FinishReason::ToolUse,
            _ => FinishReason::Stop,
        };

        let usage = api_resp.usage.unwrap_or(OpenAiUsage {
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
        });

        Ok(CompletionResponse {
            content: msg.content,
            tool_calls,
            usage: TokenUsage {
                prompt_tokens: usage.prompt_tokens,
                completion_tokens: usage.completion_tokens,
                total_tokens: usage.total_tokens,
            },
            model: api_resp.model.unwrap_or_else(|| self.model.clone()),
            finish_reason,
        })
    }

    async fn complete_stream(&self, request: &CompletionRequest) -> Result<CompletionStream> {
        let api_req = OpenAiRequest {
            model: self.model.clone(),
            messages: build_messages(request),
            temperature: request.temperature,
            max_tokens: request.max_tokens,
            tools: build_tools(request),
            stream: true,
        };

        let resp = self
            .client
            .post(format!("{}/v1/chat/completions", self.base_url))
            .json(&api_req)
            .send()
            .await
            .map_err(Error::Http)?;

        let resp = check_http_response(resp, &self.provider_name).await?;

        let stream = resp.bytes_stream();
        let mapped = futures::StreamExt::filter_map(stream, |chunk| async {
            match chunk {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    for data in crate::sse::parse_sse_data_lines(&text) {
                        if data == "[DONE]" {
                            continue;
                        }
                        if let Ok(resp) = serde_json::from_str::<OpenAiResponse>(data) {
                            if let Some(choice) = resp.choices.into_iter().next() {
                                let delta = choice.delta.unwrap_or(OpenAiDelta {
                                    content: None,
                                    tool_calls: None,
                                });
                                let tool_deltas: Vec<ToolCallDelta> = delta
                                    .tool_calls
                                    .unwrap_or_default()
                                    .into_iter()
                                    .map(|tc| ToolCallDelta {
                                        index: tc.index,
                                        id: tc.id,
                                        name: tc.function.as_ref().and_then(|f| f.name.clone()),
                                        arguments_delta: tc.function.and_then(|f| f.arguments),
                                    })
                                    .collect();

                                let finish = choice.finish_reason.as_deref().map(|r| match r {
                                    "stop" => FinishReason::Stop,
                                    "tool_calls" => FinishReason::ToolUse,
                                    "length" => FinishReason::MaxTokens,
                                    _ => FinishReason::Stop,
                                });

                                return Some(Ok(CompletionChunk {
                                    delta_content: delta.content,
                                    delta_tool_calls: tool_deltas,
                                    finish_reason: finish,
                                }));
                            }
                        }
                    }
                    None
                }
                Err(e) => Some(Err(Error::Http(e))),
            }
        });

        Ok(Box::pin(mapped))
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            supports_streaming: true,
            supports_tools: true,
            supports_vision: true,
            max_tokens: 128_000,
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
        &self.provider_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider =
            OpenAiCompatProvider::new("https://api.openai.com", "gpt-4o", Some("test-key".into()))
                .unwrap()
                .with_name("openai");
        assert_eq!(provider.name(), "openai");
    }

    #[test]
    fn test_provider_creation_no_api_key() {
        let provider = OpenAiCompatProvider::new("http://localhost:11434", "test", None).unwrap();
        assert_eq!(provider.name(), "openai-compat");
    }

    #[test]
    fn test_invalid_api_key_header_returns_error() {
        // API keys with control characters (e.g. newlines) should return a Config
        // error instead of panicking or silently degrading to an unauthenticated client.
        let result = OpenAiCompatProvider::new(
            "https://api.openai.com",
            "gpt-4o",
            Some("key\ninjection".into()),
        );
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(
            matches!(err, Error::Config(_)),
            "expected Config error, got: {err:?}"
        );
    }

    #[test]
    fn test_build_messages() {
        let req = CompletionRequest::new(vec![Message::user("hello"), Message::assistant("hi")])
            .with_system("system prompt");
        let msgs = build_messages(&req);
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].role, "system");
    }

    #[test]
    fn test_cost_estimate() {
        let provider = OpenAiCompatProvider::new("http://localhost", "test", None)
            .unwrap()
            .with_costs(0.005, 0.015);
        let cost = provider.cost_estimate(1000, 500);
        assert!((cost.input_cost - 0.005).abs() < 0.001);
        assert!((cost.output_cost - 0.0075).abs() < 0.001);
    }
}
