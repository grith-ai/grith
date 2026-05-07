// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Shared data types for LLM requests, responses, messages, and tool calls.

use serde::{Deserialize, Serialize};
use std::pin::Pin;

/// A request to a language model for completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionRequest {
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<ToolDefinition>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
}

/// A message in a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: Content,
}

/// Role of a message sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

/// Message content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Content {
    Text(String),
    ToolCall(ToolCall),
    ToolResult(ToolResult),
    Parts(Vec<ContentPart>),
}

/// A part of mixed content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentPart {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse(ToolCall),
    #[serde(rename = "tool_result")]
    ToolResult(ToolResult),
}

/// A tool definition (JSON Schema).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// A tool call from the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

/// A tool result to return to the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub tool_call_id: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

/// Response from a completion request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionResponse {
    pub content: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub usage: TokenUsage,
    pub model: String,
    pub finish_reason: FinishReason,
}

/// A chunk of a streaming response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionChunk {
    pub delta_content: Option<String>,
    pub delta_tool_calls: Vec<ToolCallDelta>,
    pub finish_reason: Option<FinishReason>,
}

/// Partial tool call for streaming.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallDelta {
    pub index: usize,
    pub id: Option<String>,
    pub name: Option<String>,
    pub arguments_delta: Option<String>,
}

/// Token usage statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: usize,
    pub completion_tokens: usize,
    pub total_tokens: usize,
}

/// Reason the completion finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    ToolUse,
    MaxTokens,
    Error,
}

/// Provider capabilities.
#[derive(Debug, Clone)]
pub struct ProviderCapabilities {
    pub supports_streaming: bool,
    pub supports_tools: bool,
    pub supports_vision: bool,
    pub max_tokens: usize,
}

/// Cost estimate for a completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostEstimate {
    pub input_cost: f64,
    pub output_cost: f64,
    pub total_cost: f64,
    pub currency: String,
}

/// A boxed stream of completion chunks.
pub type CompletionStream =
    Pin<Box<dyn futures::Stream<Item = crate::error::Result<CompletionChunk>> + Send>>;

impl CompletionRequest {
    pub fn new(messages: Vec<Message>) -> Self {
        Self {
            messages,
            tools: None,
            temperature: None,
            max_tokens: None,
            system: None,
        }
    }

    pub fn with_tools(mut self, tools: Vec<ToolDefinition>) -> Self {
        self.tools = Some(tools);
        self
    }

    pub fn with_system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    pub fn with_temperature(mut self, temp: f64) -> Self {
        self.temperature = Some(temp);
        self
    }

    pub fn with_max_tokens(mut self, max: usize) -> Self {
        self.max_tokens = Some(max);
        self
    }
}

impl Message {
    pub fn user(text: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: Content::Text(text.into()),
        }
    }

    pub fn assistant(text: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: Content::Text(text.into()),
        }
    }

    pub fn system(text: impl Into<String>) -> Self {
        Self {
            role: Role::System,
            content: Content::Text(text.into()),
        }
    }

    pub fn tool_result(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: Role::Tool,
            content: Content::ToolResult(ToolResult {
                tool_call_id: tool_call_id.into(),
                content: content.into(),
                is_error: None,
            }),
        }
    }

    /// Get the text content if this is a simple text message.
    pub fn text(&self) -> Option<&str> {
        match &self.content {
            Content::Text(t) => Some(t),
            _ => None,
        }
    }
}

/// Estimate token count from text (rough heuristic: ~4 chars per token).
///
/// **Limitation:** This uses `str::len()` (byte length), which counts bytes,
/// not characters. For non-ASCII text (e.g. CJK, emoji, accented characters),
/// the byte length can be 2-4x the character count, producing significant
/// overestimates. For ASCII-dominated text the heuristic is reasonable. If
/// accurate token counts are needed for routing decisions, consider using a
/// proper tokenizer (e.g. `tiktoken` for OpenAI models).
pub fn estimate_tokens(text: &str) -> usize {
    text.len() / 4 + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_user() {
        let msg = Message::user("hello");
        assert_eq!(msg.role, Role::User);
        assert_eq!(msg.text(), Some("hello"));
    }

    #[test]
    fn test_completion_request_builder() {
        let req = CompletionRequest::new(vec![Message::user("hi")])
            .with_system("You are helpful")
            .with_temperature(0.7)
            .with_max_tokens(1000);
        assert_eq!(req.system.as_deref(), Some("You are helpful"));
        assert_eq!(req.temperature, Some(0.7));
        assert_eq!(req.max_tokens, Some(1000));
    }

    #[test]
    fn test_serde_roundtrip_message() {
        let msg = Message::user("test");
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.role, Role::User);
    }

    #[test]
    fn test_estimate_tokens() {
        assert!(estimate_tokens("hello world") > 0);
        assert!(estimate_tokens("") > 0);
    }

    #[test]
    fn test_tool_definition_serde() {
        let tool = ToolDefinition {
            name: "read_file".into(),
            description: "Read a file".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                },
                "required": ["path"]
            }),
        };
        let json = serde_json::to_string(&tool).unwrap();
        let parsed: ToolDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "read_file");
    }
}
