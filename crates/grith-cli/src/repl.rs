// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Interactive REPL session for the grith built-in agent.

use crate::commands::{banner, help_text, parse_input, Command, InputType};
use crate::render::Decision;
use grith_llm::{CompletionRequest, CompletionResponse, FinishReason, Message, ToolCall};
use grith_proxy::scoring::{SCORE_DENY_THRESHOLD, SCORE_QUEUE_THRESHOLD};
use uuid::Uuid;

/// REPL session state.
#[derive(Debug)]
pub struct ReplSession {
    pub session_id: String,
    pub messages: Vec<Message>,
    pub model_name: String,
    pub filter_count: usize,
    pub turn_count: usize,
    pub is_running: bool,
}

/// Configuration for the REPL.
#[derive(Debug, Clone)]
pub struct ReplConfig {
    pub version: String,
    pub model_name: String,
    pub filter_count: usize,
    pub max_tool_rounds: usize,
    pub system_prompt: Option<String>,
}

impl Default for ReplConfig {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            model_name: "llama3.1:8b".to_string(),
            filter_count: 0,
            max_tool_rounds: 20,
            system_prompt: None,
        }
    }
}

/// Result of processing a single user input line.
#[derive(Debug)]
pub enum ProcessResult {
    /// Continue the REPL loop.
    Continue,
    /// Exit the REPL.
    Exit,
    /// An LLM response was produced.
    Response(String),
    /// A tool call loop produced a final response.
    ToolResponse {
        response: String,
        tool_rounds: usize,
    },
    /// A command was executed with output.
    CommandOutput(String),
    /// The user wants to open the interactive digest review.
    DigestReview,
    /// The user wants to view recent audit entries.
    AuditList { count: usize },
    /// The user wants to test a call description through the proxy.
    ProxyTest { call_desc: String },
}

impl ReplSession {
    /// Create a new REPL session.
    pub fn new(config: &ReplConfig) -> Self {
        let mut messages = Vec::new();
        if let Some(ref system) = config.system_prompt {
            messages.push(Message::system(system));
        }

        Self {
            session_id: Uuid::new_v4().to_string(),
            messages,
            model_name: config.model_name.clone(),
            filter_count: config.filter_count,
            turn_count: 0,
            is_running: true,
        }
    }

    /// Get the startup banner.
    pub fn banner(&self, version: &str) -> String {
        banner(version, &self.model_name, self.filter_count)
    }

    /// Process a single line of user input.
    pub fn process_input(&mut self, input: &str) -> ProcessResult {
        match parse_input(input) {
            InputType::Empty => ProcessResult::Continue,
            InputType::Command(cmd) => self.handle_command(cmd),
            InputType::Message(msg) => {
                self.messages.push(Message::user(&msg));
                self.turn_count += 1;
                ProcessResult::Continue
            }
        }
    }

    /// Handle a parsed command.
    fn handle_command(&mut self, cmd: Command) -> ProcessResult {
        match cmd {
            Command::Help => ProcessResult::CommandOutput(help_text()),
            Command::Quit => {
                self.is_running = false;
                ProcessResult::Exit
            }
            Command::Clear => ProcessResult::CommandOutput("\x1B[2J\x1B[H".to_string()),
            Command::Config => ProcessResult::CommandOutput(format!(
                "Session: {}\nModel: {}\nFilters: {}\nTurns: {}\nMessages: {}\n",
                self.session_id,
                self.model_name,
                self.filter_count,
                self.turn_count,
                self.messages.len(),
            )),
            Command::Model { name } => {
                if name.is_empty() {
                    ProcessResult::CommandOutput(format!("Current model: {}\n", self.model_name))
                } else {
                    self.model_name = name;
                    ProcessResult::CommandOutput(format!(
                        "Switched display model to: {}\nWarning: this only updates the session display name. The LLM router is not updated at runtime. To change the actual model, update your config and restart.\n",
                        self.model_name
                    ))
                }
            }
            Command::Context => ProcessResult::CommandOutput(format!(
                "Session: {}\nTurn: {}\nMessage history: {} messages\n",
                self.session_id,
                self.turn_count,
                self.messages.len(),
            )),
            Command::Audit { count } => ProcessResult::AuditList { count },
            Command::Digest => ProcessResult::DigestReview,
            Command::ProxyStatus => ProcessResult::CommandOutput(format!(
                "Proxy: {} filters active\n",
                self.filter_count
            )),
            Command::ProxyTest { call_desc } => ProcessResult::ProxyTest { call_desc },
        }
    }

    /// Build a completion request from the current message history.
    pub fn build_request(&self) -> CompletionRequest {
        CompletionRequest::new(self.messages.clone())
    }

    /// Add an assistant response to the message history.
    pub fn add_assistant_response(&mut self, content: &str) {
        self.messages.push(Message::assistant(content));
    }

    /// Add a tool result to the message history.
    pub fn add_tool_result(&mut self, tool_call_id: &str, content: &str) {
        self.messages
            .push(Message::tool_result(tool_call_id, content));
    }

    /// Check if we should continue a tool call loop.
    pub fn should_continue_tool_loop(
        &self,
        response: &CompletionResponse,
        round: usize,
        max_rounds: usize,
    ) -> bool {
        round < max_rounds
            && !response.tool_calls.is_empty()
            && response.finish_reason != FinishReason::Stop
    }

    /// Reset the session (clear history, keep config).
    pub fn reset(&mut self) {
        let system_msg: Option<Message> = self
            .messages
            .iter()
            .find(|m| m.role == grith_llm::Role::System)
            .cloned();

        self.messages.clear();
        if let Some(msg) = system_msg {
            self.messages.push(msg);
        }
        self.turn_count = 0;
        self.session_id = Uuid::new_v4().to_string();
    }
}

/// Format a tool call for display.
pub fn format_tool_call(tool_call: &ToolCall) -> String {
    let args_preview = if tool_call.arguments.to_string().len() > 60 {
        format!("{}...", &tool_call.arguments.to_string()[..57])
    } else {
        tool_call.arguments.to_string()
    };
    format!("{}: {}", tool_call.name, args_preview)
}

/// Determine the decision type for a tool call based on score.
pub fn score_to_decision(score: f64) -> Decision {
    if score < SCORE_QUEUE_THRESHOLD {
        Decision::Allowed
    } else if score <= SCORE_DENY_THRESHOLD {
        Decision::Queued
    } else {
        Decision::Denied
    }
}

/// Format the REPL prompt string.
pub fn prompt_string(pending_digest: usize) -> String {
    if pending_digest > 0 {
        format!("> [{pending_digest} pending] ")
    } else {
        "> ".to_string()
    }
}

/// Exit codes for single-shot task execution.
pub mod exit_codes {
    pub const SUCCESS: i32 = 0;
    pub const ERROR: i32 = 1;
    pub const DENIED: i32 = 2;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> ReplConfig {
        ReplConfig {
            version: "0.1.0".to_string(),
            model_name: "test-model".to_string(),
            filter_count: 6,
            max_tool_rounds: 10,
            system_prompt: Some("You are a helpful assistant.".to_string()),
        }
    }

    #[test]
    fn test_session_creation() {
        let config = default_config();
        let session = ReplSession::new(&config);
        assert!(!session.session_id.is_empty());
        assert_eq!(session.model_name, "test-model");
        assert_eq!(session.filter_count, 6);
        assert_eq!(session.turn_count, 0);
        assert!(session.is_running);
        // System prompt should be first message
        assert_eq!(session.messages.len(), 1);
    }

    #[test]
    fn test_session_no_system_prompt() {
        let config = ReplConfig {
            system_prompt: None,
            ..default_config()
        };
        let session = ReplSession::new(&config);
        assert_eq!(session.messages.len(), 0);
    }

    #[test]
    fn test_process_empty_input() {
        let mut session = ReplSession::new(&default_config());
        assert!(matches!(session.process_input(""), ProcessResult::Continue));
        assert!(matches!(
            session.process_input("   "),
            ProcessResult::Continue
        ));
    }

    #[test]
    fn test_process_message() {
        let mut session = ReplSession::new(&default_config());
        let initial_len = session.messages.len();
        let result = session.process_input("hello world");
        assert!(matches!(result, ProcessResult::Continue));
        assert_eq!(session.messages.len(), initial_len + 1);
        assert_eq!(session.turn_count, 1);
    }

    #[test]
    fn test_process_help() {
        let mut session = ReplSession::new(&default_config());
        match session.process_input("/help") {
            ProcessResult::CommandOutput(text) => {
                assert!(text.contains("/help"));
                assert!(text.contains("/quit"));
            }
            _ => panic!("Expected CommandOutput"),
        }
    }

    #[test]
    fn test_process_quit() {
        let mut session = ReplSession::new(&default_config());
        assert!(matches!(
            session.process_input("/quit"),
            ProcessResult::Exit
        ));
        assert!(!session.is_running);
    }

    #[test]
    fn test_process_config() {
        let mut session = ReplSession::new(&default_config());
        match session.process_input("/config") {
            ProcessResult::CommandOutput(text) => {
                assert!(text.contains("test-model"));
                assert!(text.contains("Filters: 6"));
            }
            _ => panic!("Expected CommandOutput"),
        }
    }

    #[test]
    fn test_process_model_switch() {
        let mut session = ReplSession::new(&default_config());
        match session.process_input("/model gpt-4o") {
            ProcessResult::CommandOutput(text) => {
                assert!(text.contains("gpt-4o"));
                assert!(text.contains("Warning"));
            }
            _ => panic!("Expected CommandOutput"),
        }
        assert_eq!(session.model_name, "gpt-4o");
    }

    #[test]
    fn test_process_model_show() {
        let mut session = ReplSession::new(&default_config());
        match session.process_input("/model") {
            ProcessResult::CommandOutput(text) => {
                assert!(text.contains("test-model"));
            }
            _ => panic!("Expected CommandOutput"),
        }
    }

    #[test]
    fn test_process_context() {
        let mut session = ReplSession::new(&default_config());
        session.process_input("hello"); // add a turn
        match session.process_input("/context") {
            ProcessResult::CommandOutput(text) => {
                assert!(text.contains("Turn: 1"));
                assert!(text.contains("2 messages")); // system + user
            }
            _ => panic!("Expected CommandOutput"),
        }
    }

    #[test]
    fn test_process_clear() {
        let mut session = ReplSession::new(&default_config());
        match session.process_input("/clear") {
            ProcessResult::CommandOutput(text) => {
                assert!(text.contains("\x1B[2J")); // ANSI clear screen
            }
            _ => panic!("Expected CommandOutput"),
        }
    }

    #[test]
    fn test_build_request() {
        let mut session = ReplSession::new(&default_config());
        session.process_input("hello");
        let request = session.build_request();
        assert_eq!(request.messages.len(), 2); // system + user
    }

    #[test]
    fn test_add_assistant_response() {
        let mut session = ReplSession::new(&default_config());
        session.add_assistant_response("Hello! How can I help?");
        assert_eq!(session.messages.len(), 2); // system + assistant
    }

    #[test]
    fn test_add_tool_result() {
        let mut session = ReplSession::new(&default_config());
        session.add_tool_result("call-1", "File contents here");
        assert_eq!(session.messages.len(), 2); // system + tool_result
    }

    #[test]
    fn test_should_continue_tool_loop() {
        let session = ReplSession::new(&default_config());

        let usage = grith_llm::TokenUsage {
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
        };

        // No tool calls -> don't continue
        let response = CompletionResponse {
            content: Some("done".to_string()),
            tool_calls: vec![],
            usage: usage.clone(),
            model: "test".to_string(),
            finish_reason: FinishReason::Stop,
        };
        assert!(!session.should_continue_tool_loop(&response, 0, 10));

        // Has tool calls, not at max -> continue
        let response_with_tools = CompletionResponse {
            content: None,
            tool_calls: vec![ToolCall {
                id: "1".to_string(),
                name: "read_file".to_string(),
                arguments: serde_json::json!({"path": "/tmp/test"}),
            }],
            usage: usage.clone(),
            model: "test".to_string(),
            finish_reason: FinishReason::ToolUse,
        };
        assert!(session.should_continue_tool_loop(&response_with_tools, 0, 10));

        // At max rounds -> don't continue
        assert!(!session.should_continue_tool_loop(&response_with_tools, 10, 10));
    }

    #[test]
    fn test_reset() {
        let mut session = ReplSession::new(&default_config());
        let old_id = session.session_id.clone();
        session.process_input("hello");
        session.process_input("world");
        assert_eq!(session.turn_count, 2);

        session.reset();
        assert_eq!(session.turn_count, 0);
        assert_ne!(session.session_id, old_id);
        // System prompt should be preserved
        assert_eq!(session.messages.len(), 1);
    }

    #[test]
    fn test_reset_without_system() {
        let config = ReplConfig {
            system_prompt: None,
            ..default_config()
        };
        let mut session = ReplSession::new(&config);
        session.process_input("hello");
        session.reset();
        assert_eq!(session.messages.len(), 0);
    }

    #[test]
    fn test_banner() {
        let session = ReplSession::new(&default_config());
        let b = session.banner("0.1.0");
        assert!(b.contains("grith v0.1.0"));
        assert!(b.contains("test-model"));
        assert!(b.contains("filters: 6"));
    }

    #[test]
    fn test_format_tool_call() {
        let tc = ToolCall {
            id: "1".to_string(),
            name: "read_file".to_string(),
            arguments: serde_json::json!({"path": "/tmp/test.txt"}),
        };
        let formatted = format_tool_call(&tc);
        assert!(formatted.contains("read_file"));
        assert!(formatted.contains("/tmp/test.txt"));
    }

    #[test]
    fn test_format_tool_call_long_args() {
        let tc = ToolCall {
            id: "1".to_string(),
            name: "write_file".to_string(),
            arguments: serde_json::json!({
                "path": "/tmp/very/long/path/to/some/file/that/exceeds/the/sixty/character/limit.txt",
                "content": "lots of content here"
            }),
        };
        let formatted = format_tool_call(&tc);
        assert!(formatted.contains("..."));
    }

    #[test]
    fn test_score_to_decision() {
        assert_eq!(score_to_decision(0.5), Decision::Allowed);
        assert_eq!(score_to_decision(2.9), Decision::Allowed);
        assert_eq!(score_to_decision(3.0), Decision::Queued);
        assert_eq!(score_to_decision(5.5), Decision::Queued);
        assert_eq!(score_to_decision(8.0), Decision::Queued);
        assert_eq!(score_to_decision(8.1), Decision::Denied);
        assert_eq!(score_to_decision(10.0), Decision::Denied);
    }

    #[test]
    fn test_prompt_string() {
        assert_eq!(prompt_string(0), "> ");
        assert_eq!(prompt_string(3), "> [3 pending] ");
    }

    #[test]
    fn test_exit_codes() {
        assert_eq!(exit_codes::SUCCESS, 0);
        assert_eq!(exit_codes::ERROR, 1);
        assert_eq!(exit_codes::DENIED, 2);
    }

    #[test]
    fn test_process_proxy_status() {
        let mut session = ReplSession::new(&default_config());
        match session.process_input("/proxy") {
            ProcessResult::CommandOutput(text) => {
                assert!(text.contains("6 filters"));
            }
            _ => panic!("Expected CommandOutput"),
        }
    }

    #[test]
    fn test_process_audit() {
        let mut session = ReplSession::new(&default_config());
        match session.process_input("/audit 20") {
            ProcessResult::AuditList { count } => {
                assert_eq!(count, 20);
            }
            _ => panic!("Expected AuditList"),
        }
    }

    #[test]
    fn test_process_proxy_test() {
        let mut session = ReplSession::new(&default_config());
        let input = r#"/proxy test {"type": "FileRead", "path": "/etc/passwd"}"#;
        match session.process_input(input) {
            ProcessResult::ProxyTest { call_desc } => {
                assert!(call_desc.contains("FileRead"));
            }
            _ => panic!("Expected ProxyTest"),
        }
    }
}
