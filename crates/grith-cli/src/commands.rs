// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! REPL command parsing with fuzzy suggestion support.

/// A parsed in-REPL command.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    Help,
    Quit,
    Digest,
    Audit { count: usize },
    Config,
    Model { name: String },
    ProxyStatus,
    ProxyTest { call_desc: String },
    Clear,
    Context,
}

/// Result of parsing user input.
#[derive(Debug, Clone, PartialEq)]
pub enum InputType {
    /// A slash command.
    Command(Command),
    /// A regular user message to send to the LLM.
    Message(String),
    /// Empty input (just pressed Enter).
    Empty,
}

/// All known command names for suggestion matching.
const KNOWN_COMMANDS: &[&str] = &[
    "/help", "/quit", "/digest", "/audit", "/config", "/model", "/proxy", "/clear", "/context",
];

/// Parse user input into a command or message.
pub fn parse_input(input: &str) -> InputType {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return InputType::Empty;
    }

    if !trimmed.starts_with('/') {
        return InputType::Message(trimmed.to_string());
    }

    let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
    let cmd = parts[0].to_lowercase();
    let args = parts.get(1).map(|s| s.trim()).unwrap_or("");

    match cmd.as_str() {
        "/help" | "/h" | "/?" => InputType::Command(Command::Help),
        "/quit" | "/q" | "/exit" => InputType::Command(Command::Quit),
        "/digest" | "/d" => InputType::Command(Command::Digest),
        "/audit" => {
            let count = args.parse().unwrap_or(10);
            InputType::Command(Command::Audit { count })
        }
        "/config" => InputType::Command(Command::Config),
        "/model" => InputType::Command(Command::Model {
            name: args.to_string(),
        }),
        "/proxy" => {
            if let Some(rest) = args.strip_prefix("test ") {
                InputType::Command(Command::ProxyTest {
                    call_desc: rest.to_string(),
                })
            } else {
                InputType::Command(Command::ProxyStatus)
            }
        }
        "/clear" => InputType::Command(Command::Clear),
        "/context" => InputType::Command(Command::Context),
        _ => InputType::Command(Command::Help), // Unknown command -> show help
    }
}

/// Find the closest matching command for suggestions.
pub fn suggest_command(input: &str) -> Option<&'static str> {
    let input_lower = input.to_lowercase();
    KNOWN_COMMANDS
        .iter()
        .filter(|cmd| cmd.starts_with(&input_lower) || levenshtein(cmd, &input_lower) <= 2)
        .copied()
        .next()
}

/// Simple Levenshtein distance for command suggestion.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());

    let mut matrix = vec![vec![0usize; n + 1]; m + 1];
    for (i, row) in matrix.iter_mut().enumerate().take(m + 1) {
        row[0] = i;
    }
    for (j, val) in matrix[0].iter_mut().enumerate().take(n + 1) {
        *val = j;
    }

    for i in 1..=m {
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }

    matrix[m][n]
}

/// Format help text for all commands.
pub fn help_text() -> String {
    let mut text = String::new();
    text.push_str("Available commands:\n");
    text.push_str("  /help, /h, /?     Show this help message\n");
    text.push_str("  /quit, /q         Exit grith\n");
    text.push_str("  /digest, /d       Open digest review UI\n");
    text.push_str("  /audit [n]        Show last n audit entries (default: 10)\n");
    text.push_str("  /config           Show current configuration\n");
    text.push_str("  /model <name>     Switch active LLM model\n");
    text.push_str("  /proxy status     Show proxy filter status\n");
    text.push_str("  /proxy test <call> Dry-run a tool call through proxy\n");
    text.push_str("  /clear            Clear terminal screen\n");
    text.push_str("  /context          Show current task context\n");
    text
}

/// Format the startup banner.
pub fn banner(version: &str, model: &str, filter_count: usize) -> String {
    format!(
        "grith v{version} | model: {model} | filters: {filter_count}\n\
         Type /help for commands, or enter a prompt.\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_help() {
        assert_eq!(parse_input("/help"), InputType::Command(Command::Help));
        assert_eq!(parse_input("/h"), InputType::Command(Command::Help));
        assert_eq!(parse_input("/?"), InputType::Command(Command::Help));
    }

    #[test]
    fn test_parse_quit() {
        assert_eq!(parse_input("/quit"), InputType::Command(Command::Quit));
        assert_eq!(parse_input("/q"), InputType::Command(Command::Quit));
        assert_eq!(parse_input("/exit"), InputType::Command(Command::Quit));
    }

    #[test]
    fn test_parse_digest() {
        assert_eq!(parse_input("/digest"), InputType::Command(Command::Digest));
        assert_eq!(parse_input("/d"), InputType::Command(Command::Digest));
    }

    #[test]
    fn test_parse_audit() {
        assert_eq!(
            parse_input("/audit"),
            InputType::Command(Command::Audit { count: 10 })
        );
        assert_eq!(
            parse_input("/audit 20"),
            InputType::Command(Command::Audit { count: 20 })
        );
    }

    #[test]
    fn test_parse_model() {
        assert_eq!(
            parse_input("/model gpt-4o"),
            InputType::Command(Command::Model {
                name: "gpt-4o".into()
            })
        );
    }

    #[test]
    fn test_parse_proxy() {
        assert_eq!(
            parse_input("/proxy"),
            InputType::Command(Command::ProxyStatus)
        );
        assert_eq!(
            parse_input("/proxy status"),
            InputType::Command(Command::ProxyStatus)
        );
        assert_eq!(
            parse_input("/proxy test read /etc/passwd"),
            InputType::Command(Command::ProxyTest {
                call_desc: "read /etc/passwd".into()
            })
        );
    }

    #[test]
    fn test_parse_message() {
        assert_eq!(
            parse_input("hello world"),
            InputType::Message("hello world".into())
        );
    }

    #[test]
    fn test_parse_empty() {
        assert_eq!(parse_input(""), InputType::Empty);
        assert_eq!(parse_input("   "), InputType::Empty);
    }

    #[test]
    fn test_parse_clear_and_context() {
        assert_eq!(parse_input("/clear"), InputType::Command(Command::Clear));
        assert_eq!(
            parse_input("/context"),
            InputType::Command(Command::Context)
        );
    }

    #[test]
    fn test_suggest_command() {
        assert_eq!(suggest_command("/hel"), Some("/help"));
        assert_eq!(suggest_command("/qui"), Some("/quit"));
        assert_eq!(suggest_command("/dig"), Some("/digest"));
    }

    #[test]
    fn test_levenshtein() {
        assert_eq!(levenshtein("help", "help"), 0);
        assert_eq!(levenshtein("help", "hele"), 1);
        assert_eq!(levenshtein("help", "hlp"), 1);
    }

    #[test]
    fn test_help_text() {
        let text = help_text();
        assert!(text.contains("/help"));
        assert!(text.contains("/quit"));
        assert!(text.contains("/digest"));
    }

    #[test]
    fn test_banner() {
        let b = banner("0.1.0", "llama3.1:8b", 6);
        assert!(b.contains("grith v0.1.0"));
        assert!(b.contains("llama3.1:8b"));
    }
}
