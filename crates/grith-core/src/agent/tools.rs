// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! LLM tool definitions for the built-in grith agent.
//!
//! Defines the JSON schemas for file, shell, HTTP, and directory operations
//! that the agent can invoke during a task.

/// Return the tool definitions that the grith agent exposes to the LLM.
pub fn agent_tool_definitions() -> Vec<grith_llm::ToolDefinition> {
    vec![
        grith_llm::ToolDefinition {
            name: "read_file".into(),
            description: "Read the contents of a file at the given path.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute or relative path to the file to read"
                    }
                },
                "required": ["path"]
            }),
        },
        grith_llm::ToolDefinition {
            name: "write_file".into(),
            description: "Write content to a file, creating it if necessary or overwriting.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute or relative path to the file to write"
                    },
                    "content": {
                        "type": "string",
                        "description": "The content to write to the file"
                    }
                },
                "required": ["path", "content"]
            }),
        },
        grith_llm::ToolDefinition {
            name: "list_directory".into(),
            description: "List the contents of a directory.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the directory to list"
                    }
                },
                "required": ["path"]
            }),
        },
        grith_llm::ToolDefinition {
            name: "shell_exec".into(),
            description: "Execute a shell command and return its output.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The command to execute"
                    },
                    "args": {
                        "oneOf": [
                            {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            {
                                "type": "string"
                            }
                        ],
                        "description": "Arguments to pass to the command. Prefer array of strings; string is accepted for compatibility."
                    }
                },
                "required": ["command"]
            }),
        },
        grith_llm::ToolDefinition {
            name: "http_request".into(),
            description: "Make an HTTP request to a URL.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "description": "HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD)"
                    },
                    "url": {
                        "type": "string",
                        "description": "The URL to request"
                    },
                    "body": {
                        "type": "string",
                        "description": "Optional request body, sent for POST/PUT/PATCH."
                    }
                },
                "required": ["url"]
            }),
        },
        grith_llm::ToolDefinition {
            name: "append_file".into(),
            description: "Append content to the end of a file, creating it if it does not exist.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file to append to"
                    },
                    "content": {
                        "type": "string",
                        "description": "The content to append"
                    }
                },
                "required": ["path", "content"]
            }),
        },
        grith_llm::ToolDefinition {
            name: "delete_file".into(),
            description: "Delete a file at the given path.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file to delete"
                    }
                },
                "required": ["path"]
            }),
        },
        grith_llm::ToolDefinition {
            name: "rename_file".into(),
            description: "Rename or move a file from one path to another.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "old_path": {
                        "type": "string",
                        "description": "Current path of the file"
                    },
                    "new_path": {
                        "type": "string",
                        "description": "New path for the file"
                    }
                },
                "required": ["old_path", "new_path"]
            }),
        },
        grith_llm::ToolDefinition {
            name: "chmod".into(),
            description: "Change file permissions (Unix only). Provide mode as an integer using the decimal form of octal (e.g. 493 for 0o755).".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file"
                    },
                    "mode": {
                        "type": "integer",
                        "description": "Permission mode as a decimal representation of octal (e.g. 493 for 0o755)"
                    }
                },
                "required": ["path", "mode"]
            }),
        },
        grith_llm::ToolDefinition {
            name: "create_directory".into(),
            description: "Create a directory and any necessary parent directories.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path of the directory to create"
                    }
                },
                "required": ["path"]
            }),
        },
        grith_llm::ToolDefinition {
            name: "net_connect".into(),
            description: "Test a TCP connection to an address and port.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Hostname or IP address"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port number"
                    }
                },
                "required": ["address", "port"]
            }),
        },
        grith_llm::ToolDefinition {
            name: "net_listen".into(),
            description: "Bind a TCP listener on an address and port to test availability.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Address to bind (e.g. 0.0.0.0 or 127.0.0.1)"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port number"
                    }
                },
                "required": ["address", "port"]
            }),
        },
        grith_llm::ToolDefinition {
            name: "spawn_process".into(),
            description: "Spawn a process and return its output. Similar to shell_exec but maps to ProcessSpawn for proxy evaluation.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The command to execute"
                    },
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Arguments to pass to the command"
                    }
                },
                "required": ["command"]
            }),
        },
    ]
}
