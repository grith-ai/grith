// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! LLM provider abstraction with pluggable backends and request routing.
//!
//! Supports Ollama, Anthropic, and any OpenAI-compatible API via a shared
//! provider trait, with configurable routing strategies.

pub mod anthropic;
pub mod error;
pub mod ollama;
pub mod openai_compat;
pub mod provider;
pub mod router;
pub mod sse;
pub mod types;

pub use error::Error;
pub use provider::LlmProvider;
pub use router::{LlmRouter, RoutingStrategy, SemanticRoute};
pub use types::*;
