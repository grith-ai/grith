// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Core LLM provider trait that all backends implement.

use crate::error::Result;
use crate::types::{
    CompletionRequest, CompletionResponse, CompletionStream, CostEstimate, ProviderCapabilities,
};

/// Trait for LLM providers. All providers implement this for pluggable backends.
#[async_trait::async_trait]
pub trait LlmProvider: Send + Sync {
    /// Send a completion request and get a full response.
    async fn complete(&self, request: &CompletionRequest) -> Result<CompletionResponse>;

    /// Send a completion request and get a streaming response.
    async fn complete_stream(&self, request: &CompletionRequest) -> Result<CompletionStream>;

    /// Get the capabilities of this provider.
    fn capabilities(&self) -> ProviderCapabilities;

    /// Estimate cost for the given token counts.
    fn cost_estimate(&self, input_tokens: usize, output_tokens: usize) -> CostEstimate;

    /// Name of this provider.
    fn name(&self) -> &str;
}
