// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Health checking and reporting for daemon subsystems.

use grith_audit::AuditStorage;
use grith_digest::DigestQueue;
use std::sync::Mutex;

use super::{HealthReport, HealthStatus};

/// Check audit storage health.
///
/// Attempts to acquire the mutex lock and run a count query. A poisoned mutex
/// is treated as unhealthy rather than panicking.
pub(crate) fn check_audit_health(storage: &Mutex<AuditStorage>) -> HealthStatus {
    match storage.lock() {
        Ok(guard) => match guard.count() {
            Ok(_) => HealthStatus::Healthy,
            Err(e) => HealthStatus::Unhealthy(format!("audit query failed: {e}")),
        },
        Err(_) => HealthStatus::Unhealthy("audit storage mutex poisoned".to_string()),
    }
}

/// Check digest queue health.
///
/// Runs a pending-count query against the thread-safe digest queue.
pub(crate) fn check_digest_health(queue: &DigestQueue) -> HealthStatus {
    match queue.count_pending() {
        Ok(_) => HealthStatus::Healthy,
        Err(e) => HealthStatus::Unhealthy(format!("digest query failed: {e}")),
    }
}

/// Format health report for display.
pub fn format_health_report(report: &HealthReport) -> String {
    let mut output = String::new();
    let overall = if report.is_healthy() {
        "HEALTHY"
    } else if report.is_degraded() {
        "DEGRADED"
    } else {
        "UNHEALTHY"
    };
    output.push_str(&format!("System status: {overall}\n"));

    for sub in &report.subsystems {
        let (icon, detail) = match &sub.status {
            HealthStatus::Healthy => ("ok", String::new()),
            HealthStatus::Degraded(msg) => ("!!", format!(" ({msg})")),
            HealthStatus::Unhealthy(msg) => ("xx", format!(" ({msg})")),
        };
        output.push_str(&format!("  [{icon}] {}{detail}\n", sub.name));
    }

    output
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::SubsystemHealth;

    #[test]
    fn test_health_report_healthy() {
        let report = HealthReport {
            subsystems: vec![
                SubsystemHealth {
                    name: "audit".to_string(),
                    status: HealthStatus::Healthy,
                },
                SubsystemHealth {
                    name: "proxy".to_string(),
                    status: HealthStatus::Healthy,
                },
            ],
        };
        assert!(report.is_healthy());
        assert!(!report.is_degraded());
    }

    #[test]
    fn test_health_report_degraded() {
        let report = HealthReport {
            subsystems: vec![
                SubsystemHealth {
                    name: "audit".to_string(),
                    status: HealthStatus::Healthy,
                },
                SubsystemHealth {
                    name: "proxy".to_string(),
                    status: HealthStatus::Degraded("filter missing".to_string()),
                },
            ],
        };
        assert!(!report.is_healthy());
        assert!(report.is_degraded());
    }

    #[test]
    fn test_health_report_unhealthy() {
        let report = HealthReport {
            subsystems: vec![SubsystemHealth {
                name: "audit".to_string(),
                status: HealthStatus::Unhealthy("db locked".to_string()),
            }],
        };
        assert!(!report.is_healthy());
        assert!(!report.is_degraded());
    }

    #[test]
    fn test_format_health_report() {
        let report = HealthReport {
            subsystems: vec![
                SubsystemHealth {
                    name: "audit".to_string(),
                    status: HealthStatus::Healthy,
                },
                SubsystemHealth {
                    name: "proxy".to_string(),
                    status: HealthStatus::Degraded("not found".to_string()),
                },
            ],
        };
        let output = format_health_report(&report);
        assert!(output.contains("DEGRADED"));
        assert!(output.contains("[ok] audit"));
        assert!(output.contains("[!!] proxy"));
    }
}
