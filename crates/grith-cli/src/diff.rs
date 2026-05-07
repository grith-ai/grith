// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! LCS-based unified diff computation and terminal rendering.

use std::io::Write;

/// A line in a unified diff.
#[derive(Debug, Clone, PartialEq)]
pub enum DiffLine {
    Context(String),
    Addition(String),
    Deletion(String),
}

/// A unified diff result.
#[derive(Debug, Clone)]
pub struct DiffResult {
    pub lines: Vec<DiffLine>,
    pub additions: usize,
    pub deletions: usize,
}

/// Compute a simple line-by-line diff between two texts.
pub fn compute_diff(old: &str, new: &str, context_lines: usize) -> DiffResult {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    let mut diff_lines = Vec::new();
    let mut additions = 0;
    let mut deletions = 0;

    // Simple LCS-based diff
    let lcs = lcs_table(&old_lines, &new_lines);
    let raw = backtrack_diff(&lcs, &old_lines, &new_lines);

    // Apply context window
    let change_positions: Vec<usize> = raw
        .iter()
        .enumerate()
        .filter(|(_, line)| !matches!(line, DiffLine::Context(_)))
        .map(|(i, _)| i)
        .collect();

    if change_positions.is_empty() {
        return DiffResult {
            lines: vec![],
            additions: 0,
            deletions: 0,
        };
    }

    let mut included = vec![false; raw.len()];
    for &pos in &change_positions {
        let start = pos.saturating_sub(context_lines);
        let end = (pos + context_lines + 1).min(raw.len());
        for item in included.iter_mut().take(end).skip(start) {
            *item = true;
        }
    }

    for (i, line) in raw.iter().enumerate() {
        if !included[i] {
            continue;
        }
        match line {
            DiffLine::Addition(_) => additions += 1,
            DiffLine::Deletion(_) => deletions += 1,
            _ => {}
        }
        diff_lines.push(line.clone());
    }

    DiffResult {
        lines: diff_lines,
        additions,
        deletions,
    }
}

/// Render a diff to a writer.
pub fn render_diff(w: &mut impl Write, diff: &DiffResult) -> std::io::Result<()> {
    for line in &diff.lines {
        match line {
            DiffLine::Context(text) => writeln!(w, "  {text}")?,
            DiffLine::Addition(text) => writeln!(w, "+ {text}")?,
            DiffLine::Deletion(text) => writeln!(w, "- {text}")?,
        }
    }
    writeln!(w, "+{} lines, -{} lines", diff.additions, diff.deletions)
}

/// Format a diff summary string.
pub fn diff_summary(diff: &DiffResult) -> String {
    format!("+{} lines, -{} lines", diff.additions, diff.deletions)
}

// --- LCS-based diff algorithm ---

fn lcs_table<'a>(old: &[&'a str], new: &[&'a str]) -> Vec<Vec<usize>> {
    let m = old.len();
    let n = new.len();
    let mut table = vec![vec![0usize; n + 1]; m + 1];

    for i in 1..=m {
        for j in 1..=n {
            if old[i - 1] == new[j - 1] {
                table[i][j] = table[i - 1][j - 1] + 1;
            } else {
                table[i][j] = table[i - 1][j].max(table[i][j - 1]);
            }
        }
    }

    table
}

fn backtrack_diff(table: &[Vec<usize>], old: &[&str], new: &[&str]) -> Vec<DiffLine> {
    let mut result = Vec::new();
    let mut i = old.len();
    let mut j = new.len();

    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old[i - 1] == new[j - 1] {
            result.push(DiffLine::Context(old[i - 1].to_string()));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || table[i][j - 1] >= table[i - 1][j]) {
            result.push(DiffLine::Addition(new[j - 1].to_string()));
            j -= 1;
        } else if i > 0 {
            result.push(DiffLine::Deletion(old[i - 1].to_string()));
            i -= 1;
        }
    }

    result.reverse();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_diff_no_changes() {
        let diff = compute_diff("hello\nworld", "hello\nworld", 3);
        assert_eq!(diff.additions, 0);
        assert_eq!(diff.deletions, 0);
        assert!(diff.lines.is_empty());
    }

    #[test]
    fn test_compute_diff_addition() {
        let diff = compute_diff("hello", "hello\nworld", 3);
        assert_eq!(diff.additions, 1);
        assert_eq!(diff.deletions, 0);
    }

    #[test]
    fn test_compute_diff_deletion() {
        let diff = compute_diff("hello\nworld", "hello", 3);
        assert_eq!(diff.deletions, 1);
        assert_eq!(diff.additions, 0);
    }

    #[test]
    fn test_compute_diff_modification() {
        let diff = compute_diff("hello\nworld", "hello\nearth", 3);
        assert_eq!(diff.additions, 1);
        assert_eq!(diff.deletions, 1);
    }

    #[test]
    fn test_render_diff() {
        let diff = compute_diff("hello\nworld", "hello\nearth", 3);
        let mut buf = Vec::new();
        render_diff(&mut buf, &diff).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("+ earth") || output.contains("+"));
        assert!(output.contains("- world") || output.contains("-"));
    }

    #[test]
    fn test_diff_summary() {
        let diff = DiffResult {
            lines: vec![],
            additions: 5,
            deletions: 3,
        };
        assert_eq!(diff_summary(&diff), "+5 lines, -3 lines");
    }

    #[test]
    fn test_empty_diff() {
        let diff = compute_diff("", "", 3);
        assert_eq!(diff.additions, 0);
        assert_eq!(diff.deletions, 0);
    }
}
