import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ScoreBreakdown } from "../ScoreBreakdown";
import type { FilterResultSummary } from "@/types/api";

describe("ScoreBreakdown", () => {
  it("shows 'No filters triggered' for empty", () => {
    render(
      <ScoreBreakdown filterResults={[]} compositeScore={0.0} />,
    );

    expect(screen.getByText("No filters triggered")).toBeTruthy();
    expect(screen.getByText("ALLOW")).toBeTruthy();
  });

  it("renders filter bars for matched filters", () => {
    const filters: FilterResultSummary[] = [
      {
        filter_name: "path_match",
        rule_id: "ssh-key",
        matched: true,
        score: 5.0,
        severity: "critical",
        message: "SSH key access",
      },
      {
        filter_name: "secret_scan",
        rule_id: "aws-key",
        matched: true,
        score: 3.0,
        severity: "medium",
        message: "AWS key detected",
      },
    ];

    render(
      <ScoreBreakdown filterResults={filters} compositeScore={8.0} />,
    );

    expect(screen.getAllByText("path_match").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("+5.0")).toBeTruthy();
    expect(screen.getAllByText("secret_scan").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("+3.0")).toBeTruthy();
  });

  it("shows ALLOW for low score", () => {
    const filters: FilterResultSummary[] = [
      {
        filter_name: "argument",
        rule_id: "check",
        matched: true,
        score: 1.0,
        severity: "low",
        message: "Minor concern",
      },
    ];

    render(
      <ScoreBreakdown filterResults={filters} compositeScore={1.0} />,
    );

    expect(screen.getByText("ALLOW")).toBeTruthy();
  });

  it("shows QUEUE for mid score", () => {
    const filters: FilterResultSummary[] = [
      {
        filter_name: "command",
        rule_id: "sudo",
        matched: true,
        score: 5.0,
        severity: "high",
        message: "Sudo detected",
      },
    ];

    render(
      <ScoreBreakdown filterResults={filters} compositeScore={5.0} />,
    );

    expect(screen.getByText("QUEUE (digest review)")).toBeTruthy();
  });

  it("shows DENY for high score", () => {
    const filters: FilterResultSummary[] = [
      {
        filter_name: "path_match",
        rule_id: "ssh-key",
        matched: true,
        score: 5.0,
        severity: "critical",
        message: "SSH key",
      },
      {
        filter_name: "secret_scan",
        rule_id: "aws-key",
        matched: true,
        score: 5.0,
        severity: "critical",
        message: "AWS key",
      },
    ];

    render(
      <ScoreBreakdown filterResults={filters} compositeScore={10.0} />,
    );

    expect(screen.getByText("DENY")).toBeTruthy();
  });

  it("renders threshold markers", () => {
    const filters: FilterResultSummary[] = [
      {
        filter_name: "path_match",
        rule_id: "ssh-key",
        matched: true,
        score: 5.0,
        severity: "critical",
        message: "SSH key",
      },
      {
        filter_name: "secret_scan",
        rule_id: "aws-key",
        matched: true,
        score: 5.0,
        severity: "critical",
        message: "AWS key",
      },
    ];

    render(
      <ScoreBreakdown filterResults={filters} compositeScore={10.0} />,
    );

    expect(screen.getByText("3.0")).toBeTruthy();
    expect(screen.getByText("8.0")).toBeTruthy();
  });
});
