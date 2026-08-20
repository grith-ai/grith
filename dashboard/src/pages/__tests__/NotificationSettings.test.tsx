import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { NotificationSettingsPage } from "../NotificationSettings";

describe("NotificationSettingsPage", () => {
  it("renders the coming-soon placeholder", () => {
    render(<NotificationSettingsPage />);

    expect(screen.getByText("Notifications")).toBeTruthy();
    expect(screen.getByText("Coming soon")).toBeTruthy();
    expect(
      screen.getByText(/A Pro feature, arriving in an upcoming release\./),
    ).toBeTruthy();
  });

  it("does not render the old channel inspector controls", () => {
    render(<NotificationSettingsPage />);

    // No test/refresh buttons or channel grid while notifications are parked.
    expect(screen.queryByText("Refresh")).toBeNull();
    expect(screen.queryByText("Test")).toBeNull();
  });
});
