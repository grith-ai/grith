// Notifications — "coming soon" placeholder.
//
// Notifications are being rebuilt as a managed, dashboard-configured feature
// (connect Telegram/Slack/etc. with no local setup — grith runs the
// integration). Until that ships, this page shows a coming-soon state instead
// of the previous local BYO channel inspector, which was read/test-only and
// read as half-built. The nav entry is kept deliberately as a roadmap signal.
// See work/84 for the build plan.

export function NotificationSettingsPage() {
  return (
    <div className="p-6 max-w-4xl">
      <h1 className="font-heading text-[22px] font-semibold tracking-[-0.02em] text-text mb-6">
        Notifications
      </h1>

      <div className="bg-surface border border-border rounded-card p-8 text-center">
        <div className="mb-4">
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-pill border border-green-border bg-green-light font-label text-[11px] font-medium text-accent-text uppercase tracking-[0.08em]">
            Coming soon
          </span>
        </div>
        <p className="font-heading text-lg font-semibold text-text mb-2">
          Approve from anywhere
        </p>
        <p className="text-sm text-text-secondary mb-6 max-w-md mx-auto">
          Get an alert — and approve or deny what your agents do — from Telegram,
          Slack, and more. Connect your account in a couple of clicks; grith runs
          the integration, with no local configuration to manage.
        </p>
        <p className="text-xs text-text-secondary">
          A Pro feature, arriving in an upcoming release.
        </p>
      </div>
    </div>
  );
}
