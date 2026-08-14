import { useState, useEffect, useCallback } from "react";
import {
  getAnalyticsSummary,
  listPolicies,
  createPolicy,
  updatePolicy,
  deletePolicy,
} from "@/lib/api";
import type {
  AnalyticsSummaryResponse,
  Policy,
  PolicyRules,
} from "@/types/api";

interface TierInfo {
  tier: string;
  seats: number;
  max_sessions: number;
  features: Record<string, boolean>;
}

function ProBadge({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center gap-3 py-6">
      <span className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-medium rounded-pill bg-green-light border border-green-border text-accent-text">
        <span>&#128274;</span>
        Upgrade Required
      </span>
      <p className="text-xs text-text-secondary text-center max-w-xs">
        {message}
      </p>
    </div>
  );
}

function useTierInfo(): TierInfo | null {
  const [tierInfo, setTierInfo] = useState<TierInfo | null>(null);
  useEffect(() => {
    fetch("/api/tier")
      .then((res) => res.json())
      .then((data) => setTierInfo(data))
      .catch(() => {});
  }, []);
  return tierInfo;
}

// ---------------------------------------------------------------------------
// Score Distribution Bar (shared)
// ---------------------------------------------------------------------------

function ScoreDistributionBar({
  allow,
  queue,
  deny,
}: {
  allow: number;
  queue: number;
  deny: number;
}) {
  const total = allow + queue + deny;
  if (total === 0) {
    return (
      <div className="h-3 rounded-full bg-border overflow-hidden" />
    );
  }
  const pctAllow = (allow / total) * 100;
  const pctQueue = (queue / total) * 100;
  const pctDeny = (deny / total) * 100;

  return (
    <div className="h-3 rounded-full bg-border overflow-hidden flex">
      {pctAllow > 0 && (
        <div
          className="bg-green transition-all"
          style={{ width: `${pctAllow}%` }}
        />
      )}
      {pctQueue > 0 && (
        <div
          className="bg-warning transition-all"
          style={{ width: `${pctQueue}%` }}
        />
      )}
      {pctDeny > 0 && (
        <div
          className="bg-danger transition-all"
          style={{ width: `${pctDeny}%` }}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// UsageAnalytics (Pro Feature)
// ---------------------------------------------------------------------------

function AnalyticsContent() {
  const [data, setData] = useState<AnalyticsSummaryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getAnalyticsSummary()
      .then(setData)
      .catch((e) => setError(e.message));
  }, []);

  if (error) {
    return <p className="text-xs text-danger-text">{error}</p>;
  }
  if (!data) {
    return <p className="text-xs text-text-secondary">Loading analytics...</p>;
  }

  return (
    <div className="space-y-5">
      {/* Summary stat cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Total Evaluations" value={data.total_evaluations.toLocaleString()} />
        <StatCard label="Allowed" value={data.allow_count.toLocaleString()} color="text-accent-text" />
        <StatCard label="Queued" value={data.queue_count.toLocaleString()} color="text-warning-text" />
        <StatCard label="Denied" value={data.deny_count.toLocaleString()} color="text-danger-text" />
      </div>

      {/* Average score */}
      <div className="flex items-center gap-4">
        <span className="text-xs text-text-secondary">Avg Score</span>
        <span className="text-sm font-code text-text">{data.avg_score.toFixed(2)}</span>
      </div>

      {/* Decision distribution */}
      <div>
        <h3 className="font-label text-[11px] font-medium text-text-dim uppercase tracking-[0.08em] mb-2">Decision Distribution</h3>
        <ScoreDistributionBar
          allow={data.allow_count}
          queue={data.queue_count}
          deny={data.deny_count}
        />
        <div className="flex gap-6 mt-2 text-xs text-text-secondary">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-green" />
            Allow: {data.allow_count.toLocaleString()}
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-warning" />
            Queue: {data.queue_count.toLocaleString()}
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-danger" />
            Deny: {data.deny_count.toLocaleString()}
          </span>
        </div>
      </div>

      {/* Latency percentiles */}
      <div>
        <h3 className="font-label text-[11px] font-medium text-text-dim uppercase tracking-[0.08em] mb-2">Latency Percentiles</h3>
        <div className="grid grid-cols-4 gap-3">
          <StatCard label="Avg" value={`${data.latency.avg_ms.toFixed(1)}ms`} />
          <StatCard label="p50" value={`${data.latency.p50_ms.toFixed(1)}ms`} />
          <StatCard label="p95" value={`${data.latency.p95_ms.toFixed(1)}ms`} />
          <StatCard label="p99" value={`${data.latency.p99_ms.toFixed(1)}ms`} />
        </div>
      </div>

      {/* Top triggered filters */}
      {data.top_filters.length > 0 && (
        <div>
          <h3 className="font-label text-[11px] font-medium text-text-dim uppercase tracking-[0.08em] mb-2">Top Triggered Filters</h3>
          <div className="space-y-1.5">
            {data.top_filters.map((f) => (
              <div key={f.name} className="flex items-center justify-between text-xs">
                <span className="font-code text-text">{f.name}</span>
                <span className="text-text-secondary">{f.trigger_count.toLocaleString()} hits</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Time range */}
      {data.time_range.earliest && (
        <div className="text-xs text-text-secondary">
          Data from {new Date(data.time_range.earliest).toLocaleDateString()} to{" "}
          {data.time_range.latest ? new Date(data.time_range.latest).toLocaleDateString() : "now"}
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div className="bg-surface-2 rounded-btn p-3">
      <p className="text-xs text-text-secondary mb-1">{label}</p>
      <p className={`text-lg font-semibold font-code ${color ?? "text-text"}`}>
        {value}
      </p>
    </div>
  );
}

export function UsageAnalytics() {
  const tierInfo = useTierInfo();
  const allowed = tierInfo?.features?.usage_analytics ?? false;

  return (
    <div className={`bg-surface border border-border rounded-card p-5 ${allowed ? "" : "opacity-75"}`}>
      <h2 className="font-heading text-[15px] font-semibold text-text mb-1">
        Usage Analytics
      </h2>
      <p className="text-xs text-text-secondary mb-4">
        Track tool call volume, score trends, filter effectiveness, and
        agent behaviour patterns over time.
      </p>
      {!allowed ? (
        <ProBadge message="Pro feature. Upgrade to Pro for detailed usage analytics." />
      ) : (
        <AnalyticsContent />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// PolicyEditor (Enterprise Feature)
// ---------------------------------------------------------------------------

interface PolicyFormState {
  name: string;
  description: string;
  autoAllowThreshold: string;
  autoDenyThreshold: string;
  allowlistPaths: string;
  allowlistCommands: string;
  allowlistDomains: string;
}

const EMPTY_FORM: PolicyFormState = {
  name: "",
  description: "",
  autoAllowThreshold: "",
  autoDenyThreshold: "",
  allowlistPaths: "",
  allowlistCommands: "",
  allowlistDomains: "",
};

function formToRules(form: PolicyFormState): PolicyRules {
  const rules: PolicyRules = { filters: {} };
  const allow = form.autoAllowThreshold ? parseFloat(form.autoAllowThreshold) : undefined;
  const deny = form.autoDenyThreshold ? parseFloat(form.autoDenyThreshold) : undefined;
  if (allow !== undefined || deny !== undefined) {
    rules.proxy = {
      auto_allow_threshold: allow,
      auto_deny_threshold: deny,
    };
  }
  const paths = form.allowlistPaths.split("\n").map((s) => s.trim()).filter(Boolean);
  const commands = form.allowlistCommands.split("\n").map((s) => s.trim()).filter(Boolean);
  const domains = form.allowlistDomains.split("\n").map((s) => s.trim()).filter(Boolean);
  if (paths.length > 0 || commands.length > 0 || domains.length > 0) {
    rules.allowlists = { paths, commands, domains };
  }
  return rules;
}

function policyToForm(p: Policy): PolicyFormState {
  return {
    name: p.name,
    description: p.description,
    autoAllowThreshold: p.rules.proxy?.auto_allow_threshold?.toString() ?? "",
    autoDenyThreshold: p.rules.proxy?.auto_deny_threshold?.toString() ?? "",
    allowlistPaths: p.rules.allowlists?.paths.join("\n") ?? "",
    allowlistCommands: p.rules.allowlists?.commands.join("\n") ?? "",
    allowlistDomains: p.rules.allowlists?.domains.join("\n") ?? "",
  };
}

function PolicyEditorContent() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [editing, setEditing] = useState<string | null>(null); // policy name or "__new__"
  const [form, setForm] = useState<PolicyFormState>(EMPTY_FORM);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(() => {
    setLoading(true);
    listPolicies()
      .then((res) => {
        setPolicies(res.policies);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleCreate = () => {
    setEditing("__new__");
    setForm(EMPTY_FORM);
    setError(null);
  };

  const handleEdit = (p: Policy) => {
    setEditing(p.name);
    setForm(policyToForm(p));
    setError(null);
  };

  const handleCancel = () => {
    setEditing(null);
    setForm(EMPTY_FORM);
    setError(null);
  };

  const handleSave = async () => {
    setError(null);
    try {
      const rules = formToRules(form);
      if (editing === "__new__") {
        await createPolicy(form.name, form.description, rules);
      } else if (editing) {
        await updatePolicy(editing, { description: form.description, rules });
      }
      setEditing(null);
      setForm(EMPTY_FORM);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const handleDelete = async (name: string) => {
    setError(null);
    try {
      await deletePolicy(name);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const updateField = (field: keyof PolicyFormState, value: string) =>
    setForm((prev) => ({ ...prev, [field]: value }));

  if (loading && policies.length === 0) {
    return <p className="text-xs text-text-secondary">Loading policies...</p>;
  }

  return (
    <div className="space-y-4">
      {error && <p className="text-xs text-danger-text">{error}</p>}

      {/* Policy list */}
      {!editing && (
        <>
          {policies.length === 0 ? (
            <p className="text-xs text-text-secondary">No policies defined yet.</p>
          ) : (
            <div className="space-y-2">
              {policies.map((p) => (
                <div
                  key={p.name}
                  className="flex items-center justify-between bg-surface-2 rounded-btn p-3"
                >
                  <div>
                    <span className="text-sm font-code text-text">{p.name}</span>
                    <span className="ml-2 text-xs text-text-secondary">v{p.version}</span>
                    {p.description && (
                      <p className="text-xs text-text-secondary mt-0.5">{p.description}</p>
                    )}
                  </div>
                  <div className="flex gap-2">
                    <button
                      className="px-2.5 py-1 text-xs rounded-btn border border-border text-text hover:border-border-dark hover:bg-surface transition-colors"
                      onClick={() => handleEdit(p)}
                    >
                      Edit
                    </button>
                    <button
                      className="px-2.5 py-1 text-xs rounded-btn border border-danger-border text-danger-text hover:bg-danger-light transition-colors"
                      onClick={() => handleDelete(p.name)}
                    >
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
          <button
            className="px-3 py-1.5 text-xs font-medium rounded-btn bg-green-light border border-green-border text-accent-text hover:bg-green/15 transition-colors"
            onClick={handleCreate}
          >
            + New Policy
          </button>
        </>
      )}

      {/* Editor form */}
      {editing && (
        <div className="space-y-3 bg-surface-2 rounded-btn p-4">
          <h3 className="text-xs font-medium text-text">
            {editing === "__new__" ? "Create Policy" : `Edit: ${editing}`}
          </h3>

          {editing === "__new__" && (
            <FormField label="Name" placeholder="my-policy" value={form.name}
              onChange={(v) => updateField("name", v)} />
          )}
          <FormField label="Description" placeholder="Policy description" value={form.description}
            onChange={(v) => updateField("description", v)} />

          <div className="grid grid-cols-2 gap-3">
            <FormField label="Allow Threshold" placeholder="e.g. 3.0" value={form.autoAllowThreshold}
              onChange={(v) => updateField("autoAllowThreshold", v)} type="number" />
            <FormField label="Deny Threshold" placeholder="e.g. 8.0" value={form.autoDenyThreshold}
              onChange={(v) => updateField("autoDenyThreshold", v)} type="number" />
          </div>

          <FormTextarea label="Allowed Paths (one per line)" value={form.allowlistPaths}
            onChange={(v) => updateField("allowlistPaths", v)} placeholder="/tmp&#10;/home/user/safe" />
          <FormTextarea label="Allowed Commands (one per line)" value={form.allowlistCommands}
            onChange={(v) => updateField("allowlistCommands", v)} placeholder="ls&#10;cat" />
          <FormTextarea label="Allowed Domains (one per line)" value={form.allowlistDomains}
            onChange={(v) => updateField("allowlistDomains", v)} placeholder="api.example.com" />

          <div className="flex gap-2 pt-2">
            <button
              className="px-3 py-1.5 text-xs font-medium rounded-btn bg-green-light border border-green-border text-accent-text hover:bg-green/15 transition-colors"
              onClick={handleSave}
            >
              Save
            </button>
            <button
              className="px-3 py-1.5 text-xs rounded-btn border border-border text-text-secondary hover:text-text hover:border-border-dark transition-colors"
              onClick={handleCancel}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function FormField({
  label,
  placeholder,
  value,
  onChange,
  type = "text",
}: {
  label: string;
  placeholder: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
}) {
  return (
    <label className="block">
      <span className="text-xs text-text-secondary">{label}</span>
      <input
        type={type}
        className="mt-1 block w-full text-xs bg-bg border border-border rounded-btn px-2.5 py-1.5 text-text placeholder:text-text-dim focus:outline-none focus:border-green focus:shadow-glow"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  );
}

function FormTextarea({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="block">
      <span className="text-xs text-text-secondary">{label}</span>
      <textarea
        className="mt-1 block w-full text-xs bg-bg border border-border rounded-btn px-2.5 py-1.5 text-text placeholder:text-text-dim focus:outline-none focus:border-green focus:shadow-glow min-h-[60px] resize-y"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        rows={3}
      />
    </label>
  );
}

export function PolicyEditor() {
  const tierInfo = useTierInfo();
  const allowed = tierInfo?.features?.policy_editor ?? false;

  return (
    <div className={`bg-surface border border-border rounded-card p-5 ${allowed ? "" : "opacity-75"}`}>
      <h2 className="font-heading text-[15px] font-semibold text-text mb-1">
        Policy Editor
      </h2>
      <p className="text-xs text-text-secondary mb-4">
        Define and manage security policies with version control, team sharing,
        and conditional rule chains.
      </p>
      {!allowed ? (
        <ProBadge message="Pro feature. Upgrade to Pro for team policy management." />
      ) : (
        <PolicyEditorContent />
      )}
    </div>
  );
}
