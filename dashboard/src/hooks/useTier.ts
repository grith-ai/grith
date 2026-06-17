import { useEffect, useState } from "react";
import { getTier } from "@/lib/api";
import type { TierResponse } from "@/types/api";

export interface TierState {
  tier: TierResponse | null;
  /** Lowercased tier key ("community" | "pro" | "enterprise"). */
  tierKey: string;
  /** True for any paid tier (pro or enterprise). */
  isPaid: boolean;
  /** Convenience: is a named feature enabled for this tier? */
  has: (feature: string) => boolean;
  /** Where the "Upgrade" CTAs should point. */
  billingUrl: string;
}

const DEFAULT_BILLING_URL = "/billing";

/**
 * Shared read of the current license tier. Falls back to a Community-shaped
 * state when the tier endpoint is unreachable or unauthorised, so upgrade
 * surfaces still render (fail-open toward showing the upsell, never toward
 * unlocking a gated feature).
 */
export function useTier(): TierState {
  const [tier, setTier] = useState<TierResponse | null>(null);

  useEffect(() => {
    let cancelled = false;
    getTier()
      .then((t) => {
        if (!cancelled) setTier(t);
      })
      .catch(() => {
        /* leave null — treated as Community below */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const tierKey = (tier?.tier ?? "community").toLowerCase();
  const isPaid = tierKey === "pro" || tierKey === "enterprise";

  return {
    tier,
    tierKey,
    isPaid,
    has: (feature: string) => tier?.features?.[feature] ?? false,
    billingUrl: tier?.billing_portal_url ?? DEFAULT_BILLING_URL,
  };
}
