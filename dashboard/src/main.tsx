import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import {
  captureDashboardTokenFromUrl,
  redeemDashboardPairCode,
} from "./lib/csrf";
import "./index.css";

// Legacy `#token=` launch fragment (sync). Kept for backward compatibility.
captureDashboardTokenFromUrl();

function mount() {
  const rootEl = document.getElementById("root");
  if (!rootEl) throw new Error("Root element not found");
  createRoot(rootEl).render(
    <StrictMode>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </StrictMode>,
  );
}

// If the launch/pair URL carries a single-use `#pair=<code>`, redeem it for the
// dashboard token BEFORE first render so the initial API calls are authorised.
// The exchange strips the code from the URL up front and is best-effort, so we
// always render regardless of outcome.
void redeemDashboardPairCode().finally(mount);
