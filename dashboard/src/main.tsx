import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./app";
import { installStaleBuildGuard } from "./dashboard-build";
import "./tailwind-root.css";
import "./shell-navigation.css";
import "./open-guard-cloud-action.css";
import "./shell-navigation-status.css";
import "./extensions-presence.css";
import "./home-hero.css";
import "./responsive-layout.css";

const container = document.getElementById("guard-dashboard-root");

if (container === null) {
  throw new Error("Missing guard-dashboard-root");
}

installStaleBuildGuard();

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>
);
