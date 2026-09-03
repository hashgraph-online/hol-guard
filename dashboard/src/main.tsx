import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./app";
import "./styles.css";
import "./shell-navigation.css";
import "./open-guard-cloud-action.css";
import "./shell-navigation-status.css";
import "./responsive-layout.css";

const container = document.getElementById("guard-dashboard-root");

if (container === null) {
  throw new Error("Missing guard-dashboard-root");
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>
);
