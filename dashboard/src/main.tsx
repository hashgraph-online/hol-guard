import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./app";
import { PresentationModeProvider } from "./presentation-mode-provider";
import "./styles.css";
import "./shell-navigation.css";
import "./shell-navigation-status.css";
import "./responsive-layout.css";

const container = document.getElementById("guard-dashboard-root");

if (container === null) {
  throw new Error("Missing guard-dashboard-root");
}

createRoot(container).render(
  <StrictMode>
    <PresentationModeProvider>
      <App />
    </PresentationModeProvider>
  </StrictMode>
);
