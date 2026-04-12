import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./app";
import "./styles.css";

const container = document.getElementById("guard-dashboard-root");

if (container === null) {
  throw new Error("Missing guard-dashboard-root");
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>
);
