import { resolve } from "node:path";

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: resolve(__dirname, "../src/codex_plugin_scanner/guard/daemon/static"),
    emptyOutDir: true,
    manifest: false,
    sourcemap: false,
    rollupOptions: {
      output: {
        entryFileNames: "assets/guard-dashboard.js",
        chunkFileNames: "assets/chunks/[name].js",
        assetFileNames: (assetInfo) => {
          if (assetInfo.names.includes("style.css")) {
            return "assets/guard-dashboard.css";
          }
          return "assets/[name][extname]";
        }
      }
    }
  }
});
