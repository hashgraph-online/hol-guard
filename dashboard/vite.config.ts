import { resolve } from "node:path";

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const daemonTarget = env.GUARD_DAEMON_TARGET || "http://127.0.0.1:4781";

  return {
    plugins: [react(), tailwindcss()],
    server: {
      host: "127.0.0.1",
      port: 4174,
      strictPort: true,
      proxy: {
        "/v1": daemonTarget,
        "/healthz": daemonTarget
      }
    },
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
  };
});
