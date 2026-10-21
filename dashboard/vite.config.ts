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
      minify: false,
      rollupOptions: {
        output: {
          entryFileNames: "assets/guard-dashboard.js",
          // Content-hashed chunk names keep each build's module graph apart. A tab
          // still running an older entry then fails to fetch its old chunks (and
          // reloads) instead of linking new chunks against its old shared modules.
          chunkFileNames: "assets/chunks/[name]-[hash].js",
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
