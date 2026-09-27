/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const apiTarget = process.env.VITE_API_PROXY ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { "/api": { target: apiTarget, changeOrigin: false } } },
  preview: { proxy: { "/api": { target: apiTarget, changeOrigin: false } } },
  build: {
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (id.includes("recharts") || id.includes("d3-")) return "charts";
          if (id.includes("react-markdown") || id.includes("micromark") || id.includes("mdast")) return "markdown";
          return undefined;
        },
      },
    },
  },
  test: { environment: "jsdom", setupFiles: ["./src/test/setup.ts"], css: false, globals: true },
});
