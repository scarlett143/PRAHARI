import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    // Mirrors what nginx does in the container, so `npm run dev` and a built image
    // resolve the API identically -- same-origin in both. Without this the dev server
    // would be the one place the app needed a different API base.
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: true },
      "/health": { target: "http://127.0.0.1:8000", changeOrigin: true },
      "/ws": { target: "ws://127.0.0.1:8000", ws: true },
    },
  },
  preview: {
    host: "0.0.0.0",
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: true },
      "/health": { target: "http://127.0.0.1:8000", changeOrigin: true },
      "/ws": { target: "ws://127.0.0.1:8000", ws: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    rollupOptions: {
      output: {
        // ML-KEM and the curve implementations are large and change rarely; keeping
        // them in their own chunk means an app-code deploy does not re-download them.
        manualChunks: {
          crypto: ["@noble/curves/ed25519.js", "@noble/post-quantum/ml-kem.js"],
        },
      },
    },
  },
});
