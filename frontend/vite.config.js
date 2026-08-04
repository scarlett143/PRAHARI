import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
  },
  preview: {
    host: "0.0.0.0",
    port: 5173,
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
