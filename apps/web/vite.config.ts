import tailwindcss from "@tailwindcss/vite";
import vue from "@vitejs/plugin-vue";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  server: {
    proxy: {
      "/api": process.env.VERIQ_API_ORIGIN ?? "http://127.0.0.1:8000",
    },
  },
});
