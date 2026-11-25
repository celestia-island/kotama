import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import vueJsx from "@vitejs/plugin-vue-jsx";

export default defineConfig({
  base: "./",
  plugins: [vue(), vueJsx()],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { target: "chrome105", minify: false },
});
