/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["DM Sans", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
      colors: {
        ng: {
          bg: "#0b1220",
          card: "#111827",
          border: "#1f2937",
          accent: "#22d3ee",
          danger: "#f87171",
          warn: "#fbbf24",
          muted: "#9ca3af",
        },
      },
    },
  },
  plugins: [],
};
