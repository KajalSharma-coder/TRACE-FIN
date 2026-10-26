/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        trace: {
          ink: "#06111e",
          navy: "#0a1929",
          panel: "#102337",
          line: "#234057",
          cyan: "#35d6cc",
          muted: "#8ea6b8",
          gold: "#d7af68",
        },
      },
      boxShadow: {
        trace: "0 24px 80px rgba(0, 0, 0, 0.28)",
      },
    },
  },
  plugins: [],
}
