/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        green: {
          DEFAULT: "#00a85a",
          dark: "#008548",
          light: "#e6f9ef",
          border: "#b4e6cc",
        },
        grith: {
          bg: "#ffffff",
          surface: "#f3f5f8",
          "surface-alt": "#eaecf1",
          border: "#e2e6eb",
          "border-hover": "#d0d5dc",
          text: "#0d1117",
          "text-bright": "#0d1117",
          muted: "#57606a",
          dim: "#8b949e",
        },
        accent: {
          DEFAULT: "#00a85a",
          hover: "#008548",
          light: "#e6f9ef",
        },
        status: {
          "allow-green": "#00a85a",
          "queue-amber": "#bf8700",
          "deny-red": "#d1242f",
          "allow-light": "#e6f9ef",
          "queue-light": "#fff8e1",
          "deny-light": "#fef1f2",
        },
        terminal: {
          bg: "#0d1117",
          text: "#e6edf3",
          border: "#21262d",
        },
      },
      borderRadius: {
        card: "12px",
        input: "8px",
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
};
