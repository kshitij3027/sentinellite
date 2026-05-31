import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        // Security-ops severity accents.
        sev: {
          critical: "#ef4444",
          high: "#f97316",
          medium: "#f59e0b",
          low: "#3b82f6",
          info: "#64748b",
        },
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
