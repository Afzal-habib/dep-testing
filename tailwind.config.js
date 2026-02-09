/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class"],
  content: [
    "./pages/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./app/**/*.{ts,tsx}",
    "./src/**/*.{ts,tsx}",
    "*.{js,ts,jsx,tsx,mdx}",
  ],
  safelist: [
    // Grid column classes for dynamic filtering
    'col-span-1', 'col-span-2', 'col-span-3', 'col-span-4', 
    'col-span-5', 'col-span-6', 'col-span-7', 'col-span-8',
    'col-span-9', 'col-span-10', 'col-span-11', 'col-span-12',
    // Responsive grid column classes
    'sm:col-span-1', 'sm:col-span-2', 'sm:col-span-3', 'sm:col-span-4',
    'sm:col-span-5', 'sm:col-span-6', 'sm:col-span-7', 'sm:col-span-8',
    'sm:col-span-9', 'sm:col-span-10', 'sm:col-span-11', 'sm:col-span-12',
    'md:col-span-1', 'md:col-span-2', 'md:col-span-3', 'md:col-span-4',
    'md:col-span-5', 'md:col-span-6', 'md:col-span-7', 'md:col-span-8',
    'md:col-span-9', 'md:col-span-10', 'md:col-span-11', 'md:col-span-12',
    'lg:col-span-1', 'lg:col-span-2', 'lg:col-span-3', 'lg:col-span-4',
    'lg:col-span-5', 'lg:col-span-6', 'lg:col-span-7', 'lg:col-span-8',
    'lg:col-span-9', 'lg:col-span-10', 'lg:col-span-11', 'lg:col-span-12',
    'xl:col-span-1', 'xl:col-span-2', 'xl:col-span-3', 'xl:col-span-4',
    'xl:col-span-5', 'xl:col-span-6', 'xl:col-span-7', 'xl:col-span-8',
    'xl:col-span-9', 'xl:col-span-10', 'xl:col-span-11', 'xl:col-span-12',
  ],
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      fontFamily: {
        sans: ["var(--font-sans)"],
      },
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        sidebar: {
          DEFAULT: "hsl(var(--sidebar-background))",
          foreground: "hsl(var(--sidebar-foreground))",
          primary: "hsl(var(--sidebar-primary))",
          "primary-foreground": "hsl(var(--sidebar-primary-foreground))",
          accent: "hsl(var(--sidebar-accent))",
          "accent-foreground": "hsl(var(--sidebar-accent-foreground))",
          border: "hsl(var(--sidebar-border))",
          ring: "hsl(var(--sidebar-ring))",
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      keyframes: {
        "accordion-down": {
          from: { height: 0 },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: 0 },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
}
