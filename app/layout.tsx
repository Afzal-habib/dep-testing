import type React from "react"
import type { Metadata } from "next"
import { Inter } from "next/font/google"
import "./globals.css"
import ClientProviders from "./ClientProviders"
import { cn } from "@/lib/utils"
import { LayoutProvider } from "@/components/layout/layout-provider"
import { ThemeProvider } from "@/components/theme-provider"

// Optimize font loading for better LCP
const inter = Inter({
  subsets: ["latin"],
  weight: ['400', '500', '600', '700'],
  variable: "--font-sans",
  display: 'swap',
  preload: true,
  adjustFontFallback: true, // Reduce CLS
  fallback: ['system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Arial', 'sans-serif'], // Better fallbacks
})

export const metadata: Metadata = {
  title: "DIGI-ERA PRO CRM",
  description: "A DIGI-ERA PRO CRM application",
  generator: 'Next Js',
  icons: {
    icon: '/digi-era-logo.webp',
    shortcut: '/digi-era-logo.webp',
    apple: '/digi-era-logo.webp',
  }
}
export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
      <html lang="en" suppressHydrationWarning>
      <head>
        {/* Preload critical resources for faster navigation */}
        <link rel="preload" href="/digi-era-logo.webp" as="image" type="image/webp" />
        <link rel="dns-prefetch" href="//fonts.gstatic.com" />
        <link rel="dns-prefetch" href="//fonts.googleapis.com" />
        {/* Optimize resource loading */}
        <link rel="preconnect" href="//fonts.gstatic.com" crossOrigin="anonymous" />
        <link rel="preconnect" href="//fonts.googleapis.com" crossOrigin="anonymous" />
        {/* Performance hints */}
        <meta name="format-detection" content="telephone=no" />
        <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
      </head>
      <body className={cn(inter.variable, "font-sans antialiased")} suppressHydrationWarning>
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          <ClientProviders>
            <LayoutProvider>
              {children}
            </LayoutProvider>
          </ClientProviders>
        </ThemeProvider>
      </body>
    </html>
  )
}
