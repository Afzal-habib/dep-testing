/** @type {import('next').NextConfig} */
// Note: Next.js 16 uses Turbopack by default.
// To use this webpack config, run: npm run build:webpack
const nextConfig = {
  serverExternalPackages: ['mongoose', 'rate-limiter-flexible'],
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    remotePatterns: [
      {
        protocol: 'http',
        hostname: 'localhost',
      },
      {
        protocol: 'https',
        hostname: 'localhost',
      },
    ],
    unoptimized: true,
    formats: ['image/webp', 'image/avif'],
  },
  env: {
    MONGODB_URI: process.env.MONGODB_URI,
    NEXTAUTH_SECRET: process.env.NEXTAUTH_SECRET,
    NEXTAUTH_URL: process.env.NEXTAUTH_URL,
  },
  
  // Performance optimizations for ultra-fast navigation
  poweredByHeader: false,
  reactStrictMode: true,
  
  // Enable modern JavaScript features for better performance
  experimental: {
    optimizeCss: true,
    scrollRestoration: true,
    optimizePackageImports: [
       'lucide-react',
      '@radix-ui/react-icons', 
      'recharts',
      '@tanstack/react-query',
      '@reduxjs/toolkit',
      'next-auth', // Added for better tree-shaking
      'react-redux'
    ],
    // Enable faster client-side navigation
    clientRouterFilter: true,
    // Enable aggressive code splitting
    optimisticClientCache: true,
  },
  
  // Compiler optimizations
  compiler: {
    removeConsole: process.env.NODE_ENV === 'production',
  },
  
  // Content Security Policy headers
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data: blob: https:",
              "font-src 'self' data:",
              "media-src 'self' blob: https://depllc-crm.s3.us-east-1.amazonaws.com https://*.s3.amazonaws.com https://*.s3.us-east-1.amazonaws.com https://*.s3.us-west-2.amazonaws.com https://*.s3.eu-west-1.amazonaws.com",
              "connect-src 'self' https://mifxampcsrojspuhtlpy.supabase.co wss://mifxampcsrojspuhtlpy.supabase.co https://kkdcderwckpktfxersdk.supabase.co wss://kkdcderwckpktfxersdk.supabase.co",
              "frame-src 'self'",
              "worker-src 'self' blob:"
            ].join('; ')
          }
        ]
      }
    ]
  }
}

export default nextConfig