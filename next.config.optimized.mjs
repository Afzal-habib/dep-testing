import { withSentryConfig } from '@sentry/nextjs'

/** @type {import('next').NextConfig} */
const nextConfig = {
  serverExternalPackages: ['mongoose', 'rate-limiter-flexible'],
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    domains: ['localhost'],
    unoptimized: true,
    formats: ['image/webp', 'image/avif'],
  },
  env: {
    MONGODB_URI: process.env.MONGODB_URI,
    NEXTAUTH_SECRET: process.env.NEXTAUTH_SECRET,
    NEXTAUTH_URL: process.env.NEXTAUTH_URL,
  },
  
  // Performance optimizations for fast navigation
  swcMinify: true,
  poweredByHeader: false,
  
  // Enable modern JavaScript features for better performance
  experimental: {
    optimizeCss: true,
    scrollRestoration: true,
    optimizePackageImports: ['lucide-react', '@radix-ui/react-icons'],
  },
  
  // Compiler optimizations
  compiler: {
    removeConsole: process.env.NODE_ENV === 'production',
  },

  webpack: (config, { isServer, dev }) => {
    // Exclude rate-limiter-flexible from client-side bundling
    if (!isServer) {
      config.externals = config.externals || [];
      config.externals.push('rate-limiter-flexible');
      
      // Add fallback for server-only packages
      config.resolve.fallback = {
        ...config.resolve.fallback,
        'rate-limiter-flexible': false,
      };
    }
    
    // Handle .d.ts files - exclude them from webpack processing
    config.module.rules.push({
      test: /\.d\.ts$/,
      use: 'ignore-loader'
    });
    
    // Exclude TypeScript definition files from rate-limiter-flexible
    config.module.rules.push({
      test: /node_modules\/rate-limiter-flexible\/.*\.d\.ts$/,
      use: 'ignore-loader'
    });

    // Performance optimizations
    if (!dev) {
      // Split chunks for better caching
      config.optimization = {
        ...config.optimization,
        splitChunks: {
          chunks: 'all',
          cacheGroups: {
            vendor: {
              test: /[\\/]node_modules[\\/]/,
              name: 'vendors',
              chunks: 'all',
            },
            common: {
              name: 'common',
              minChunks: 2,
              priority: 10,
              reuseExistingChunk: true,
            },
          },
        },
      }
    }
    
    return config;
  }
}

export default nextConfig