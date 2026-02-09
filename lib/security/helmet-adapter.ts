import { NextRequest, NextResponse } from "next/server"

// Security headers utility (equivalent to Helmet for Next.js)
export function applySecurityHeaders(response: NextResponse): NextResponse {
  // Basic security headers
  response.headers.set('X-Content-Type-Options', 'nosniff')
  response.headers.set('X-Frame-Options', 'DENY')
  response.headers.set('X-XSS-Protection', '1; mode=block')
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  // Allow microphone for voice messages feature, camera for future video features
  response.headers.set('Permissions-Policy', 'camera=(self), microphone=(self), geolocation=(), payment=()')

  // HTTPS enforcement (only in production)
  if (process.env.NODE_ENV === 'production') {
    response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')
  }

  // Content Security Policy
  const csp = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-eval' 'unsafe-inline'", // Needed for Next.js in dev
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com", // Allow Google Fonts
    "img-src 'self' data: blob: https:",
    "font-src 'self' data: https://fonts.gstatic.com", // Allow Google Fonts
    "media-src 'self' blob: https://depllc-crm.s3.us-east-1.amazonaws.com https://*.s3.*.amazonaws.com", // Allow blob: URLs and S3 for audio/video playback (voice messages)
    "connect-src 'self' https://mifxampcsrojspuhtlpy.supabase.co wss://mifxampcsrojspuhtlpy.supabase.co https://kkdcderwckpktfxersdk.supabase.co wss://kkdcderwckpktfxersdk.supabase.co", // Allow Supabase connections
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "worker-src 'self' blob:" // Allow web workers for real-time features
  ].join('; ')

  response.headers.set('Content-Security-Policy', csp)

  // Remove potentially revealing headers
  response.headers.delete('x-powered-by')
  response.headers.delete('server')

  return response
}

// Enhanced security middleware for API routes
export function createSecurityMiddleware() {
  return {
    // Apply all security measures to a request
    secure: async (req: NextRequest, handler: () => Promise<NextResponse>) => {
      try {
        // Execute the main handler
        const response = await handler()

        // Apply security headers
        return applySecurityHeaders(response)
      } catch (error) {
        // Create error response with security headers
        const errorResponse = NextResponse.json({
          success: false,
          error: "Internal server error"
        }, { status: 500 })

        return applySecurityHeaders(errorResponse)
      }
    },

    // Check for common attack patterns in request
    detectMaliciousPatterns: (req: NextRequest): { isMalicious: boolean; reason?: string } => {
      const userAgent = req.headers.get('user-agent') || ''
      const url = req.url

      // Check for common bot/scanner user agents
      const suspiciousAgents = [
        /sqlmap/i,
        /nikto/i,
        /w3af/i,
        /dirbuster/i,
        /nessus/i,
        /openvas/i,
        /burpsuite/i,
        /<script/i,
        /eval\(/i,
        /javascript:/i
      ]

      for (const pattern of suspiciousAgents) {
        if (pattern.test(userAgent)) {
          return { isMalicious: true, reason: 'Suspicious user agent' }
        }
      }

      // Check for common attack patterns in URL
      const attackPatterns = [
        /\.\.\//,  // Path traversal
        /<script/i, // XSS
        /union.*select/i, // SQL injection
        /exec\(/i, // Command injection
        /eval\(/i, // Code injection
        /%00/, // Null byte injection
        /javascript:/i, // JavaScript protocol
        /data:.*base64/i, // Data URI with base64
      ]

      for (const pattern of attackPatterns) {
        if (pattern.test(url)) {
          return { isMalicious: true, reason: 'Malicious URL pattern detected' }
        }
      }

      return { isMalicious: false }
    },

    // Validate request size and structure
    validateRequest: (req: NextRequest): { isValid: boolean; reason?: string } => {
      // Check Content-Length header for large payloads
      const contentLength = parseInt(req.headers.get('content-length') || '0')
      const maxSize = 10 * 1024 * 1024 // 10MB limit

      if (contentLength > maxSize) {
        return { isValid: false, reason: 'Request payload too large' }
      }

      // Check for required headers in POST/PUT requests
      if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
        const contentType = req.headers.get('content-type')
        if (!contentType) {
          return { isValid: false, reason: 'Missing Content-Type header' }
        }

        // Validate JSON content type for API routes
        if (req.url.includes('/api/') && !contentType.includes('application/json')) {
          return { isValid: false, reason: 'Invalid Content-Type for API request' }
        }
      }

      return { isValid: true }
    }
  }
}

// IP address validation and geolocation checking
export function validateClientIP(req: NextRequest): {
  ip: string
  isValid: boolean
  isSuspicious: boolean
  reason?: string
} {
  const ip = (
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-real-ip") ||
    req.headers.get("cf-connecting-ip") ||
    "127.0.0.1"
  )

  // Check for valid IP format
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/

  const isValidFormat = ipv4Regex.test(ip) || ipv6Regex.test(ip) || ip === "127.0.0.1"

  // Check for suspicious IP ranges (basic check)
  const suspiciousRanges = [
    /^10\./, // Private networks (suspicious if claiming to be external)
    /^192\.168\./, // Private networks
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private networks
    /^0\./, // Invalid range
    /^255\./, // Invalid range
  ]

  let isSuspicious = false
  let reason = undefined

  // Only check private ranges if not localhost
  if (ip !== "127.0.0.1") {
    for (const range of suspiciousRanges) {
      if (range.test(ip)) {
        isSuspicious = true
        reason = "Private IP range detected from external request"
        break
      }
    }
  }

  return {
    ip,
    isValid: isValidFormat,
    isSuspicious,
    reason
  }
}

// Security event types for monitoring
export enum SecurityEventType {
  MALICIOUS_REQUEST = "MALICIOUS_REQUEST",
  RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED",
  INVALID_REQUEST = "INVALID_REQUEST",
  SUSPICIOUS_IP = "SUSPICIOUS_IP",
  AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE",
  AUTHORIZATION_FAILURE = "AUTHORIZATION_FAILURE",
  DATA_BREACH_ATTEMPT = "DATA_BREACH_ATTEMPT",
}

// Security monitoring utility
export function logSecurityEvent(
  type: SecurityEventType,
  details: {
    ip?: string
    userAgent?: string
    url?: string
    userId?: string
    severity: 'low' | 'medium' | 'high' | 'critical'
    message: string
    additionalData?: Record<string, any>
  }
) {
  const event = {
    timestamp: new Date().toISOString(),
    type,
    ...details
  }

  // In development, log to console
  if (process.env.NODE_ENV === 'development') {
    console.warn('🚨 Security Event:', event)
  }

  // In production, you would send this to a security monitoring service
  // Examples: Datadog, Splunk, ELK Stack, etc.

  // For now, we'll just return the event for potential database logging

  return event
}

// Helper to create secure error responses
export function createSecureErrorResponse(
  message: string,
  statusCode: number = 400,
  publicDetails?: Record<string, any>
): NextResponse {
  const response = NextResponse.json({
    success: false,
    error: message,
    ...(publicDetails && { details: publicDetails }),
    timestamp: new Date().toISOString()
  }, { status: statusCode })

  return applySecurityHeaders(response)
}

// CORS configuration utility
export function applyCorsHeaders(
  response: NextResponse,
  origin?: string
): NextResponse {
  const allowedOrigins = [
    'http://localhost:3000',
    'https://digi-era-pro.vercel.app',
    // Add your production domains here
  ]

  if (origin && allowedOrigins.includes(origin)) {
    response.headers.set('Access-Control-Allow-Origin', origin)
  } else {
    response.headers.set('Access-Control-Allow-Origin', 'null')
  }

  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  response.headers.set('Access-Control-Max-Age', '86400')

  return response
}