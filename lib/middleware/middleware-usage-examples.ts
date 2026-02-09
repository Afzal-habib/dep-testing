/**
 * EXAMPLES: Using the Ultra-Generic Route Middleware
 * One function to rule them all - just pass resource and action!
 */

import { type NextRequest, NextResponse } from "next/server"
import { 
  genericApiRoutesMiddleware,
  publicMiddleware,
  routeMiddleware // For advanced use cases
} from '@/lib/middleware/route-middleware'

// =====================================
// ULTRA-SIMPLE: One Function for Everything
// =====================================

// Users CRUD Operations
export async function GET_USERS(request: NextRequest) {
  try {
    // Automatically uses "api" rate limit for read operations
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'users', 'read')
    
    return NextResponse.json({ 
      success: true, 
      users: [],
      message: `Accessed by ${userEmail}`
    })
  } catch (error: any) {
    return NextResponse.json({ success: false, error: "Error" }, { status: 500 })
  }
}

export async function POST_USERS(request: NextRequest) {
  try {
    // Automatically uses "sensitive" rate limit for create operations
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'users', 'create')
    
    return NextResponse.json({ success: true, message: 'User created' })
  } catch (error: any) {
    return NextResponse.json({ success: false, error: "Error" }, { status: 500 })
  }
}

export async function PUT_USERS(request: NextRequest) {
  try {
    // Automatically uses "sensitive" rate limit for update operations
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'users', 'update')
    
    return NextResponse.json({ success: true, message: 'User updated' })
  } catch (error: any) {
    return NextResponse.json({ success: false, error: "Error" }, { status: 500 })
  }
}

export async function DELETE_USERS(request: NextRequest) {
  try {
    // Automatically uses "sensitive" rate limit for delete operations
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'users', 'delete')
    
    return NextResponse.json({ success: true, message: 'User deleted' })
  } catch (error: any) {
    return NextResponse.json({ success: false, error: "Error" }, { status: 500 })
  }
}

// System Operations
export async function POST_SYSTEM_MANAGE(request: NextRequest) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'system', 'manage')
    return NextResponse.json({ success: true, message: 'System managed' })
  } catch (error: any) {
    return NextResponse.json({ success: false, error: "Error" }, { status: 500 })
  }
}

// Authentication Operations
export async function POST_LOGIN(request: NextRequest) {
  try {
    // Automatically uses "auth" rate limit for login operations
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'auth', 'login')
    return NextResponse.json({ success: true, message: 'Logged in' })
  } catch (error: any) {
    return NextResponse.json({ success: false, error: "Error" }, { status: 500 })
  }
}

// For PUBLIC routes (no authentication)
export async function GET_PUBLIC(request: NextRequest) {
  try {
    const { session, user, userEmail } = await publicMiddleware(request)
    // session and user will be null, userEmail will be 'anonymous'
    
    return NextResponse.json({ success: true, data: 'Public data' })
  } catch (error: any) {
    return NextResponse.json({ success: false, error: "Error" }, { status: 500 })
  }
}

// =====================================
// Custom Options & Advanced Usage
// =====================================

// With custom options
export async function GET_CUSTOM(request: NextRequest) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'system', 'manage', {
      rateLimitType: 'sensitive',      // Override auto-detected rate limit
      enableLogging: true,             // Enable permission logging
      superAdminEmail: 'custom@admin.com' // Custom super admin
    })
    
    return NextResponse.json({ success: true })
  } catch (error: any) {
    return NextResponse.json({ success: false, error: "Error" }, { status: 500 })
  }
}

// Skip rate limiting (for internal APIs)
export async function GET_NO_RATE_LIMIT(request: NextRequest) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'users', 'read', {
      skipRateLimit: true  // Skip rate limiting entirely
    })
    
    return NextResponse.json({ success: true })
  } catch (error: any) {
    return NextResponse.json({ success: false, error: "Error" }, { status: 500 })
  }
}

// For very advanced cases, you can still use the low-level routeMiddleware
export async function GET_ADVANCED(request: NextRequest) {
  try {
    const { session, user, userEmail } = await routeMiddleware(request, 'custom', 'action', {
      rateLimitType: 'api',
      skipRateLimit: false,
      skipAuth: false,
      enableLogging: true
    })
    
    return NextResponse.json({ success: true })
  } catch (error: any) {
    return NextResponse.json({ success: false, error: "Error" }, { status: 500 })
  }
}

// =====================================
// COMPARISON: Before vs After
// =====================================

/*
// OLD WAY (Before) - 6+ lines of boilerplate:
export async function GET_OLD(request: NextRequest) {
  try {
    const rateLimitResponse = await applyRateLimit(request, "api")
    if (rateLimitResponse) return rateLimitResponse

    const authResult = await validateRouteAccess(request, 'users', 'read')
    if (authResult.error) return authResult.error

    const sessionUser = authResult.session!.user as any
    const userEmail = sessionUser?.email || sessionUser?.user?.email

    // Your logic here...
  } catch (error) {
    // Error handling
  }
}

// NEW ULTRA-GENERIC WAY (After) - 1 line:
export async function GET_NEW(request: NextRequest) {
  try {
    // Just pass resource and action - everything else is handled automatically!
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'users', 'read')
    
    // Your logic here...
  } catch (error) {
    // Error handling
  }
}

// Rate limits are automatically chosen based on action:
// - 'read', 'export' → 'api' rate limit
// - 'create', 'update', 'delete', 'manage' → 'sensitive' rate limit  
// - 'login', 'register', 'logout' → 'auth' rate limit
*/