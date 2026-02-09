import { NextRequest, NextResponse } from "next/server"
import { genericApiRoutesMiddleware } from "@/lib/middleware/route-middleware"
import { createAPIErrorResponse } from "@/lib/utils/api-responses"
import { AuditLogger } from "@/lib/security/audit-logger"
import Settings from "@/models/Settings"
import { updateThemeSchema } from "@/lib/validations/settings"
import { executeGenericDbQuery, clearCache } from "@/lib/mongodb"
import { THEME_VARIANTS, VALID_THEME_VARIANTS } from "@/lib/constants/theme-variants"

// Re-export theme variants for backward compatibility
export { THEME_VARIANTS } from "@/lib/constants/theme-variants"

// Helper function to create consistent error responses
function createErrorResponse(message: string, status: number, details?: any) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details && { details })
  }, { status })
}

// GET /api/settings/themes - Get available theme variants and current theme (Admin only for management)
export async function GET(request: NextRequest) {
  try {
    // Apply middleware - Only admins can access theme management
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(
      request, 
      'settings', 
      'read',
      {
        enableLogging: true
      }
    )

    // Check if user is admin or super admin (hierarchy level >= 9)
    // const userHierarchyLevel = user.role?.hierarchyLevel || 0
    if (!isSuperAdmin) {
      console.log('Theme management access denied:', {
        userEmail,
        // userHierarchyLevel,
        isSuperAdmin,
        roleName: user.role?.name
      })
      return createErrorResponse("Access denied. Admin privileges required.", 403)
    }

    // Get current theme setting
    const currentThemeSetting = await Settings.findOne({ 
      key: 'theme_variant',
      category: 'appearance' 
    }).lean()

    const currentTheme = currentThemeSetting?.value || 'default'

    // Validate that the current theme exists in THEME_VARIANTS
    const validTheme = THEME_VARIANTS[currentTheme as keyof typeof THEME_VARIANTS] 
      ? currentTheme 
      : 'default'

    return NextResponse.json({
      success: true,
      data: {
        currentTheme: validTheme,
        themeConfig: THEME_VARIANTS[validTheme as keyof typeof THEME_VARIANTS],
        variants: THEME_VARIANTS,
        availableThemes: VALID_THEME_VARIANTS
      },
      message: 'Theme variants retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error in GET /api/settings/themes:', error)
    
    // Handle middleware errors (like permission denied)
    if (error instanceof Response) {
      return error
    }
    
    return createAPIErrorResponse("Internal server error", 500)
  }
}

// PUT /api/settings/themes - Update current theme variant (Admin only)
export async function PUT(request: NextRequest) {
  try {
    // Apply middleware - Only super admins can modify theme settings
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(
      request, 
      'settings', 
      'update',
      {
        rateLimitType: 'api'
      }
    )

    // Check if user is admin or super admin (hierarchy level >= 9)
    // const userHierarchyLevel = user.role?.hierarchyLevel || 0
    if (!isSuperAdmin) {
      console.log('Theme update denied:', {
        userEmail,
        // userHierarchyLevel,
        isSuperAdmin,
        roleName: user.role?.name
      })
      return createErrorResponse("Access denied. Admin privileges required.", 403)
    }

    const body = await request.json()
    console.log('🎨 Theme update request body:', body)

    // Validate the request body
    const validation = updateThemeSchema.safeParse(body)
    if (!validation.success) {
      console.error('❌ Theme validation failed:', validation.error.errors)
      return createErrorResponse('Validation failed', 400, {
        errors: validation.error.errors,
        availableThemes: VALID_THEME_VARIANTS
      })
    }

    const { theme_variant, theme } = validation.data
    const selectedTheme = theme_variant || theme
    console.log('✅ Validated theme:', selectedTheme)

    // Double check that theme exists in THEME_VARIANTS
    if (!selectedTheme || !THEME_VARIANTS[selectedTheme]) {
      console.error('❌ Theme not found in variants:', selectedTheme)
      return createErrorResponse('Invalid theme variant', 400, {
        providedTheme: selectedTheme,
        availableThemes: VALID_THEME_VARIANTS
      })
    }

    // Update or create the theme setting
    const result = await Settings.findOneAndUpdate(
      { key: 'theme_variant', category: 'appearance' },
      {
        key: 'theme_variant',
        value: selectedTheme,
        category: 'appearance',
        description: 'Current system theme variant',
        isPublic: true, // Make theme setting public for all users to read
        updatedAt: new Date()
      },
      { 
        upsert: true, 
        new: true,
        runValidators: true
      }
    )

    console.log('✅ Theme setting updated:', result)

    // Clear cache to ensure fresh data on next request
    await clearCache('public-themes')
    await clearCache('settings-cache')

    // Log the theme change for audit purposes
    await AuditLogger.logUserAction({
      userId: user.id,
      action: 'theme_update',
      resource: 'settings',
      resourceId: result._id?.toString() || 'unknown',
      details: {
        userEmail: userEmail,
        previousTheme: 'Unknown', // We could track this if needed
        newTheme: selectedTheme,
        themeConfig: THEME_VARIANTS[selectedTheme],
        ipAddress: request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown',
        userAgent: request.headers.get('user-agent') || 'unknown'
      }
    })

    return NextResponse.json({
      success: true,
      data: {
        currentTheme: selectedTheme,
        themeConfig: THEME_VARIANTS[selectedTheme],
        variants: THEME_VARIANTS,
        availableThemes: VALID_THEME_VARIANTS,
        setting: result
      },
      message: 'Theme updated successfully'
    })

  } catch (error: any) {
    console.error('❌ Error in PUT /api/settings/themes:', error)
    
    // Handle middleware errors (like permission denied)
    if (error instanceof Response) {
      return error
    }
    
    return createAPIErrorResponse("Internal server error", 500)
  }
}