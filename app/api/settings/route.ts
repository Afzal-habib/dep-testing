import { NextRequest, NextResponse } from "next/server"
import { genericApiRoutesMiddleware } from "@/lib/middleware/route-middleware"
import { executeGenericDbQuery, clearCache } from "@/lib/mongodb"
import { createAPIErrorResponse } from "@/lib/utils/api-responses"
import { AuditLogger } from "@/lib/security/audit-logger"
import { SecurityUtils } from "@/lib/security/validation"
import Settings from "@/models/Settings"
import { 
  updateSettingSchema, 
  createSettingSchema, 
  batchCreateSettingsSchema,
  settingsQuerySchema,
  validateSettingValue
} from "@/lib/validations/settings"



// Helper to create consistent error responses
function createErrorResponse(message: string, status: number, details?: any) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details && { details })
  }, { status })
}

// GET /api/settings - Get system settings
export async function GET(request: NextRequest) {
  try {
    // Apply middleware - Only super admins and admins can access settings
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(
      request, 
      'settings', 
      'read',
      {
        enableLogging: true
      }
    )
    console.log("super admin 39:", isSuperAdmin);
    // Check if user is admin or super admin (hierarchy level >= 9)
    // const userHierarchyLevel = user.role?.hierarchyLevel || 0
    // if (!isSuperAdmin && userHierarchyLevel < 9) {
    if (!isSuperAdmin) {
      console.log('Settings access denied:', {
        userEmail,
        // userHierarchyLevel,
        isSuperAdmin,
        roleName: user.role?.name
      })
      return createErrorResponse("Access denied. Admin privileges required.", 403)
    }

    const { searchParams } = new URL(request.url)
    const queryParams = Object.fromEntries(searchParams.entries())

    // Validate query parameters
    const validation = settingsQuerySchema.safeParse(queryParams)
    if (!validation.success) {
      return createErrorResponse("Invalid query parameters", 400, {
        errors: validation.error.errors
      })
    }

    const { category, includePrivate } = validation.data

    // Build query
    const filter: any = {}
    if (category) {
      filter.category = category
    }

    // Only include public settings for non-super admins
    if (!isSuperAdmin && !includePrivate) {
      filter.isPublic = true
    }

    const settings = await executeGenericDbQuery(async () => {
      return await Settings.find(filter)
        .select('key value description category isPublic metadata')
        .sort({ category: 1, key: 1 })
        .lean()
        .exec()
    }, `settings-${JSON.stringify(filter)}`, 300000) // 5-minute cache

    // Log successful access
    await AuditLogger.logUserAction({
      userId: session.user.id,
      action: 'settings_read',
      resource: 'settings',
      details: {
        message: 'Settings accessed',
        category: category || 'all',
        settingsCount: settings.length,
        userEmail,
        ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
        userAgent: request.headers.get('user-agent') || 'unknown'
      }
    })

    return NextResponse.json({
      success: true,
      data: settings,
      message: 'Settings retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error in GET /api/settings:', error)
    
    // Handle middleware errors (like permission denied)
    if (error instanceof Response) {
      return error
    }
    
    return createAPIErrorResponse("Internal server error", 500)
  }
}

// PUT /api/settings - Update system settings
export async function PUT(request: NextRequest) {
  try {
    // Apply middleware - Only super admins can modify settings
    // Use 'api' rate limit for admin settings (more lenient than 'sensitive')
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
      // if (!isSuperAdmin && userHierarchyLevel < 9) {
    if (!isSuperAdmin) {
      console.log('Settings update denied:', {
        userEmail,
        // userHierarchyLevel,
        isSuperAdmin,
        roleName: user.role?.name
      })
      return createErrorResponse("Access denied. Admin privileges required.", 403)
    }

    const body = await request.json()
    
    // Validate request body
    const validation = updateSettingSchema.safeParse(body)
    if (!validation.success) {
      return createErrorResponse("Validation failed", 400, {
        errors: validation.error.errors
      })
    }

    const validatedData = validation.data

    // Additional validation for specific setting keys
    const valueValidation = validateSettingValue(validatedData.key, validatedData.value)
    if (!valueValidation.success) {
      return createErrorResponse(`Invalid value for setting '${validatedData.key}'`, 400, {
        errors: valueValidation.error.errors
      })
    }

    // Security checks
    const dataString = JSON.stringify(validatedData)
    if (SecurityUtils.containsSQLInjection(dataString) || 
        SecurityUtils.containsXSS(dataString)) {
      await AuditLogger.log({
        userId: session.user.id,
        action: 'malicious_input_attempt',
        resource: 'settings',
        success: false,
        details: {
          message: 'Potential malicious input detected in settings update',
          userEmail,
          inputData: dataString.substring(0, 200),
          ipAddress: request.headers.get('x-forwarded-for') || 'unknown'
        }
      })
      return createErrorResponse("Invalid input detected", 400)
    }

    const { key, value, description, category, isPublic } = validatedData

    // Update or create setting with automatic connection management
    const updatedSetting = await executeGenericDbQuery(async () => {
      return await Settings.findOneAndUpdate(
        { key },
        {
          key,
          value,
          description: description || '',
          category: category || 'general',
          isPublic: isPublic || false,
          'metadata.updatedBy': userEmail,
          'metadata.updatedAt': new Date()
        },
        {
          new: true,
          upsert: true,
          runValidators: true,
          setDefaultsOnInsert: true
        }
      )
    })

    // Clear settings cache
    clearCache('settings')

    // Set createdBy for new documents
    if (!updatedSetting.metadata?.createdBy) {
      updatedSetting.metadata = {
        ...updatedSetting.metadata,
        createdBy: userEmail
      }
      await updatedSetting.save()
    }

    // Log setting update
    await AuditLogger.logUserAction({
      userId: session.user.id,
      action: 'settings_update',
      resource: 'settings',
      details: {
        message: `Setting '${key}' updated`,
        settingKey: key,
        settingCategory: category || 'general',
        previousValue: 'hidden', // Don't log actual values for security
        userEmail,
        ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
        userAgent: request.headers.get('user-agent') || 'unknown'
      }
    })

    return NextResponse.json({
      success: true,
      data: updatedSetting,
      message: 'Setting updated successfully'
    })

  } catch (error: any) {
    console.error('Error in PUT /api/settings:', error)
    
    // Handle middleware errors
    if (error instanceof Response) {
      return error
    }

    // Handle MongoDB duplicate key error
    if (error.code === 11000) {
      return createErrorResponse("Setting key already exists", 409)
    }

    return createAPIErrorResponse("Failed to update setting", 500)
  }
}

// POST /api/settings - Create new setting (batch create)
export async function POST(request: NextRequest) {
  try {
    // Apply middleware - Only super admins can create settings
    // Use 'api' rate limit for admin settings (more lenient than 'sensitive')
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(
      request, 
      'settings', 
      'create',
      {
        rateLimitType: 'api'
      }
    )

    // Check if user is admin or super admin (hierarchy level >= 9)
    // const userHierarchyLevel = user.role?.hierarchyLevel || 0
    if (!isSuperAdmin) {
      return createErrorResponse("Access denied. Admin privileges required.", 403)
    }

    const body = await request.json()
    
    // Support both single setting and batch creation
    const settings = Array.isArray(body) ? body : [body]

    // Validate all settings
    for (const setting of settings) {
      if (!setting.key || setting.value === undefined) {
        return createErrorResponse("Each setting must have a key and value", 400)
      }
    }


    const createdSettings = []
    
    for (const settingData of settings) {
      const { key, value, description, category, isPublic } = settingData
      
      const sanitizedKey = SecurityUtils.sanitizeString(key)
      const sanitizedCategory = category ? SecurityUtils.sanitizeString(category) : 'general'

      try {
        const newSetting = new Settings({
          key: sanitizedKey,
          value: value,
          description: description || '',
          category: sanitizedCategory,
          isPublic: isPublic || false,
          metadata: {
            createdBy: userEmail,
            updatedBy: userEmail
          }
        })

        await newSetting.save()
        createdSettings.push(newSetting)
      } catch (error: any) {
        if (error.code === 11000) {
          // Skip duplicate keys
          console.warn(`Setting '${sanitizedKey}' already exists, skipping`)
          continue
        }
        throw error
      }
    }

    // Log batch creation
    await AuditLogger.logUserAction({
      userId: session.user.id,
      action: 'settings_create_batch',
      resource: 'settings',
      details: {
        message: `Batch created ${createdSettings.length} settings`,
        settingsCount: createdSettings.length,
        userEmail,
        ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
        userAgent: request.headers.get('user-agent') || 'unknown'
      }
    })

    return NextResponse.json({
      success: true,
      data: createdSettings,
      message: `${createdSettings.length} settings created successfully`
    }, { status: 201 })

  } catch (error: any) {
    console.error('Error in POST /api/settings:', error)
    
    if (error instanceof Response) {
      return error
    }
    
    return createAPIErrorResponse("Failed to create settings", 500)
  }
}