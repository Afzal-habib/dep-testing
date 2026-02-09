import { NextRequest, NextResponse } from "next/server"
import { genericApiRoutesMiddleware } from "@/lib/middleware/route-middleware"
import { AuditLogger } from "@/lib/security/audit-logger"
import { SecurityUtils } from "@/lib/security/validation"
import { 
  manualBackupSchema, 
  restoreSchema, 
  backupListQuerySchema,
  BackupListQuery 
} from "@/lib/validations/backup"
import {
  checkNativeBackupAvailable,
  executeNativeBackup,
  executeNativeRestore,
  listNativeBackups,
  getNativeDatabaseStats
} from "@/lib/utils/native-backup"

// Helper to create consistent error responses
function createErrorResponse(message: string, status: number, details?: any) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details && { details })
  }, { status })
}

// GET /api/settings/backup - Get backup status and available backups
export async function GET(request: NextRequest) {
  try {
    // Apply middleware - Only super admins can access backup functionality
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(
      request,
      'settings',
      'read'
    )
    
    // Additional check for super admin role
    if (!isSuperAdmin) {
      return createErrorResponse("Access denied. Super admin privileges required for backup operations.", 403)
    }

    const url = new URL(request.url)
    const queryValidation = backupListQuerySchema.safeParse({
      page: url.searchParams.get('page') || '1',
      limit: url.searchParams.get('limit') || '20',
      status: url.searchParams.get('status') || 'all',
      dateFrom: url.searchParams.get('dateFrom') || undefined,
      dateTo: url.searchParams.get('dateTo') || undefined,
      sortBy: url.searchParams.get('sortBy') || 'createdAt',
      sortOrder: url.searchParams.get('sortOrder') || 'desc'
    })

    if (!queryValidation.success) {
      return createErrorResponse("Invalid query parameters", 400, {
        errors: queryValidation.error.errors
      })
    }

    const query: BackupListQuery = queryValidation.data

    // Check if native backup service is available
    const nativeStatus = await checkNativeBackupAvailable()

    // Get default backup directory from environment or use default
    const defaultBackupDir = process.env.BACKUP_DIRECTORY || './backups'

    // List available backups
    const backupsResult = await listNativeBackups(defaultBackupDir)

    let backups: Array<{
      name: string
      path: string
      size: number
      createdAt: Date
      isDirectory: boolean
      formattedSize: string
      metadata?: any
    }> = []
    if (backupsResult.success && backupsResult.backups) {
      // Process backup data
      for (const backup of backupsResult.backups) {
        const formatFileSize = (bytes: number): string => {
          const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
          if (bytes === 0) return '0 Bytes'
          const i = Math.floor(Math.log(bytes) / Math.log(1024))
          return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i]
        }
        
        backups.push({
          ...backup,
          formattedSize: formatFileSize(backup.size)
        })
      }

      // Apply filters and pagination
      if (query.dateFrom) {
        backups = backups.filter(b => b.createdAt >= query.dateFrom!)
      }
      if (query.dateTo) {
        backups = backups.filter(b => b.createdAt <= query.dateTo!)
      }

      // Sort
      backups.sort((a, b) => {
        const multiplier = query.sortOrder === 'asc' ? 1 : -1
        switch (query.sortBy) {
          case 'name':
            return a.name.localeCompare(b.name) * multiplier
          case 'size':
            return (a.size - b.size) * multiplier
          case 'createdAt':
          default:
            return (a.createdAt.getTime() - b.createdAt.getTime()) * multiplier
        }
      })

      // Paginate
      const startIndex = (query.page - 1) * query.limit
      const endIndex = startIndex + query.limit
      backups = backups.slice(startIndex, endIndex)
    }

    // Log access
    await AuditLogger.logUserAction({
      userId: session.user.id,
      action: 'backup_list_accessed',
      resource: 'backup',
      details: {
        message: 'Backup list accessed',
        backupCount: backups.length,
        userEmail,
        ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
        userAgent: request.headers.get('user-agent') || 'unknown'
      }
    })

    return NextResponse.json({
      success: true,
      data: {
        nativeBackupAvailable: nativeStatus.available,
        databaseInfo: nativeStatus.databaseInfo,
        backups: backups || [],
        pagination: {
          page: query.page,
          limit: query.limit,
          total: backupsResult.backups?.length || 0
        },
        defaultBackupDirectory: defaultBackupDir
      },
      message: 'Backup information retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error in GET /api/settings/backup:', error)
    
    // Handle middleware errors
    if (error instanceof Response) {
      return error
    }

    return createErrorResponse("Failed to retrieve backup information", 500)
  }
}

// POST /api/settings/backup - Create a new backup
export async function POST(request: NextRequest) {
  try {
    // Apply middleware - Only super admins can create backups
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(
      request,
      'settings',
      'create'
    )
    
    // Additional check for super admin role
    if (!isSuperAdmin) {
      return createErrorResponse("Access denied. Super admin privileges required for backup operations.", 403)
    }

    // Parse and validate request body
    const body = await request.json()
    
    // Check for malicious content in string fields
    const fieldsToCheck = [
      body.destinationPath,
      body.backupName,
      body.description
    ].filter(Boolean).join(' ')
    
    if (fieldsToCheck && (SecurityUtils.containsSQLInjection(fieldsToCheck) || SecurityUtils.containsXSS(fieldsToCheck))) {
      return createErrorResponse("Request contains potentially malicious content", 400)
    }

    const validation = manualBackupSchema.safeParse(body)
    if (!validation.success) {
      return createErrorResponse("Invalid backup configuration", 400, {
        errors: validation.error.errors
      })
    }

    const backupConfig = validation.data

    // Check if native backup service is available
    const nativeStatus = await checkNativeBackupAvailable()
    if (!nativeStatus.available) {
      return createErrorResponse(
        "Database backup service is not available. " + (nativeStatus.error || "Unknown error"), 
        503,
        { nativeStatus }
      )
    }

    // Execute backup using native service
    const backupResult = await executeNativeBackup(backupConfig)

    if (backupResult.success) {
      // Log successful backup
      await AuditLogger.logUserAction({
        userId: session.user.id,
        action: 'backup_created',
        resource: 'backup',
        details: {
          message: 'Database backup created successfully',
          backupPath: backupResult.filePath,
          backupName: backupConfig.backupName,
          userEmail,
          ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
          userAgent: request.headers.get('user-agent') || 'unknown'
        }
      })

      return NextResponse.json({
        success: true,
        data: {
          backupPath: backupResult.filePath,
          details: backupResult.details
        },
        message: 'Backup created successfully'
      }, { status: 201 })
    } else {
      // Log failed backup
      await AuditLogger.logUserAction({
        userId: session.user.id,
        action: 'backup_failed',
        resource: 'backup',
        details: {
          message: 'Database backup failed',
          error: backupResult.error,
          backupName: backupConfig.backupName,
          userEmail,
          ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
          userAgent: request.headers.get('user-agent') || 'unknown'
        }
      })

      return createErrorResponse(
        backupResult.error || "Backup operation failed",
        500,
        { details: backupResult.details }
      )
    }

  } catch (error: any) {
    console.error('Error in POST /api/settings/backup:', error)
    
    // Handle middleware errors
    if (error instanceof Response) {
      return error
    }

    return createErrorResponse("Failed to create backup", 500)
  }
}

// PUT /api/settings/backup - Restore from backup
export async function PUT(request: NextRequest) {
  try {
    // Apply middleware - Only super admins can restore backups
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(
      request,
      'settings',
      'update'
    )
    
    // Additional check for super admin role
    if (!isSuperAdmin) {
      return createErrorResponse("Access denied. Super admin privileges required for backup operations.", 403)
    }

    // Parse and validate request body
    const body = await request.json()
    
    // Check if this is a file upload request
    const isFileUpload = body.isFileUpload === true
    let restoreConfig: any
    
    if (isFileUpload) {
      // Handle file upload restore
      if (!body.backupContent) {
        return createErrorResponse("Backup content is required for file upload", 400)
      }
      
      // Validate backup content
      try {
        const backupData = JSON.parse(body.backupContent)
        if (!backupData.metadata || !backupData.collections) {
          return createErrorResponse("Invalid backup file structure", 400)
        }
      } catch (error) {
        return createErrorResponse("Invalid JSON backup content", 400)
      }
      
      // Create config for file upload
      restoreConfig = {
        backupContent: body.backupContent,
        targetDatabase: body.targetDatabase || undefined,
        dropExisting: body.dropExisting || false,
        dryRun: body.dryRun || false,
        isFileUpload: true
      }
    } else {
      // Handle server file restore
      // Check for malicious content in string fields
      const fieldsToCheck = [
        body.backupPath,
        body.targetDatabase
      ].filter(Boolean).join(' ')
      
      if (fieldsToCheck && (SecurityUtils.containsSQLInjection(fieldsToCheck) || SecurityUtils.containsXSS(fieldsToCheck))) {
        return createErrorResponse("Request contains potentially malicious content", 400)
      }

      const validation = restoreSchema.safeParse(body)
      if (!validation.success) {
        return createErrorResponse("Invalid restore configuration", 400, {
          errors: validation.error.errors
        })
      }

      restoreConfig = validation.data
    }

    // Check if native backup service is available
    const nativeStatus = await checkNativeBackupAvailable()
    if (!nativeStatus.available) {
      return createErrorResponse(
        "Database restore service is not available. " + (nativeStatus.error || "Unknown error"), 
        503,
        { nativeStatus }
      )
    }

    // Execute restore using native service
    const restoreResult = await executeNativeRestore(restoreConfig)

    if (restoreResult.success) {
      // Log successful restore
      await AuditLogger.logUserAction({
        userId: session.user.id,
        action: 'backup_restored',
        resource: 'backup',
        details: {
          message: 'Database restored successfully',
          backupPath: restoreConfig.backupPath,
          targetDatabase: restoreConfig.targetDatabase,
          dropExisting: restoreConfig.dropExisting,
          dryRun: restoreConfig.dryRun,
          userEmail,
          ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
          userAgent: request.headers.get('user-agent') || 'unknown'
        }
      })

      return NextResponse.json({
        success: true,
        data: {
          details: restoreResult.details
        },
        message: restoreConfig.dryRun ? 'Restore validation completed successfully' : 'Database restored successfully'
      })
    } else {
      // Log failed restore
      await AuditLogger.logUserAction({
        userId: session.user.id,
        action: 'backup_restore_failed',
        resource: 'backup',
        details: {
          message: 'Database restore failed',
          error: restoreResult.error,
          backupPath: restoreConfig.backupPath,
          userEmail,
          ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
          userAgent: request.headers.get('user-agent') || 'unknown'
        }
      })

      return createErrorResponse(
        restoreResult.error || "Restore operation failed",
        500,
        { details: restoreResult.details }
      )
    }

  } catch (error: any) {
    console.error('Error in PUT /api/settings/backup:', error)
    
    // Handle middleware errors
    if (error instanceof Response) {
      return error
    }

    return createErrorResponse("Failed to restore backup", 500)
  }
}