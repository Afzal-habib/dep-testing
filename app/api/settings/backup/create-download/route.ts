import { NextRequest, NextResponse } from "next/server"
import { genericApiRoutesMiddleware } from "@/lib/middleware/route-middleware"
import { AuditLogger } from "@/lib/security/audit-logger"
import { manualBackupSchema } from "@/lib/validations/backup"
import { executeNativeBackup, checkNativeBackupAvailable } from "@/lib/utils/native-backup"
import { readFile } from 'fs/promises'

// POST /api/settings/backup/create-download - Create backup and return for download
export async function POST(request: NextRequest) {
  try {
    // Apply middleware - Only super admins can create backups
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(
      request,
      'settings',
      'write'
    )
    
    // Additional check for super admin role
    if (!isSuperAdmin) {
      return NextResponse.json({
        success: false,
        error: "Access denied. Super admin privileges required for backup operations."
      }, { status: 403 })
    }

    // Parse and validate request body
    const body = await request.json()
    const validation = manualBackupSchema.safeParse(body)

    if (!validation.success) {
      return NextResponse.json({
        success: false,
        error: "Invalid backup configuration",
        details: validation.error.errors
      }, { status: 400 })
    }

    const backupConfig = validation.data

    // Check if native backup service is available
    const nativeStatus = await checkNativeBackupAvailable()
    if (!nativeStatus.available) {
      return NextResponse.json({
        success: false,
        error: "Database backup service is not available. " + (nativeStatus.error || "Unknown error")
      }, { status: 503 })
    }

    // Execute backup using native service with temporary path
    const tempBackupConfig = {
      ...backupConfig,
      destinationPath: './temp-backups' // Use temporary directory
    }
    
    const backupResult = await executeNativeBackup(tempBackupConfig)

    if (!backupResult.success || !backupResult.filePath) {
      await AuditLogger.logUserAction({
        userId: session.user.id,
        action: 'backup_create_download_failed',
        resource: 'backup',
        details: { userEmail, error: backupResult.error, message: `Backup creation failed: ${backupResult.error}` }
      })
      
      return NextResponse.json({
        success: false,
        error: backupResult.error || "Backup creation failed"
      }, { status: 500 })
    }

    // Read the backup file
    let fileBuffer: Buffer
    let fileName: string
    
    try {
      fileBuffer = await readFile(backupResult.filePath)
      fileName = backupResult.filePath.split(/[\\/]/).pop() || 'backup.json'
    } catch (error: any) {
      await AuditLogger.logUserAction({
        userId: session.user.id,
        action: 'backup_create_download_read_error',
        resource: 'backup',
        details: { userEmail, filePath: backupResult.filePath, error: error.message, message: `Failed to read created backup file: ${error.message}` }
      })
      
      return NextResponse.json({
        success: false,
        error: "Failed to read created backup file"
      }, { status: 500 })
    }

    // Log successful backup creation and download
    await AuditLogger.logUserAction({
      userId: session.user.id,
      action: 'backup_created_and_downloaded',
      resource: 'backup',
      details: {
        message: 'Database backup created and downloaded successfully',
        fileName,
        fileSize: fileBuffer.length,
        userEmail,
        ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
        userAgent: request.headers.get('user-agent') || 'unknown'
      }
    })

    // Clean up temporary file (optional - could keep for backup history)
    try {
      const fs = require('fs/promises')
      await fs.unlink(backupResult.filePath)
    } catch (error) {
      // Log cleanup error but don't fail the request
      console.warn('Failed to cleanup temporary backup file:', error)
    }

    // Return file as download
    const headers = new Headers()
    headers.set('Content-Type', 'application/json')
    headers.set('Content-Disposition', `attachment; filename="${fileName}"`)
    headers.set('Content-Length', fileBuffer.length.toString())
    
    return new NextResponse(new Uint8Array(fileBuffer), {
      status: 200,
      headers
    })

  } catch (error: any) {
    console.error('Backup create-download error:', error)
    
    await AuditLogger.logUserAction({
      userId: 'unknown',
      action: 'backup_create_download_error',
      resource: 'backup',
      details: { error: error.message, stack: error.stack, message: `Backup create-download failed: ${error.message}` }
    })

    return NextResponse.json({
      success: false,
      error: "Internal server error during backup creation"
    }, { status: 500 })
  }
}