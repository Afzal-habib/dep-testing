import { NextRequest, NextResponse } from "next/server"
import { genericApiRoutesMiddleware } from "@/lib/middleware/route-middleware"
import { AuditLogger } from "@/lib/security/audit-logger"
import { readFile } from 'fs/promises'
import path from 'path'

// GET /api/settings/backup/download - Download backup file
export async function GET(request: NextRequest) {
  try {
    // Apply middleware - Only super admins can download backups
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(
      request,
      'settings',
      'read'
    )
    
    // Additional check for super admin role
    if (!isSuperAdmin) {
      return NextResponse.json({
        success: false,
        error: "Access denied. Super admin privileges required for backup downloads."
      }, { status: 403 })
    }

    const url = new URL(request.url)
    const backupPath = url.searchParams.get('path')
    
    if (!backupPath) {
      return NextResponse.json({
        success: false,
        error: "Backup path is required"
      }, { status: 400 })
    }

    // Security: Ensure the path is within allowed backup directories
    const resolvedPath = path.resolve(backupPath)
    const allowedPaths = [
      path.resolve('./backups'),
      path.resolve('C:/backup/mongodb'),
      path.resolve('/home/backup/mongodb')
    ]
    
    const isAllowedPath = allowedPaths.some(allowedPath => 
      resolvedPath.startsWith(allowedPath)
    )
    
    if (!isAllowedPath) {
      await AuditLogger.logUserAction({
        userId: session.user.id,
        action: 'backup_download_security_violation',
        resource: 'backup',
        details: { userEmail, backupPath, resolvedPath, error: `Attempt to download file from unauthorized path: ${backupPath}` }
      })
      
      return NextResponse.json({
        success: false,
        error: "Access denied to requested file path"
      }, { status: 403 })
    }

    // Read the backup file
    let fileBuffer: Buffer
    let fileName: string
    
    try {
      fileBuffer = await readFile(resolvedPath)
      fileName = path.basename(resolvedPath)
    } catch (error: any) {
      await AuditLogger.logUserAction({
        userId: session.user.id,
        action: 'backup_download_error',
        resource: 'backup',
        details: { userEmail, backupPath, error: error.message, message: `Failed to read backup file: ${error.message}` }
      })
      
      return NextResponse.json({
        success: false,
        error: "Backup file not found or cannot be read"
      }, { status: 404 })
    }

    // Log successful download
    await AuditLogger.logUserAction({
      userId: session.user.id,
      action: 'backup_downloaded',
      resource: 'backup',
      details: { userEmail, fileName, fileSize: fileBuffer.length, message: `Backup file downloaded successfully: ${fileName}` }
    })

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
    console.error('Backup download error:', error)
    
    await AuditLogger.logUserAction({
      userId: 'unknown',
      action: 'backup_download_failed',
      resource: 'backup',
      details: { error: error.message, stack: error.stack, message: `Backup download failed: ${error.message}` }
    })

    return NextResponse.json({
      success: false,
      error: "Internal server error during backup download"
    }, { status: 500 })
  }
}