import { type NextRequest, NextResponse } from "next/server"
import { S3Service } from '@/lib/services/s3-service'
import { deleteFileSchema, fileMetadataSchema } from '@/lib/validations/s3'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'

type RouteParams = {
    params: Promise<{ key: string }>
}

// GET /api/files/[key] - Get file metadata
export async function GET(request: NextRequest, { params }: RouteParams) {
    try {
        // Security & Authentication
        const { session, user } = await genericApiRoutesMiddleware(request, 'files', 'read')

        const { key: rawKey } = await params
        const key = decodeURIComponent(rawKey)

        const validation = fileMetadataSchema.safeParse({ key })
        if (!validation.success) {
            return NextResponse.json({
                success: false,
                error: 'Invalid file key',
                details: validation.error.errors
            }, { status: 400 })
        }

        // Get file metadata
        const result = await S3Service.getFileMetadata(key)

        if (!result.success) {
            return NextResponse.json({
                success: false,
                error: result.error
            }, { status: 404 })
        }

        return NextResponse.json({
            success: true,
            data: result.data,
            message: 'File metadata retrieved successfully'
        })

    } catch (error: any) {
        console.error('File metadata API error:', error)
        return NextResponse.json({
            success: false,
            error: error.message || 'Failed to get file metadata'
        }, { status: 500 })
    }
}

// DELETE /api/files/[key] - Delete file from S3
export async function DELETE(request: NextRequest, { params }: RouteParams) {
    try {
        // Security & Authentication
        const { session, user } = await genericApiRoutesMiddleware(request, 'files', 'delete')

        const { key: rawKey } = await params
        const key = decodeURIComponent(rawKey)

        const validation = deleteFileSchema.safeParse({ key })
        if (!validation.success) {
            return NextResponse.json({
                success: false,
                error: 'Invalid file key',
                details: validation.error.errors
            }, { status: 400 })
        }

        // Check if file belongs to user (basic security check)
        // Extract userId from key path
        const keyParts = key.split('/')
        if (keyParts.length < 2) {
            return NextResponse.json({
                success: false,
                error: 'Invalid file key format'
            }, { status: 400 })
        }

        const fileUserId = keyParts[1]
        if (fileUserId !== user.id) {
            return NextResponse.json({
                success: false,
                error: 'Unauthorized to delete this file'
            }, { status: 403 })
        }

        // Delete file from S3
        const result = await S3Service.deleteFile(key)

        if (!result.success) {
            return NextResponse.json({
                success: false,
                error: result.error
            }, { status: 500 })
        }

        return NextResponse.json({
            success: true,
            message: 'File deleted successfully'
        })

    } catch (error: any) {
        console.error('File deletion API error:', error)
        return NextResponse.json({
            success: false,
            error: error.message || 'Failed to delete file'
        }, { status: 500 })
    }
}