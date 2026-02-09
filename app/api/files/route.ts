import { type NextRequest, NextResponse } from "next/server"
import { S3Service } from '@/lib/services/s3-service'
import { uploadFileSchema, presignedUrlSchema } from '@/lib/validations/s3'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'

// POST /api/files - Upload file to S3
export async function POST(request: NextRequest) {
    try {
        // Security & Authentication
        const { session, user } = await genericApiRoutesMiddleware(request, 'files', 'create')

        const formData = await request.formData()
        const file = formData.get('file') as File
        const fileType = formData.get('fileType') as string
        const clientId = formData.get('clientId') as string | null

        if (!file) {
            return NextResponse.json({
                success: false,
                error: 'No file provided'
            }, { status: 400 })
        }

        // Validate file data
        const fileData = {
            name: file.name,
            size: file.size,
            type: file.type,
            fileType: fileType as any,
            clientId: clientId || undefined
        }

        const validation = uploadFileSchema.safeParse(fileData)
        if (!validation.success) {
            return NextResponse.json({
                success: false,
                error: 'Invalid file data',
                details: validation.error.errors
            }, { status: 400 })
        }

        // Convert file to buffer
        const buffer = Buffer.from(await file.arrayBuffer())

        // Upload to S3
        const result = await S3Service.uploadFile({
            file: buffer,
            fileName: file.name,
            contentType: file.type,
            fileType: validation.data.fileType,
            userId: user.id,
            clientId: validation.data.clientId,
            metadata: {
                uploadSource: 'api'
            }
        })

        if (!result.success) {
            return NextResponse.json({
                success: false,
                error: result.error
            }, { status: 400 })
        }

        return NextResponse.json({
            success: true,
            data: result.data,
            message: 'File uploaded successfully'
        }, { status: 201 })

    } catch (error: any) {
        console.error('File upload API error:', error)
        return NextResponse.json({
            success: false,
            error: error.message || 'Failed to upload file'
        }, { status: 500 })
    }
}

// GET /api/files - Get presigned URL for file access
export async function GET(request: NextRequest) {
    try {
        // Security & Authentication
        const { session, user } = await genericApiRoutesMiddleware(request, 'files', 'read')

        const searchParams = request.nextUrl.searchParams
        const key = searchParams.get('key')
        const fileType = searchParams.get('fileType')

        if (!key || !fileType) {
            return NextResponse.json({
                success: false,
                error: 'Missing key or fileType parameter'
            }, { status: 400 })
        }

        // Get presigned URL
        const url = await S3Service.getPresignedUrl(key, fileType as any)

        return NextResponse.json({
            success: true,
            data: { url, key },
            message: 'Presigned URL generated successfully'
        })

    } catch (error: any) {
        console.error('File access API error:', error)
        return NextResponse.json({
            success: false,
            error: error.message || 'Failed to get file access URL'
        }, { status: 500 })
    }
}