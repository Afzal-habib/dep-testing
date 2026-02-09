import { type NextRequest, NextResponse } from "next/server"
import { S3Service } from '@/lib/services/s3-service'
import { presignedUrlSchema } from '@/lib/validations/s3'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'

// POST /api/files/presigned-url - Get presigned URL for direct upload
export async function POST(request: NextRequest) {
    try {
        // Security & Authentication
        const { session, user } = await genericApiRoutesMiddleware(request, 'files', 'create')

        // Parse & validate request body
        const body = await request.json()
        const validation = presignedUrlSchema.safeParse(body)

        if (!validation.success) {
            return NextResponse.json({
                success: false,
                error: 'Invalid request data',
                details: validation.error.errors
            }, { status: 400 })
        }

        const { fileName, contentType, fileType, clientId } = validation.data

        // Generate presigned upload URL
        const result = await S3Service.getPresignedUploadUrl(
            fileName,
            contentType,
            fileType,
            user.id,
            clientId
        )

        if (!result.success) {
            return NextResponse.json({
                success: false,
                error: result.error
            }, { status: 400 })
        }

        return NextResponse.json({
            success: true,
            data: result.data,
            message: 'Presigned upload URL generated successfully'
        })

    } catch (error: any) {
        console.error('Presigned URL API error:', error)
        return NextResponse.json({
            success: false,
            error: error.message || 'Failed to generate presigned URL'
        }, { status: 500 })
    }
}