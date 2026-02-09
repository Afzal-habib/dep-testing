import { type NextRequest, NextResponse } from "next/server"
import { EmailService } from '@/lib/services/email-service'
import { EnhancedEmailService } from '@/lib/services/enhanced-email-service'
import { sendEmailSchema, emailQuerySchema } from '@/lib/validations/email'
import { emailWithS3AttachmentsSchema } from '@/lib/validations/s3'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { z } from 'zod'

// POST /api/email - Send email
export async function POST(request: NextRequest) {
    try {
        // Security & Authentication
        const { session, user } = await genericApiRoutesMiddleware(request, 'email', 'create')

        // Parse & validate request body
        const body = await request.json()

        // Check if email has S3 attachments
        const hasS3Attachments = body.s3Attachments && body.s3Attachments.length > 0

        let result
        if (hasS3Attachments) {
            // Use enhanced email service for S3 attachments
            const validatedData = emailWithS3AttachmentsSchema.parse(body)
            result = await EnhancedEmailService.sendEmailWithAttachments({
                ...validatedData,
                userId: user.id
            })
        } else {
            // Use regular email service
            const validatedData = sendEmailSchema.parse(body)
            result = await EmailService.sendEmail({
                ...validatedData,
                userId: user.id,
                clientId: body.clientId
            })
        }

        if (!result.success) {
            return NextResponse.json({
                success: false,
                error: result.error
            }, { status: 400 })
        }

        return NextResponse.json({
            success: true,
            data: {
                messageId: result.messageId,
                emailLogId: result.emailLogId,
                attachmentCount: 'attachmentCount' in result ? result.attachmentCount ?? 0 : 0
            },
            message: 'Email sent successfully'
        }, { status: 201 })

    } catch (error: any) {
        console.error('Email API error:', error)

        if (error.name === 'ZodError') {
            return NextResponse.json({
                success: false,
                error: 'Invalid request data',
                details: error.errors
            }, { status: 400 })
        }

        return NextResponse.json({
            success: false,
            error: error.message || 'Failed to send email'
        }, { status: 500 })
    }
}

// GET /api/email - Get email analytics and logs
export async function GET(request: NextRequest) {
    try {
        // Security & Authentication
        const { session, user } = await genericApiRoutesMiddleware(request, 'email', 'read')

        // Parse query parameters
        const searchParams = request.nextUrl.searchParams
        const queryParams = {
            page: searchParams.get('page') || '1',
            limit: searchParams.get('limit') || '20',
            search: searchParams.get('search') || '',
            category: searchParams.get('category') || '',
            status: searchParams.get('status') || '',
            priority: searchParams.get('priority') || '',
            startDate: searchParams.get('startDate') || '',
            endDate: searchParams.get('endDate') || ''
        }

        // Validate query parameters
        const validatedParams = emailQuerySchema.parse(queryParams)

        // Get email analytics (using enhanced service for better statistics)
        const result = await EnhancedEmailService.getEmailAnalytics({
            userId: user.id,
            startDate: validatedParams.startDate ? new Date(validatedParams.startDate) : undefined,
            endDate: validatedParams.endDate ? new Date(validatedParams.endDate) : undefined
        })

        if (!result.success) {
            return NextResponse.json({
                success: false,
                error: result.error
            }, { status: 500 })
        }

        return NextResponse.json({
            success: true,
            data: result.data,
            message: 'Email analytics retrieved successfully'
        })

    } catch (error: any) {
        console.error('Email analytics API error:', error)
        return NextResponse.json({
            success: false,
            error: error.message || 'Failed to fetch email analytics'
        }, { status: 500 })
    }
}