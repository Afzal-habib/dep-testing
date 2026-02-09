import { type NextRequest, NextResponse } from "next/server"
import { EmailService } from '@/lib/services/email-service'
import { EnhancedEmailService } from '@/lib/services/enhanced-email-service'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'

// GET /api/email/quota - Get SES send quota
export async function GET(request: NextRequest) {
    try {
        const { session, user } = await genericApiRoutesMiddleware(request, 'email', 'read')

        const quota = await EnhancedEmailService.getSendQuota()

        if (!quota.success) {
            return NextResponse.json(
                { success: false, error: quota.error },
                { status: 500 }
            )
        }

        return NextResponse.json({
            success: true,
            data: quota.data,
            message: 'Send quota retrieved successfully'
        })

    } catch (error: any) {
        console.error('Quota fetch error:', error)
        return NextResponse.json({
            success: false,
            error: error.message || 'Failed to fetch quota'
        }, { status: 500 })
    }
}