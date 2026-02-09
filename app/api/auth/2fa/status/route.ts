import { NextRequest, NextResponse } from 'next/server'
import { executeGenericDbQuery } from '@/lib/mongodb'
import TwoFactorToken from '@/models/TwoFactorToken'

/**
 * POST /api/auth/2fa/status
 * Check if user has an active 2FA token
 */
export async function POST(request: NextRequest) {
    try {
        const { email } = await request.json()

        if (!email) {
            return NextResponse.json(
                { error: 'Email is required' },
                { status: 400 }
            )
        }

        // Find the most recent active token for this email
        const activeToken = await executeGenericDbQuery(async () => {
            return await TwoFactorToken.findOne({
                email: email.toLowerCase(),
                expiresAt: { $gt: new Date() }
            }).sort({ createdAt: -1 })
        })

        if (activeToken) {
            // Calculate remaining time in seconds
            const remainingTime = Math.max(0, Math.ceil((activeToken.expiresAt.getTime() - Date.now()) / 1000))

            return NextResponse.json({
                hasActiveToken: true,
                remainingTime,
                expiresAt: activeToken.expiresAt.toISOString(),
                attempts: activeToken.attempts || 0
            })
        }

        return NextResponse.json({
            hasActiveToken: false,
            remainingTime: 0
        })

    } catch (error: any) {
        console.error('2FA status check error:', error)
        return NextResponse.json(
            { error: 'Internal server error' },
            { status: 500 }
        )
    }
}