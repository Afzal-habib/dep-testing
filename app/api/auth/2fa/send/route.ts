import { NextRequest, NextResponse } from 'next/server'
import { executeGenericDbQuery } from '@/lib/mongodb'
import User from '@/models/User'
import TwoFactorToken from '@/models/TwoFactorToken'
import { generateOTP, hashToken } from '@/lib/utils/otp'
import { EmailService } from '@/lib/services/email-service'
import { AuditLogger } from '@/lib/security/audit-logger'

const BASE_URL = process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000'

/**
 * POST /api/auth/2fa/send
 * Send 2FA verification code to user's email
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

        // Find user
        const user = await executeGenericDbQuery(async () => {
            return await User.findOne({ email: email.toLowerCase() })
                .select('_id name email twoFactorEnabled twoFactorAttempts twoFactorLockedUntil status')
        })

        if (!user) {
            // Don't reveal if user exists for security
            return NextResponse.json(
                { message: 'If this email exists, a verification code has been sent.' },
                { status: 200 }
            )
        }

        if (user.status !== 'active') {
            return NextResponse.json(
                { error: 'Account is not active' },
                { status: 403 }
            )
        }

        // Check if user is locked out
        if (user.twoFactorLockedUntil && user.twoFactorLockedUntil > new Date()) {
            const remainingTime = Math.ceil((user.twoFactorLockedUntil.getTime() - Date.now()) / (1000 * 60))
            return NextResponse.json(
                { error: `Account locked. Try again in ${remainingTime} minutes.` },
                { status: 429 }
            )
        }

        // Reset lockout if expired
        if (user.twoFactorLockedUntil && user.twoFactorLockedUntil <= new Date()) {
            await executeGenericDbQuery(async () => {
                await User.findByIdAndUpdate(user._id, {
                    twoFactorAttempts: 0,
                    twoFactorLockedUntil: null,
                    twoFactorVerified: false
                })
            })
        }

        // Clean up old tokens for this user
        await executeGenericDbQuery(async () => {
            await TwoFactorToken.deleteMany({ email: email.toLowerCase() })
        })

        // Generate OTP and magic link token
        const { token, tokenHash } = generateOTP(email)
        const magicLinkToken = hashToken(`${token}-${Date.now()}`)
        const magicLink = `${BASE_URL}/api/auth/2fa/verify?email=${encodeURIComponent(email)}&token=${magicLinkToken}`

        // Store both tokens in database
        await executeGenericDbQuery(async () => {
            await TwoFactorToken.create({
                email: email.toLowerCase(),
                tokenHash,
                expiresAt: new Date(Date.now() + 2 * 60 * 1000), // 2 minutes
                attempts: 0
            })

            // Store magic link token separately
            await TwoFactorToken.create({
                email: email.toLowerCase(),
                tokenHash: magicLinkToken,
                expiresAt: new Date(Date.now() + 2 * 60 * 1000), // 2 minutes
                attempts: 0
            })
        })

        // Send email with OTP and magic link
        try {
            await EmailService.send2FAEmail({
                to: email,
                otp: token,
                magicLink,
                userName: user.name,
                userId: (user._id as string).toString()
            })

            // Log successful 2FA request
            await AuditLogger.logTwoFactorEvent({
                userId: (user._id as string).toString(),
                userEmail: email,
                eventType: 'code_sent',
                ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
                userAgent: request.headers.get('user-agent') || 'unknown',
                success: true
            })

        } catch (emailError) {
            console.error('Failed to send 2FA email:', emailError)

            // Clean up tokens if email failed
            await executeGenericDbQuery(async () => {
                await TwoFactorToken.deleteMany({ email: email.toLowerCase() })
            })

            return NextResponse.json(
                { error: 'Failed to send verification email. Please try again.' },
                { status: 500 }
            )
        }

        return NextResponse.json({
            message: 'Verification code sent successfully',
            expiresIn: 120 // seconds
        })

    } catch (error: any) {
        console.error('2FA send error:', error)
        return NextResponse.json(
            { error: 'Internal server error' },
            { status: 500 }
        )
    }
}