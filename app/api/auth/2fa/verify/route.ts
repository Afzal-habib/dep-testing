import { NextRequest, NextResponse } from 'next/server'
import { executeGenericDbQuery } from '@/lib/mongodb'
import User from '@/models/User'
import TwoFactorToken from '@/models/TwoFactorToken'
import { verifyOTP, hashToken } from '@/lib/utils/otp'
import { EmailService } from '@/lib/services/email-service'
import { AuditLogger } from '@/lib/security/audit-logger'

/**
 * POST /api/auth/2fa/verify
 * Verify 2FA code entered by user
 */
export async function POST(request: NextRequest) {
    try {
        const { email, code } = await request.json()

        if (!email || !code) {
            return NextResponse.json(
                { error: 'Email and verification code are required' },
                { status: 400 }
            )
        }

        // Find user
        const user = await executeGenericDbQuery(async () => {
            return await User.findOne({ email: email.toLowerCase() })
                .select('_id name email twoFactorAttempts twoFactorLockedUntil status')
        })

        if (!user) {
            return NextResponse.json(
                { error: 'Invalid verification code' },
                { status: 401 }
            )
        }

        // Check if user is locked out
        if (user.twoFactorLockedUntil && user.twoFactorLockedUntil > new Date()) {
            const remainingTime = Math.ceil((user.twoFactorLockedUntil.getTime() - Date.now()) / (1000 * 60))

            await AuditLogger.logTwoFactorEvent({
                userId: (user._id as string).toString(),
                userEmail: email,
                eventType: 'verification_blocked',
                ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
                userAgent: request.headers.get('user-agent') || 'unknown',
                success: false,
                errorMessage: 'Account locked'
            })

            return NextResponse.json(
                { error: `Account locked. Try again in ${remainingTime} minutes.` },
                { status: 429 }
            )
        }

        // Find the most recent token for this email
        const tokenDoc = await executeGenericDbQuery(async () => {
            return await TwoFactorToken.findOne({
                email: email.toLowerCase(),
                expiresAt: { $gt: new Date() }
            }).sort({ createdAt: -1 })
        })

        if (!tokenDoc) {
            await AuditLogger.logTwoFactorEvent({
                userId: (user._id as string).toString(),
                userEmail: email,
                eventType: 'verification_failed',
                ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
                userAgent: request.headers.get('user-agent') || 'unknown',
                success: false,
                errorMessage: 'Token expired or not found'
            })

            return NextResponse.json(
                { error: 'Verification code expired or invalid. Please request a new code.' },
                { status: 410 }
            )
        }

        // Verify the OTP
        const isValidOTP = verifyOTP(code, email)
        const providedTokenHash = hashToken(code)
        const isValidHash = providedTokenHash === tokenDoc.tokenHash

        if (!isValidOTP && !isValidHash) {
            // Increment attempts
            tokenDoc.attempts += 1
            user.twoFactorAttempts += 1

            // Check if max attempts reached
            if (user.twoFactorAttempts >= 3) {
                // Lock user for 1 hour
                const lockoutUntil = new Date(Date.now() + 60 * 60 * 1000)

                await executeGenericDbQuery(async () => {
                    await User.findByIdAndUpdate(user._id, {
                        twoFactorLockedUntil: lockoutUntil,
                        twoFactorVerified: false
                    })
                    await TwoFactorToken.deleteMany({ email: email.toLowerCase() })
                })

                // Send lockout notification
                try {
                    await EmailService.sendLockoutNotification({
                        to: email,
                        userName: user.name,
                        userId: (user._id as string).toString()
                    })
                } catch (emailError) {
                    console.error('Failed to send lockout notification:', emailError)
                }

                await AuditLogger.logTwoFactorEvent({
                    userId: (user._id as string).toString(),
                    userEmail: email,
                    eventType: 'account_locked',
                    ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
                    userAgent: request.headers.get('user-agent') || 'unknown',
                    success: false,
                    errorMessage: 'Max attempts exceeded'
                })

                return NextResponse.json(
                    { error: 'Too many failed attempts. Account locked for 1 hour.' },
                    { status: 429 }
                )
            }

            // Save updated attempts
            await executeGenericDbQuery(async () => {
                await tokenDoc.save()
                await User.findByIdAndUpdate(user._id, {
                    twoFactorAttempts: user.twoFactorAttempts
                })
            })

            await AuditLogger.logTwoFactorEvent({
                userId: (user._id as string).toString(),
                userEmail: email,
                eventType: 'verification_failed',
                ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
                userAgent: request.headers.get('user-agent') || 'unknown',
                success: false,
                errorMessage: 'Invalid code'
            })

            const remainingAttempts = 3 - user.twoFactorAttempts
            return NextResponse.json(
                { error: `Invalid verification code. ${remainingAttempts} attempts remaining.` },
                { status: 401 }
            )
        }

        // Success! Clean up and mark as verified
        await executeGenericDbQuery(async () => {
            await TwoFactorToken.deleteMany({ email: email.toLowerCase() })
            await User.findByIdAndUpdate(user._id, {
                twoFactorAttempts: 0,
                twoFactorLockedUntil: null,
                twoFactorVerified: true
            })
        })

        // Log successful 2FA verification
        await AuditLogger.logTwoFactorEvent({
            userId: (user._id as string).toString(),
            userEmail: email,
            eventType: 'verification_success',
            ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
            userAgent: request.headers.get('user-agent') || 'unknown',
            success: true
        })

        // Log successful login (now that 2FA is complete)
        await AuditLogger.logUserLogin({
            userId: (user._id as string).toString(),
            userEmail: email,
            ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
            userAgent: request.headers.get('user-agent') || 'unknown',
            success: true,
        })
        return NextResponse.json({
            message: 'Verification successful',
            verified: true
        })

    } catch (error: any) {
        console.error('2FA verification error:', error)
        return NextResponse.json(
            { error: 'Internal server error' },
            { status: 500 }
        )
    }
}

/**
 * GET /api/auth/2fa/verify
 * Magic link verification
 */
export async function GET(request: NextRequest) {
    try {
        const { searchParams } = new URL(request.url)
        const email = searchParams.get('email')
        const token = searchParams.get('token')

        if (!email || !token) {
            return NextResponse.redirect(`${process.env.NEXT_PUBLIC_BASE_URL}/auth/error?error=invalid_link`)
        }

        // Find user
        const user = await executeGenericDbQuery(async () => {
            return await User.findOne({ email: email.toLowerCase() })
                .select('_id name email twoFactorAttempts twoFactorLockedUntil status')
        })

        if (!user) {
            return NextResponse.redirect(`${process.env.NEXT_PUBLIC_BASE_URL}/auth/error?error=user_not_found`)
        }

        // Check if user is locked out
        if (user.twoFactorLockedUntil && user.twoFactorLockedUntil > new Date()) {
            return NextResponse.redirect(`${process.env.NEXT_PUBLIC_BASE_URL}/auth/error?error=account_locked`)
        }

        // Find the magic link token
        const tokenDoc = await executeGenericDbQuery(async () => {
            return await TwoFactorToken.findOne({
                email: email.toLowerCase(),
                tokenHash: token,
                expiresAt: { $gt: new Date() }
            })
        })

        if (!tokenDoc) {
            await AuditLogger.logTwoFactorEvent({
                userId: (user._id as string).toString(),
                userEmail: email,
                eventType: 'magic_link_failed',
                ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
                userAgent: request.headers.get('user-agent') || 'unknown',
                success: false,
                errorMessage: 'Invalid or expired magic link'
            })

            return NextResponse.redirect(`${process.env.NEXT_PUBLIC_BASE_URL}/auth/error?error=link_expired`)
        }

        // Success! Clean up and mark as verified
        await executeGenericDbQuery(async () => {
            await TwoFactorToken.deleteMany({ email: email.toLowerCase() })
            await User.findByIdAndUpdate(user._id, {
                twoFactorAttempts: 0,
                twoFactorLockedUntil: null,
                twoFactorVerified: true
            })
        })

        // Log successful magic link verification
        await AuditLogger.logTwoFactorEvent({
            userId: (user._id as string).toString(),
            userEmail: email,
            eventType: 'magic_link_success',
            ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
            userAgent: request.headers.get('user-agent') || 'unknown',
            success: true
        })

        // Log successful login (now that 2FA is complete)
        await AuditLogger.logUserLogin({
            userId: (user._id as string).toString(),
            userEmail: email,
            ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
            userAgent: request.headers.get('user-agent') || 'unknown',
            success: true,
        })        // Redirect to dashboard with success message
        return NextResponse.redirect(`${process.env.NEXT_PUBLIC_BASE_URL}/auth/2fa-success`)

    } catch (error: any) {
        console.error('Magic link verification error:', error)
        return NextResponse.redirect(`${process.env.NEXT_PUBLIC_BASE_URL}/auth/error?error=server_error`)
    }
}