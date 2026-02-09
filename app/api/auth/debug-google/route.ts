import { NextRequest, NextResponse } from 'next/server'
import { executeGenericDbQuery } from '@/lib/mongodb'
import User from '@/models/User'

/**
 * POST /api/auth/debug-google
 * Debug Google OAuth account linking issues
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

        // Check if user exists with this email
        const user = await executeGenericDbQuery(async () => {
            return await User.findOne({ email: email.toLowerCase() })
                .populate('role', 'name displayName')
                .populate('department', 'name')
        })

        if (!user) {
            return NextResponse.json({
                found: false,
                message: 'No user found with this email address',
                email: email.toLowerCase(),
                solution: 'You need to create an account with this email first, or use a different Google account that matches an existing user email.'
            })
        }

        return NextResponse.json({
            found: true,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                status: user.status,
                role: (user.role as { name?: string } | null)?.name || 'No role assigned',
                department: (user.department as { name?: string } | null)?.name || 'No department assigned',
                twoFactorEnabled: user.twoFactorEnabled,
                createdAt: user.createdAt
            },
            canUseGoogle: user.status === 'active',
            issues: [
                ...(user.status !== 'active' ? [`Account status is '${user.status}' (should be 'active')`] : []),
                ...(!user.role ? ['No role assigned'] : []),
                ...(!user.department ? ['No department assigned'] : [])
            ]
        })

    } catch (error: any) {
        console.error('Debug Google OAuth error:', error)
        return NextResponse.json(
            {
                error: 'Debug check failed',
                message: error.message
            },
            { status: 500 }
        )
    }
}