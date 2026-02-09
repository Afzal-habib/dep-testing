import { NextRequest, NextResponse } from 'next/server'

/**
 * GET /api/auth/test-google
 * Test Google OAuth configuration
 */
export async function GET(request: NextRequest) {
    try {
        const hasClientId = !!process.env.GOOGLE_CLIENT_ID
        const hasClientSecret = !!process.env.GOOGLE_CLIENT_SECRET
        const hasNextAuthUrl = !!process.env.NEXTAUTH_URL
        const hasNextAuthSecret = !!process.env.NEXTAUTH_SECRET

        const clientIdLength = process.env.GOOGLE_CLIENT_ID?.length || 0
        const clientSecretLength = process.env.GOOGLE_CLIENT_SECRET?.length || 0

        return NextResponse.json({
            status: 'Google OAuth Configuration Check',
            config: {
                hasClientId,
                hasClientSecret,
                hasNextAuthUrl,
                hasNextAuthSecret,
                clientIdLength: clientIdLength > 0 ? `${clientIdLength} characters` : 'Not set',
                clientSecretLength: clientSecretLength > 0 ? `${clientSecretLength} characters` : 'Not set',
                nextAuthUrl: process.env.NEXTAUTH_URL || 'Not set',
                expectedRedirectUri: `${process.env.NEXTAUTH_URL || 'http://localhost:3000'}/api/auth/callback/google`
            },
            issues: [
                ...(!hasClientId ? ['GOOGLE_CLIENT_ID is not set'] : []),
                ...(!hasClientSecret ? ['GOOGLE_CLIENT_SECRET is not set'] : []),
                ...(!hasNextAuthUrl ? ['NEXTAUTH_URL is not set'] : []),
                ...(!hasNextAuthSecret ? ['NEXTAUTH_SECRET is not set'] : []),
                ...(process.env.GOOGLE_CLIENT_ID === 'your_google_client_id_here' ? ['GOOGLE_CLIENT_ID is still using placeholder value'] : []),
                ...(process.env.GOOGLE_CLIENT_SECRET === 'your_google_client_secret_here' ? ['GOOGLE_CLIENT_SECRET is still using placeholder value'] : [])
            ],
            instructions: [
                '1. Go to https://console.cloud.google.com/',
                '2. Create OAuth 2.0 credentials',
                '3. Add authorized JavaScript origin: ' + (process.env.NEXTAUTH_URL || 'http://localhost:3000'),
                '4. Add authorized redirect URI: ' + (process.env.NEXTAUTH_URL || 'http://localhost:3000') + '/api/auth/callback/google',
                '5. Update your .env.local file with the actual credentials',
                '6. Restart your development server'
            ]
        })
    } catch (error: any) {
        return NextResponse.json(
            {
                error: 'Configuration check failed',
                message: error.message
            },
            { status: 500 }
        )
    }
}