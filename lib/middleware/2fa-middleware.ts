import { withAuth } from "next-auth/middleware"
import { NextResponse } from "next/server"

export default withAuth(
    function middleware(req) {
        const token = req.nextauth.token

        // Check if user needs 2FA verification
        if (token?.requiresTwoFactor && !token?.twoFactorVerified) {
            const email = (token as any)?.user?.email || token?.email
            const callbackUrl = req.nextUrl.pathname + req.nextUrl.search

            // Redirect to 2FA page with email and callback URL
            const url = new URL('/auth/2fa', req.url)
            url.searchParams.set('email', email || '')
            url.searchParams.set('callbackUrl', callbackUrl)

            return NextResponse.redirect(url)
        }
    },
    {
        callbacks: {
            authorized: ({ token, req }) => {
                // Allow access to auth pages without 2FA verification
                if (req.nextUrl.pathname.startsWith('/auth/')) {
                    return !!token
                }

                // For protected routes, require both authentication and 2FA verification
                if (req.nextUrl.pathname.startsWith('/dashboard') ||
                    (req.nextUrl.pathname.startsWith('/api/') &&
                        !req.nextUrl.pathname.startsWith('/api/auth/'))) {
                    return !!token && (!(token as any)?.requiresTwoFactor || (token as any)?.twoFactorVerified)
                }

                return !!token
            },
        },
    }
)

export const config = {
    matcher: [
        '/dashboard/:path*',
        '/api/((?!auth/2fa|auth/login|auth/callback).*)/:path*'
    ]
}