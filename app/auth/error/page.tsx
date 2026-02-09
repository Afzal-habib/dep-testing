'use client'

import { useRouter, useSearchParams } from 'next/navigation'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { AlertTriangle, ArrowLeft } from 'lucide-react'

const errorMessages: Record<string, { title: string; description: string; action?: string }> = {
    OAuthAccountNotLinked: {
        title: 'Account Not Linked',
        description: 'To sign in with Google, you need to have an existing account with the same email address. Please sign in with your email and password first, or contact an administrator to create an account for you.',
        action: 'Try signing in with your email and password instead.'
    },
    OAuthCallback: {
        title: 'OAuth Callback Error',
        description: 'There was an error during the OAuth authentication process.',
    },
    OAuthSignin: {
        title: 'OAuth Sign-in Error',
        description: 'There was an error signing in with your OAuth provider.',
    },
    OAuthCreateAccount: {
        title: 'Account Creation Error',
        description: 'There was an error creating your account.',
    },
    EmailCreateAccount: {
        title: 'Email Account Creation Error',
        description: 'There was an error creating an account with this email.',
    },
    Callback: {
        title: 'Callback Error',
        description: 'There was an error in the authentication callback.',
    },
    OAuthAccountNotLinkedError: {
        title: 'Google Account Not Found',
        description: 'No account was found with this Google email address. Please ensure you have an existing account in our system or contact support.',
        action: 'Use your email and password to sign in, or contact support to create an account.'
    },
    Signin: {
        title: 'Sign-in Error',
        description: 'There was an error signing you in.',
    },
    Default: {
        title: 'Authentication Error',
        description: 'An unexpected authentication error occurred.',
    }
}

export default function AuthErrorPage() {
    const router = useRouter()
    const searchParams = useSearchParams()
    const error = searchParams?.get('error') || 'Default'

    const errorInfo = errorMessages[error] || errorMessages.Default

    return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4">
            <Card className="w-full max-w-md">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-destructive">
                        <AlertTriangle className="h-5 w-5" />
                        {errorInfo.title}
                    </CardTitle>
                    <CardDescription>
                        Authentication failed
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <Alert variant="destructive">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription>
                            {errorInfo.description}
                        </AlertDescription>
                    </Alert>

                    {errorInfo.action && (
                        <Alert>
                            <AlertDescription>
                                <strong>Suggested Action:</strong> {errorInfo.action}
                            </AlertDescription>
                        </Alert>
                    )}

                    <div className="space-y-3">
                        <Button
                            onClick={() => router.push('/auth/login')}
                            className="w-full"
                        >
                            <ArrowLeft className="mr-2 h-4 w-4" />
                            Back to Login
                        </Button>

                        {error === 'OAuthAccountNotLinked' && (
                            <Button
                                variant="outline"
                                onClick={() => router.push('/auth/login')}
                                className="w-full"
                            >
                                Sign in with Email & Password
                            </Button>
                        )}
                    </div>

                    <div className="text-center">
                        <p className="text-sm text-muted-foreground">
                            Need help? Contact our support team.
                        </p>
                    </div>
                </CardContent>
            </Card>
        </div>
    )
}