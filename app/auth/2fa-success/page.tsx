'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useSession } from 'next-auth/react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { CheckCircle, Loader2 } from 'lucide-react'

export default function TwoFactorSuccessPage() {
    const router = useRouter()
    const { data: session, update } = useSession()

    useEffect(() => {
        const completeLogin = async () => {
            // Update session to reflect 2FA verification
            await update({
                twoFactorVerified: true
            })

            // Wait a moment then redirect
            setTimeout(() => {
                router.push('/dashboard')
            }, 1000)
        }

        completeLogin()
    }, [router, update])

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 p-4">
            <Card className="w-full max-w-md">
                <CardHeader className="text-center space-y-4">
                    <div className="mx-auto w-16 h-16 bg-green-100 rounded-full flex items-center justify-center">
                        <CheckCircle className="w-8 h-8 text-green-600" />
                    </div>
                    <CardTitle className="text-2xl font-bold text-green-700">
                        Authentication Successful!
                    </CardTitle>
                </CardHeader>

                <CardContent className="text-center space-y-4">
                    <p className="text-muted-foreground">
                        Your identity has been verified successfully.
                    </p>

                    <div className="flex items-center justify-center space-x-2 text-sm text-muted-foreground">
                        <Loader2 className="w-4 h-4 animate-spin" />
                        <span>Redirecting you to the dashboard...</span>
                    </div>
                </CardContent>
            </Card>
        </div>
    )
}