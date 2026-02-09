'use client'

import { useState, useEffect } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { useSession, signOut } from 'next-auth/react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Loader2, Mail, Shield, Clock, AlertTriangle, LogOut } from 'lucide-react'

export default function TwoFactorPage() {
    const router = useRouter()
    const searchParams = useSearchParams()
    const { data: session, update } = useSession()

    const [code, setCode] = useState('')
    const [loading, setLoading] = useState(false)
    const [sendingCode, setSendingCode] = useState(false)
    const [signingOut, setSigningOut] = useState(false)
    const [error, setError] = useState('')
    const [message, setMessage] = useState('')
    const [timeLeft, setTimeLeft] = useState(120) // 2 minutes
    const [canResend, setCanResend] = useState(false)

    const email = searchParams?.get('email') || session?.user?.email || ''

    // Timer countdown
    useEffect(() => {
        if (timeLeft > 0) {
            const timer = setTimeout(() => setTimeLeft(timeLeft - 1), 1000)
            return () => clearTimeout(timer)
        } else {
            setCanResend(true)
        }
    }, [timeLeft])

    // Auto-send code when component mounts (only if no active token exists)
    useEffect(() => {
        if (email && !message && !error) {
            checkExistingTokenAndSend()
        }
    }, [email])

    // Check if there's already an active token before sending new one
    const checkExistingTokenAndSend = async () => {
        try {
            // First check if there's an active token
            const checkResponse = await fetch('/api/auth/2fa/status', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email }),
            })

            const checkData = await checkResponse.json()

            if (checkData.hasActiveToken) {
                // Set timer based on remaining time
                const remainingTime = Math.max(0, checkData.remainingTime || 0)
                setTimeLeft(remainingTime)
                setCanResend(remainingTime === 0)
                setMessage('Verification code already sent to your email')
            } else {
                // No active token, send new code
                handleSendCode()
            }
        } catch (error) {
            // If check fails, proceed with sending new code
            handleSendCode()
        }
    }    // Format time display
    const formatTime = (seconds: number) => {
        const mins = Math.floor(seconds / 60)
        const secs = seconds % 60
        return `${mins}:${secs.toString().padStart(2, '0')}`
    }

    const handleSendCode = async () => {
        if (!email) {
            setError('Email address is required')
            return
        }

        setSendingCode(true)
        setError('')
        setMessage('')

        try {
            const response = await fetch('/api/auth/2fa/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email }),
            })

            const data = await response.json()

            if (response.ok) {
                setMessage('Verification code sent to your email')
                setTimeLeft(120) // Reset timer
                setCanResend(false)
            } else {
                setError(data.error || 'Failed to send verification code')
            }
        } catch (error) {
            setError('Network error. Please try again.')
        } finally {
            setSendingCode(false)
        }
    }

    const handleSignOut = async () => {
        setSigningOut(true)
        try {
            // Use NextAuth's signOut to end the session and redirect to sign-in page
            await signOut({ callbackUrl: '/auth/login' })
        } catch (error) {
            // If sign out fails, show a quick message in the console
            console.error('Sign out failed', error)
        } finally {
            setSigningOut(false)
        }
    }

    const handleVerifyCode = async (e: React.FormEvent) => {
        e.preventDefault()

        if (!code || code.length !== 6) {
            setError('Please enter a valid 6-digit code')
            return
        }

        setLoading(true)
        setError('')

        try {
            const response = await fetch('/api/auth/2fa/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, code }),
            })

            const data = await response.json()

            if (response.ok) {
                setMessage('Verification successful! Redirecting...')

                // Update session to reflect 2FA verification
                await update({
                    twoFactorVerified: true
                })

                // Redirect to dashboard
                router.push('/dashboard')
            } else {
                setError(data.error || 'Verification failed')
                setCode('') // Clear the input
            }
        } catch (error) {
            setError('Network error. Please try again.')
        } finally {
            setLoading(false)
        }
    }

    const handleCodeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const value = e.target.value.replace(/\D/g, '').slice(0, 6)
        setCode(value)
        setError('')
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 p-4">
            <Card className="w-full max-w-md">
                <CardHeader className="text-center space-y-2">
                    <div className="mx-auto w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center">
                        <Shield className="w-6 h-6 text-primary" />
                    </div>
                    <CardTitle className="text-2xl font-bold">Two-Factor Authentication</CardTitle>
                    <CardDescription>
                        We've sent a 6-digit verification code to{' '}
                        <span className="font-medium text-foreground">{email}</span>
                    </CardDescription>
                </CardHeader>

                <CardContent className="space-y-6">
                    {error && (
                        <Alert variant="destructive">
                            <AlertTriangle className="h-4 w-4" />
                            <AlertDescription>{error}</AlertDescription>
                        </Alert>
                    )}

                    {message && (
                        <Alert>
                            <Mail className="h-4 w-4" />
                            <AlertDescription>{message}</AlertDescription>
                        </Alert>
                    )}

                    <form onSubmit={handleVerifyCode} className="space-y-4">
                        <div className="space-y-2">
                            <Label htmlFor="code">Verification Code</Label>
                            <Input
                                id="code"
                                type="text"
                                value={code}
                                onChange={handleCodeChange}
                                placeholder="000000"
                                className="text-center text-2xl font-mono tracking-widest"
                                maxLength={6}
                                autoComplete="one-time-code"
                                disabled={loading}
                            />
                            <p className="text-sm text-muted-foreground text-center">
                                Enter the 6-digit code from your email
                            </p>
                        </div>

                        <Button
                            type="submit"
                            className="w-full"
                            disabled={loading || code.length !== 6}
                        >
                            {loading ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    Verifying...
                                </>
                            ) : (
                                'Verify Code'
                            )}
                        </Button>
                    </form>

                    <div className="space-y-4">
                        <div className="flex items-center justify-center space-x-2 text-sm text-muted-foreground">
                            <Clock className="w-4 h-4" />
                            <span>
                                {timeLeft > 0 ? (
                                    <>Code expires in {formatTime(timeLeft)}</>
                                ) : (
                                    <>Code expired</>
                                )}
                            </span>
                        </div>

                        <div className="text-center">
                            <Button
                                type="button"
                                variant="outline"
                                onClick={handleSendCode}
                                disabled={sendingCode || !canResend}
                                className="w-full"
                            >
                                {sendingCode ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        Sending...
                                    </>
                                ) : (
                                    <>
                                        <Mail className="mr-2 h-4 w-4" />
                                        {canResend ? 'Resend Code' : `Resend in ${formatTime(timeLeft)}`}
                                    </>
                                )}
                            </Button>
                        </div>

                        <div className="text-center">
                            <Button
                                type="button"
                                variant="default"
                                onClick={handleSignOut}
                                disabled={signingOut}
                                className="w-full mt-2"
                            >
                                {signingOut ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        Signing out...
                                    </>
                                ) : (
                                    <>
                                        <LogOut className="mr-2 h-4 w-4" />
                                        Back To Login
                                    </>
                                )}
                            </Button>
                        </div>
                    </div>

                    <div className="text-center text-sm text-muted-foreground">
                        <p>Didn't receive an email? Check your spam folder.</p>
                        <p className="mt-1">
                            Or try using the magic link in the email instead.
                        </p>
                    </div>
                </CardContent>
            </Card>
        </div>
    )
}