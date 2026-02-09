"use client"

import { useEffect, useState } from "react"
import { signIn, useSession, getSession } from "next-auth/react"
import { useRouter, useSearchParams } from "next/navigation"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { Eye, EyeOff, Loader2, AlertCircle, Clock, Info } from "lucide-react"
// import GoogleSignInButton from '../components/GoogleSignInButton';

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { loginSchema, type LoginInput } from "@/lib/validations/auth"

export default function LoginPage() {
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState("")
  const [isRateLimited, setIsRateLimited] = useState(false)
  const [countdown, setCountdown] = useState(0)
  const router = useRouter()
  const searchParams = useSearchParams()
  const { data: session, status } = useSession()

  // Check for timeout reason and OAuth errors in URL
  const logoutReason = searchParams?.get('reason')
  const oauthError = searchParams?.get('error')

  useEffect(() => {
    // Handle OAuth errors
    if (oauthError) {
      if (oauthError === 'OAuthAccountNotLinked') {
        setError('No account found with this Google email. Please sign in with your email and password, or contact support to create an account.')
      } else {
        setError(`Authentication error: ${oauthError}. Please try again or sign in with your email and password.`)
      }
    }

    // Redirect if already logged in 
    if (status === 'authenticated' && session) {
      router.push("/dashboard")
    }
  }, [session, status, router, oauthError])

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginInput>({
    resolver: zodResolver(loginSchema),
  })

  // Countdown timer for rate limiting
  const startCountdown = (seconds: number) => {
    setCountdown(seconds)
    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(timer)
          setIsRateLimited(false)
          setError("")
          return 0
        }
        return prev - 1
      })
    }, 1000)
  }

  const formatTime = (seconds: number) => {
    const minutes = Math.floor(seconds / 60)
    const remainingSeconds = seconds % 60
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`
  }

  const onSubmit = async (data: LoginInput) => {
    try {
      setIsLoading(true)
      setError("")

      // Use Next-Auth signIn directly
      const result = await signIn("credentials", {
        email: data.email,
        password: data.password,
        redirect: false,
      })

      if (result?.error) {
        // Handle different error types
        if (result.error === 'CredentialsSignin') {
          setError("Invalid email or password. Please check your credentials and try again.")
        } else if (result.error.includes('deactivated')) {
          setError("Your account has been deactivated. Please contact support.")
        } else if (result.error.includes('rate limit')) {
          setIsRateLimited(true)
          setError("Too many login attempts. Please wait before trying again.")
          startCountdown(300) // 5 minutes countdown
        } else {
          setError(result.error || "Login failed. Please try again.")
        }
        return
      }

      // Success - check if 2FA is required (only for credentials login)
      if (result?.ok) {
        // Get updated session to check 2FA status
        const updatedSession = await getSession() as any

        // Only redirect to 2FA if:
        // 1. User has 2FA enabled (requiresTwoFactor = true)
        // 2. User hasn't completed 2FA verification yet (twoFactorVerified = false) 
        // 3. User is using credentials (not OAuth)
        if (updatedSession?.user?.requiresTwoFactor === true &&
          updatedSession?.user?.twoFactorVerified === false) {
          // Redirect to 2FA verification for credentials login
          router.push(`/auth/2fa?email=${encodeURIComponent(data.email)}`)
        } else {
          // No 2FA required or already verified - go to dashboard
          router.push('/dashboard')
        }
      }
    } catch (error: any) {
      console.error("Login error:", error)

      // Check if it's a network error that might indicate rate limiting
      if (error.message.includes('fetch')) {
        setError("Connection error. Please check your internet connection.")
      } else {
        setError("An unexpected error occurred. Please try again.")
      }
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1">
          <CardTitle className="text-2xl font-bold text-center">Welcome Back</CardTitle>
          <CardDescription className="text-center">Sign in to your CRM account</CardDescription>
        </CardHeader>
        <form onSubmit={handleSubmit(onSubmit)}>
          <CardContent className="space-y-4">
            {/* Show session timeout message if redirected due to timeout */}
            {logoutReason === 'timeout' && !error && (
              <Alert variant="default" className="border-orange-200">
                <Info className="h-4 w-4 text-orange-600" />
                <AlertDescription className="text-orange-800">
                  Your session expired due to inactivity. Please sign in again to continue.
                </AlertDescription>
              </Alert>
            )}

            {error && (
              <Alert variant={isRateLimited ? "destructive" : "destructive"}>
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  {isRateLimited ? (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <Clock className="h-4 w-4" />
                        <span className="font-medium">Account Temporarily Locked</span>
                      </div>
                      <div className="text-sm">
                        Too many failed login attempts. Please wait{" "}
                        <span className="font-mono bg-muted px-1 py-0.5 rounded">
                          {formatTime(countdown)}
                        </span>{" "}
                        before trying again.
                      </div>
                      <div className="text-xs text-muted-foreground">
                        This security measure protects your account from unauthorized access attempts.
                      </div>
                    </div>
                  ) : (
                    error
                  )}
                </AlertDescription>
              </Alert>
            )}

            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="Enter your email"
                {...register("email")}
                className={errors.email ? "border-destructive" : ""}
                disabled={isRateLimited}
              />
              {errors.email && <p className="text-sm text-destructive">{errors.email.message}</p>}
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  placeholder="Enter your password"
                  {...register("password")}
                  className={errors.password ? "border-destructive pr-10" : "pr-10"}
                  disabled={isRateLimited}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={isRateLimited}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
              </div>
              {errors.password && <p className="text-sm text-destructive">{errors.password.message}</p>}
            </div>
          </CardContent>
          <CardFooter className="flex flex-col space-y-4">
            <Button
              type="submit"
              className="w-full"
              disabled={isLoading || isRateLimited}
            >
              {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {isRateLimited ? (
                <>
                  <Clock className="mr-2 h-4 w-4" />
                  Locked ({formatTime(countdown)})
                </>
              ) : (
                "Sign In"
              )}
            </Button>
            {isRateLimited && (
              <p className="text-xs text-center text-muted-foreground">
                🛡️ Security measure active. Your account is protected from brute force attacks.
              </p>
            )}
          </CardFooter>
        </form>

        {/* Divider */}
        <div className="relative px-6 py-4">
          <div className="absolute inset-0 flex items-center">
            <span className="w-full border-t" />
          </div>
          <div className="relative flex justify-center text-xs uppercase">
            <span className="bg-background px-2 text-muted-foreground">
              Or continue with
            </span>
          </div>
        </div>

        {/* Google Sign In Button */}
        <div className="px-6 pb-6">
          <Button
            type="button"
            variant="outline"
            className="w-full"
            onClick={async () => {
              try {
                setIsLoading(true)
                setError("")

                const result = await signIn('google', {
                  redirect: false,
                  callbackUrl: '/dashboard'
                })
              } catch (error: any) {
                console.error('Google sign-in exception:', error)
                setError("An error occurred during Google sign-in. Please try again.")
              } finally {
                setIsLoading(false)
              }
            }}
            disabled={isRateLimited || isLoading}
          >
            <svg className="mr-2 h-4 w-4" viewBox="0 0 24 24">
              <path
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                fill="#4285F4"
              />
              <path
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                fill="#34A853"
              />
              <path
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                fill="#FBBC05"
              />
              <path
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                fill="#EA4335"
              />
            </svg>
            Continue with Google
          </Button>
        </div>
      </Card>
    </div>
  )
}