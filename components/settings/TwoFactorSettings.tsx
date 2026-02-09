import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Shield, Mail, Check, X } from "lucide-react"

interface TwoFactorSettingsProps {
    userEmail: string
    currentlyEnabled: boolean
    onToggle: (enabled: boolean) => Promise<void>
}

export default function TwoFactorSettings({
    userEmail,
    currentlyEnabled,
    onToggle
}: TwoFactorSettingsProps) {
    const [isEnabled, setIsEnabled] = useState(currentlyEnabled)
    const [isLoading, setIsLoading] = useState(false)
    const [message, setMessage] = useState("")
    const [error, setError] = useState("")

    const handleToggle = async (enabled: boolean) => {
        try {
            setIsLoading(true)
            setError("")
            setMessage("")

            await onToggle(enabled)
            setIsEnabled(enabled)

            if (enabled) {
                setMessage("Two-factor authentication has been enabled. You'll need to verify with OTP when signing in.")
            } else {
                setMessage("Two-factor authentication has been disabled. You can sign in with just your password.")
            }
        } catch (err: any) {
            setError(err.message || "Failed to update two-factor authentication settings")
        } finally {
            setIsLoading(false)
        }
    }

    return (
        <Card>
            <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    Two-Factor Authentication
                </CardTitle>
                <CardDescription>
                    Add an extra layer of security to your account with email-based two-factor authentication.
                </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
                {message && (
                    <Alert>
                        <Check className="h-4 w-4" />
                        <AlertDescription>{message}</AlertDescription>
                    </Alert>
                )}

                {error && (
                    <Alert variant="destructive">
                        <X className="h-4 w-4" />
                        <AlertDescription>{error}</AlertDescription>
                    </Alert>
                )}

                <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                        <label className="text-base font-medium">
                            Enable Two-Factor Authentication
                        </label>
                        <div className="text-sm text-muted-foreground flex items-center gap-1">
                            <Mail className="h-3 w-3" />
                            OTP codes will be sent to {userEmail}
                        </div>
                    </div>
                    <Switch
                        checked={isEnabled}
                        onCheckedChange={handleToggle}
                        disabled={isLoading}
                    />
                </div>

                <div className="text-sm text-muted-foreground">
                    <p className="mb-2">How it works:</p>
                    <ul className="list-disc list-inside space-y-1">
                        <li>When enabled, you'll receive a 6-digit code via email during login</li>
                        <li>Works with both password and Google sign-in methods</li>
                        <li>Codes expire after 2 minutes for security</li>
                        <li>You can disable this feature at any time</li>
                    </ul>
                </div>

                {isEnabled && (
                    <Alert>
                        <Shield className="h-4 w-4" />
                        <AlertDescription>
                            <strong>Security Notice:</strong> Two-factor authentication is currently enabled.
                            This applies to all sign-in methods including Google OAuth.
                        </AlertDescription>
                    </Alert>
                )}
            </CardContent>
        </Card>
    )
}

// Example usage hook
export const useTwoFactorSettings = (userId: string) => {
    const toggleTwoFactor = async (enabled: boolean) => {
        const response = await fetch('/api/user/2fa-settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ enabled }),
        })

        if (!response.ok) {
            const error = await response.json()
            throw new Error(error.message || 'Failed to update 2FA settings')
        }

        return response.json()
    }

    return { toggleTwoFactor }
}