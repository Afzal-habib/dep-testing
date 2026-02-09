import { useState, useCallback } from 'react'
import { useToast } from '@/hooks/use-toast'

interface SendEmailParams {
    to: string | string[]
    cc?: string | string[]
    bcc?: string | string[]
    subject: string
    htmlContent?: string
    textContent?: string
    templateId?: string
    templateData?: Record<string, any>
    category: 'auth' | 'notification' | 'marketing' | 'system' | 'client-portal'
    priority?: 'low' | 'normal' | 'high' | 'urgent'
    replyTo?: string
    tags?: Record<string, string>
    attachments?: Array<{
        filename: string
        content: string
        contentType: string
    }>
}

export function useEmail() {
    const [isLoading, setIsLoading] = useState(false)
    const [error, setError] = useState<string | null>(null)
    const { toast } = useToast()

    const sendEmail = useCallback(async (params: SendEmailParams) => {
        setIsLoading(true)
        setError(null)

        try {
            const response = await fetch('/api/email', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(params)
            })

            const data = await response.json()

            if (!data.success) {
                throw new Error(data.error || 'Failed to send email')
            }

            toast({
                title: "Email Sent",
                description: "Your email has been sent successfully.",
                variant: "default"
            })

            return data.data
        } catch (error: any) {
            const errorMessage = error.message || 'Failed to send email'
            setError(errorMessage)

            toast({
                title: "Email Error",
                description: errorMessage,
                variant: "destructive"
            })

            throw error
        } finally {
            setIsLoading(false)
        }
    }, [toast])

    const sendWelcomeEmail = useCallback(async (email: string, name: string, isClient = false) => {
        return sendEmail({
            to: email,
            subject: `Welcome to Digi Era Pro CRM${isClient ? ' Client Portal' : ''}`,
            htmlContent: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Welcome to Digi Era Pro CRM</h2>
          <p>Hello ${name},</p>
          <p>Welcome to the Digi Era Pro CRM ${isClient ? 'Client Portal' : 'system'}! Your account has been created successfully.</p>
          <p>You can now access all the features available to you.</p>
          <p>If you have any questions, please don't hesitate to contact our support team.</p>
          <p>Best regards,<br>The Digi Era Pro Team</p>
        </div>
      `,
            textContent: `Hello ${name},\n\nWelcome to Digi Era Pro CRM! Your account has been created successfully.\n\nBest regards,\nThe Digi Era Pro Team`,
            category: isClient ? 'client-portal' : 'auth',
            priority: 'normal'
        })
    }, [sendEmail])

    const sendPasswordResetEmail = useCallback(async (email: string, name: string, resetToken: string) => {
        const resetUrl = `${process.env.NEXTAUTH_URL}/auth/reset-password?token=${resetToken}`

        return sendEmail({
            to: email,
            subject: 'Password Reset - Digi Era Pro CRM',
            htmlContent: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Password Reset Request</h2>
          <p>Hello ${name},</p>
          <p>You requested a password reset for your Digi Era Pro CRM account.</p>
          <p><a href="${resetUrl}" style="background: #2563eb; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
          <p>This link will expire in 24 hours.</p>
          <p>If you didn't request this, please ignore this email.</p>
        </div>
      `,
            textContent: `Hello ${name},\n\nYou requested a password reset. Click here: ${resetUrl}\n\nThis link expires in 24 hours.`,
            category: 'auth',
            priority: 'high'
        })
    }, [sendEmail])

    const sendNotificationEmail = useCallback(async (params: {
        to: string | string[]
        cc?: string | string[]
        bcc?: string | string[]
        subject: string
        message: string
        priority?: 'low' | 'normal' | 'high' | 'urgent'
        clientId?: string
    }) => {
        return sendEmail({
            to: params.to,
            cc: params.cc,
            bcc: params.bcc,
            subject: params.subject,
            htmlContent: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Digi Era Pro CRM Notification</h2>
          <div style="margin: 20px 0;">
            ${params.message}
          </div>
          <hr style="margin: 20px 0;">
          <p style="color: #666; font-size: 12px;">
            This is an automated notification from Digi Era Pro CRM.
          </p>
        </div>
      `,
            textContent: `Digi Era Pro CRM Notification\n\n${params.message}\n\n---\nThis is an automated notification from Digi Era Pro CRM.`,
            category: 'notification',
            priority: params.priority || 'normal'
        })
    }, [sendEmail])

    // Utility function to format email addresses
    const formatEmailAddresses = useCallback((emails: string | string[]): string[] => {
        return Array.isArray(emails) ? emails : [emails]
    }, [])

    // Utility function to validate email addresses
    const validateEmailAddresses = useCallback((emails: string | string[]): boolean => {
        const emailList = formatEmailAddresses(emails)
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        return emailList.every(email => emailRegex.test(email))
    }, [formatEmailAddresses])

    // Utility function to count total recipients
    const countTotalRecipients = useCallback((params: Pick<SendEmailParams, 'to' | 'cc' | 'bcc'>): number => {
        const toCount = Array.isArray(params.to) ? params.to.length : 1
        const ccCount = params.cc ? (Array.isArray(params.cc) ? params.cc.length : 1) : 0
        const bccCount = params.bcc ? (Array.isArray(params.bcc) ? params.bcc.length : 1) : 0
        return toCount + ccCount + bccCount
    }, [])

    return {
        sendEmail,
        sendWelcomeEmail,
        sendPasswordResetEmail,
        sendNotificationEmail,
        formatEmailAddresses,
        validateEmailAddresses,
        countTotalRecipients,
        isLoading,
        error
    }
}