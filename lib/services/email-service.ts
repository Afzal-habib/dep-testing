import { SESClient, SendEmailCommand, GetSendQuotaCommand, GetSendStatisticsCommand } from '@aws-sdk/client-ses'
import connectDB from '@/lib/mongodb'
import EmailLog from '@/models/EmailLog'
import { SendEmailData } from '@/lib/validations/email'
import crypto from 'crypto'

export class EmailService {
    private static sesClient = new SESClient({
        region: process.env.AWS_REGION!,
        credentials: {
            accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
        },
    })

    static async sendEmail(params: SendEmailData & { userId: string }) {
        try {
            await connectDB()

            // Generate unique message ID
            const messageId = crypto.randomUUID()
            const recipients = Array.isArray(params.to) ? params.to : [params.to]
            const ccRecipients = params.cc ? (Array.isArray(params.cc) ? params.cc : [params.cc]) : []
            const bccRecipients = params.bcc ? (Array.isArray(params.bcc) ? params.bcc : [params.bcc]) : []

            // Calculate email size (rough estimate)
            const emailSize = JSON.stringify({
                to: recipients,
                cc: ccRecipients,
                bcc: bccRecipients,
                subject: params.subject,
                content: {
                    html: params.htmlContent,
                    text: params.textContent
                }
            }).length

            // Create email log entry
            const emailLog = new EmailLog({
                messageId,
                to: recipients,
                cc: ccRecipients.length > 0 ? ccRecipients : undefined,
                bcc: bccRecipients.length > 0 ? bccRecipients : undefined,
                from: process.env.AWS_SES_FROM_EMAIL!,
                subject: params.subject,
                content: {
                    html: params.htmlContent,
                    text: params.textContent
                },
                category: params.category,
                priority: params.priority,
                userId: params.userId,
                clientId: params.clientId,
                templateId: params.templateId,
                templateData: params.templateData,
                size: emailSize,
                cost: 0, // Will be updated after sending
                tags: params.tags,
                status: 'queued'
            })

            await emailLog.save()

            // Prepare SES command
            const replyTo = params.replyTo || process.env.AWS_SES_REPLY_TO
            const cleanReplyTo = replyTo && replyTo.includes("@") ? [replyTo] : undefined

            const command = new SendEmailCommand({
                Source: process.env.AWS_SES_FROM_EMAIL!,
                Destination: {
                    ToAddresses: recipients.filter(Boolean),
                    CcAddresses: ccRecipients.length > 0 ? ccRecipients.filter(Boolean) : undefined,
                    BccAddresses: bccRecipients.length > 0 ? bccRecipients.filter(Boolean) : undefined,
                },
                Message: {
                    Subject: {
                        Data: params.subject,
                        Charset: "UTF-8",
                    },
                    Body: {
                        Html: params.htmlContent
                            ? { Data: params.htmlContent, Charset: "UTF-8" }
                            : undefined,
                        Text: params.textContent
                            ? { Data: params.textContent, Charset: "UTF-8" }
                            : undefined,
                    },
                },
                ReplyToAddresses: cleanReplyTo,
                // ConfigurationSetName: process.env.SES_CONFIGURATION_SET,
            })


            console.log('command is: ', command)
            // Send email via SES
            const response = await this.sesClient.send(command)
            console.log('response is: ', response)

            // Update email log with success
            const totalRecipientCount = recipients.length + ccRecipients.length + bccRecipients.length
            await EmailLog.findByIdAndUpdate(emailLog._id, {
                messageId: response.MessageId,
                status: 'sent',
                cost: totalRecipientCount * 0.0001, // AWS SES pricing
                events: [{
                    type: 'send',
                    timestamp: new Date(),
                    metadata: {
                        sesMessageId: response.MessageId,
                        totalRecipients: totalRecipientCount,
                        breakdown: {
                            to: recipients.length,
                            cc: ccRecipients.length,
                            bcc: bccRecipients.length
                        }
                    }
                }]
            })

            return {
                success: true,
                messageId: response.MessageId,
                emailLogId: emailLog._id.toString()
            }

        } catch (error: any) {
            console.error('Email send error:', error)

            // Update email log with error
            if (params.userId) {
                try {
                    await EmailLog.findOneAndUpdate(
                        { userId: params.userId, status: 'queued' },
                        {
                            status: 'failed',
                            events: [{
                                type: 'send',
                                timestamp: new Date(),
                                metadata: { error: error.message }
                            }]
                        },
                        { sort: { createdAt: -1 } }
                    )
                } catch (logError) {
                    console.error('Failed to update email log:', logError)
                }
            }

            return {
                success: false,
                error: error.message || 'Failed to send email'
            }
        }
    }

    static async getEmailAnalytics(params: {
        userId?: string
        clientId?: string
        startDate?: Date
        endDate?: Date
    }) {
        try {
            await connectDB()

            const query: any = {}

            if (params.userId) query.userId = params.userId
            if (params.clientId) query.clientId = params.clientId
            if (params.startDate && params.endDate) {
                query.createdAt = {
                    $gte: params.startDate,
                    $lte: params.endDate
                }
            }

            const [stats, recentEmails] = await Promise.all([
                EmailLog.aggregate([
                    { $match: query },
                    {
                        $group: {
                            _id: null,
                            totalEmails: { $sum: 1 },
                            totalCost: { $sum: '$cost' },
                            avgSize: { $avg: '$size' },
                            byStatus: {
                                $push: {
                                    status: '$status',
                                    count: 1
                                }
                            },
                            byCategory: {
                                $push: {
                                    category: '$category',
                                    count: 1
                                }
                            }
                        }
                    }
                ]),
                EmailLog.find(query)
                    .sort({ createdAt: -1 })
                    .limit(10)
                    .lean()
            ])

            return {
                success: true,
                data: {
                    stats: stats[0] || {
                        totalEmails: 0,
                        totalCost: 0,
                        avgSize: 0,
                        byStatus: [],
                        byCategory: []
                    },
                    recentEmails
                }
            }

        } catch (error: any) {
            console.error('Email analytics error:', error)
            return {
                success: false,
                error: error.message || 'Failed to get email analytics'
            }
        }
    }

    static async getSendQuota() {
        try {
            const command = new GetSendQuotaCommand({})
            const response = await this.sesClient.send(command)

            return {
                success: true,
                data: {
                    maxSend24Hour: response.Max24HourSend,
                    maxSendRate: response.MaxSendRate,
                    sentLast24Hours: response.SentLast24Hours
                }
            }
        } catch (error: any) {
            return {
                success: false,
                error: error.message
            }
        }
    }

    /**
     * Send 2FA verification email with OTP and magic link
     */
    static async send2FAEmail(params: {
        to: string
        otp: string
        magicLink: string
        userName?: string
        userId: string
    }) {
        const userGreeting = params.userName ? `Hi ${params.userName},` : 'Hello,'
        const BASE_URL = process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000'

        const htmlContent = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Two-Factor Authentication</title>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }
                    .container { max-width: 600px; margin: 0 auto; background-color: white; }
                    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 30px; text-align: center; }
                    .content { padding: 40px 30px; }
                    .otp-code { background-color: #f8f9fa; border: 2px dashed #dee2e6; border-radius: 8px; padding: 30px; text-align: center; margin: 30px 0; }
                    .otp-number { font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #333; font-family: 'Courier New', monospace; }
                    .magic-link { background-color: #007bff; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; display: inline-block; margin: 20px 0; font-weight: bold; }
                    .warning { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
                    .footer { background-color: #f8f9fa; padding: 20px 30px; text-align: center; color: #6c757d; font-size: 14px; }
                    .divider { text-align: center; margin: 30px 0; color: #6c757d; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 Two-Factor Authentication</h1>
                        <p>Secure login verification</p>
                    </div>
                    
                    <div class="content">
                        <p>${userGreeting}</p>
                        <p>You're trying to sign in to your account. To complete the login process, please use one of the following methods:</p>
                        
                        <div class="otp-code">
                            <h3>Method 1: Enter this code</h3>
                            <div class="otp-number">${params.otp}</div>
                            <p style="color: #6c757d; margin-top: 15px;">Enter this 6-digit code in the verification form</p>
                        </div>
                        
                        <div class="divider">
                            <span style="background-color: white; padding: 0 15px;">OR</span>
                        </div>
                        
                        <div style="text-align: center;">
                            <h3>Method 2: Click the magic link</h3>
                            <a href="${params.magicLink}" class="magic-link">
                                🚀 Login Instantly
                            </a>
                            <p style="color: #6c757d; margin-top: 15px;">This link will automatically log you in</p>
                        </div>
                        
                        <div class="warning">
                            <h4>⚠️ Important Security Information:</h4>
                            <ul style="margin: 10px 0; padding-left: 20px;">
                                <li><strong>This code expires in 2 minutes</strong></li>
                                <li>Never share this code with anyone</li>
                                <li>You have 3 attempts before lockout</li>
                                <li>If you didn't request this, please ignore this email</li>
                            </ul>
                        </div>
                        
                        <p style="margin-top: 30px; color: #6c757d;">
                            If you're having trouble clicking the magic link, copy and paste this URL into your browser:
                            <br><small style="word-break: break-all;">${params.magicLink}</small>
                        </p>
                    </div>
                    
                    <div class="footer">
                        <p>This is an automated message. Please do not reply to this email.</p>
                        <p>&copy; ${new Date().getFullYear()} Your Company Name. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
        `

        const textContent = `
${userGreeting}

You're trying to sign in to your account. To complete the login process, please use one of the following methods:

Method 1: Enter this 6-digit code
${params.otp}

Method 2: Click this magic link
${params.magicLink}

IMPORTANT SECURITY INFORMATION:
- This code expires in 2 minutes
- Never share this code with anyone
- You have 3 attempts before lockout
- If you didn't request this, please ignore this email

If you're having trouble with the link, copy and paste this URL into your browser:
${params.magicLink}

This is an automated message. Please do not reply to this email.
        `

        return await this.sendEmail({
            to: params.to,
            subject: '🔐 Your Login Verification Code - Expires in 2 minutes',
            htmlContent,
            textContent,
            category: 'auth',
            priority: 'high',
            userId: params.userId,
            tags: { '2fa': '2fa', 'auth': 'auth', 'security': 'security' }
        })
    }

    /**
     * Send account lockout notification
     */
    static async sendLockoutNotification(params: {
        to: string
        userName?: string
        lockoutDuration?: string
        userId: string
    }) {
        const userGreeting = params.userName ? `Hi ${params.userName},` : 'Hello,'
        const lockoutDuration = params.lockoutDuration || '1 hour'

        const htmlContent = `
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Account Temporarily Locked</title>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }
                    .container { max-width: 600px; margin: 0 auto; background-color: white; }
                    .header { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); color: white; padding: 40px 30px; text-align: center; }
                    .content { padding: 40px 30px; }
                    .warning { background-color: #f8d7da; border-left: 4px solid #dc3545; padding: 20px; margin: 20px 0; border-radius: 4px; }
                    .footer { background-color: #f8f9fa; padding: 20px 30px; text-align: center; color: #6c757d; font-size: 14px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔒 Account Temporarily Locked</h1>
                        <p>Security protection activated</p>
                    </div>
                    
                    <div class="content">
                        <p>${userGreeting}</p>
                        
                        <div class="warning">
                            <h3>⚠️ Your account has been temporarily locked</h3>
                            <p>Due to multiple failed 2FA verification attempts, your account has been locked for <strong>${lockoutDuration}</strong> as a security precaution.</p>
                        </div>
                        
                        <h3>What happened?</h3>
                        <p>Someone (hopefully you) made 3 unsuccessful attempts to verify their identity using two-factor authentication.</p>
                        
                        <h3>What should you do?</h3>
                        <ul>
                            <li>Wait ${lockoutDuration} before trying to log in again</li>
                            <li>Make sure you're entering the correct 6-digit code</li>
                            <li>Check that you're using the code within 2 minutes of receiving it</li>
                            <li>Try using the magic link instead of entering the code manually</li>
                        </ul>
                        
                        <h3>If this wasn't you:</h3>
                        <p>If you didn't attempt to log in, someone may have tried to access your account. Please contact our support team immediately.</p>
                    </div>
                    
                    <div class="footer">
                        <p>This is an automated security notification.</p>
                        <p>&copy; ${new Date().getFullYear()} Your Company Name. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
        `

        return await this.sendEmail({
            to: params.to,
            subject: '🔒 Account Temporarily Locked - Security Alert',
            htmlContent,
            category: 'auth',
            priority: 'high',
            userId: params.userId,
            tags: { 'auth': 'auth', 'lockout': 'lockout', 'alert': 'alert' }
        })
    }
}