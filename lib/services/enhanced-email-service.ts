import { SESClient, SendRawEmailCommand, GetSendQuotaCommand, GetSendStatisticsCommand } from '@aws-sdk/client-ses'
import connectDB from '@/lib/mongodb'
import EmailLog from '@/models/EmailLog'
import { S3Service } from './s3-service'
import type { EmailWithS3Attachments, S3EmailAttachment } from '@/lib/validations/s3'
import crypto from 'crypto'

interface RawEmailParams extends EmailWithS3Attachments {
    userId: string
}

export class EnhancedEmailService {
    private static sesClient = new SESClient({
        region: process.env.AWS_REGION!,
        credentials: {
            accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
        },
    })

    static async sendEmailWithAttachments(params: RawEmailParams) {
        try {
            await connectDB()

            // Generate unique message ID
            const messageId = crypto.randomUUID()
            const recipients = Array.isArray(params.to) ? params.to : [params.to]
            const ccRecipients = params.cc ? (Array.isArray(params.cc) ? params.cc : [params.cc]) : []
            const bccRecipients = params.bcc ? (Array.isArray(params.bcc) ? params.bcc : [params.bcc]) : []

            // Process S3 attachments
            const processedAttachments: Array<{
                filename: string
                content: Buffer
                contentType: string
                size: number
            }> = []

            if (params.s3Attachments && params.s3Attachments.length > 0) {
                for (const s3Attachment of params.s3Attachments) {
                    try {
                        const fileResult = await S3Service.getFileBuffer(s3Attachment.key)
                        if (fileResult.success) {
                            processedAttachments.push({
                                filename: s3Attachment.filename,
                                content: fileResult.data!.buffer,
                                contentType: s3Attachment.contentType,
                                size: fileResult.data!.buffer.length
                            })
                        } else {
                            console.warn(`Failed to get S3 file: ${s3Attachment.key}`, fileResult.error)
                        }
                    } catch (error) {
                        console.error(`Error processing S3 attachment ${s3Attachment.key}:`, error)
                    }
                }
            }

            // Process base64 attachments (for backward compatibility)
            if (params.attachments && params.attachments.length > 0) {
                for (const attachment of params.attachments) {
                    const buffer = Buffer.from(attachment.content, 'base64')
                    processedAttachments.push({
                        filename: attachment.filename,
                        content: buffer,
                        contentType: attachment.contentType,
                        size: buffer.length
                    })
                }
            }

            // Calculate total email size
            const baseEmailSize = JSON.stringify({
                to: recipients,
                cc: ccRecipients,
                bcc: bccRecipients,
                subject: params.subject,
                content: {
                    html: params.htmlContent,
                    text: params.textContent
                }
            }).length

            const attachmentSize = processedAttachments.reduce((sum, att) => sum + att.size, 0)
            const totalEmailSize = baseEmailSize + attachmentSize

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
                size: totalEmailSize,
                cost: 0, // Will be updated after sending
                status: 'queued',
                customData: {
                    hasAttachments: processedAttachments.length > 0,
                    attachmentCount: processedAttachments.length,
                    s3AttachmentKeys: params.s3Attachments?.map(att => att.key) || []
                }
            })

            await emailLog.save()

            // Build raw email with attachments
            const rawEmail = this.buildRawEmail({
                from: process.env.AWS_SES_FROM_EMAIL!,
                to: recipients,
                cc: ccRecipients,
                bcc: bccRecipients,
                subject: params.subject,
                htmlContent: params.htmlContent,
                textContent: params.textContent,
                replyTo: params.replyTo,
                attachments: processedAttachments
            })

            // Send email via SES
            const command = new SendRawEmailCommand({
                Source: process.env.AWS_SES_FROM_EMAIL!,
                Destinations: [...recipients, ...ccRecipients, ...bccRecipients],
                RawMessage: {
                    Data: rawEmail
                },
                ConfigurationSetName: process.env.SES_CONFIGURATION_SET
            })

            const response = await this.sesClient.send(command)

            // Update email log with success
            const totalRecipientCount = recipients.length + ccRecipients.length + bccRecipients.length
            const attachmentCost = Math.ceil(attachmentSize / (1024 * 1024)) * 0.0001 // Additional cost for attachments

            await EmailLog.findByIdAndUpdate(emailLog._id, {
                messageId: response.MessageId,
                status: 'sent',
                cost: (totalRecipientCount * 0.0001) + attachmentCost,
                events: [{
                    type: 'send',
                    timestamp: new Date(),
                    metadata: {
                        sesMessageId: response.MessageId,
                        totalRecipients: totalRecipientCount,
                        attachmentCount: processedAttachments.length,
                        totalSize: totalEmailSize,
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
                emailLogId: emailLog._id.toString(),
                attachmentCount: processedAttachments.length
            }

        } catch (error: any) {
            console.error('Enhanced email send error:', error)

            // Update email log with error if possible
            if (params.userId) {
                try {
                    await EmailLog.create({
                        messageId: crypto.randomUUID(),
                        to: Array.isArray(params.to) ? params.to : [params.to],
                        from: process.env.AWS_SES_FROM_EMAIL!,
                        subject: params.subject,
                        content: {
                            html: params.htmlContent,
                            text: params.textContent
                        },
                        category: params.category,
                        priority: params.priority,
                        userId: params.userId,
                        size: 0,
                        cost: 0,
                        status: 'failed',
                        events: [{
                            type: 'send',
                            timestamp: new Date(),
                            metadata: { error: error.message }
                        }]
                    })
                } catch (logError) {
                    console.error('Failed to log email error:', logError)
                }
            }

            return {
                success: false,
                error: error.message || 'Failed to send email'
            }
        }
    }

    private static buildRawEmail(params: {
        from: string
        to: string[]
        cc?: string[]
        bcc?: string[]
        subject: string
        htmlContent?: string
        textContent?: string
        replyTo?: string
        attachments?: Array<{
            filename: string
            content: Buffer
            contentType: string
            size: number
        }>
    }): Buffer {
        const boundary = `----=_NextPart_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
        const attachmentBoundary = `----=_Attachment_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`

        let rawEmail = ''

        // Headers
        rawEmail += `From: ${params.from}\r\n`
        rawEmail += `To: ${params.to.join(', ')}\r\n`
        if (params.cc && params.cc.length > 0) {
            rawEmail += `Cc: ${params.cc.join(', ')}\r\n`
        }
        if (params.bcc && params.bcc.length > 0) {
            rawEmail += `Bcc: ${params.bcc.join(', ')}\r\n`
        }
        rawEmail += `Subject: ${params.subject}\r\n`
        if (params.replyTo) {
            rawEmail += `Reply-To: ${params.replyTo}\r\n`
        }
        rawEmail += `MIME-Version: 1.0\r\n`

        if (params.attachments && params.attachments.length > 0) {
            rawEmail += `Content-Type: multipart/mixed; boundary="${attachmentBoundary}"\r\n\r\n`
            rawEmail += `--${attachmentBoundary}\r\n`
        }

        // Content-Type for main body
        if (params.htmlContent && params.textContent) {
            rawEmail += `Content-Type: multipart/alternative; boundary="${boundary}"\r\n\r\n`
        } else if (params.htmlContent) {
            rawEmail += `Content-Type: text/html; charset=UTF-8\r\n\r\n`
        } else {
            rawEmail += `Content-Type: text/plain; charset=UTF-8\r\n\r\n`
        }

        // Body content
        if (params.htmlContent && params.textContent) {
            // Text part
            rawEmail += `--${boundary}\r\n`
            rawEmail += `Content-Type: text/plain; charset=UTF-8\r\n\r\n`
            rawEmail += `${params.textContent}\r\n\r\n`

            // HTML part
            rawEmail += `--${boundary}\r\n`
            rawEmail += `Content-Type: text/html; charset=UTF-8\r\n\r\n`
            rawEmail += `${params.htmlContent}\r\n\r\n`
            rawEmail += `--${boundary}--\r\n`
        } else if (params.htmlContent) {
            rawEmail += `${params.htmlContent}\r\n`
        } else if (params.textContent) {
            rawEmail += `${params.textContent}\r\n`
        }

        // Attachments
        if (params.attachments && params.attachments.length > 0) {
            for (const attachment of params.attachments) {
                rawEmail += `--${attachmentBoundary}\r\n`
                rawEmail += `Content-Type: ${attachment.contentType}; name="${attachment.filename}"\r\n`
                rawEmail += `Content-Disposition: attachment; filename="${attachment.filename}"\r\n`
                rawEmail += `Content-Transfer-Encoding: base64\r\n\r\n`

                // Convert buffer to base64 and add line breaks every 76 characters
                const base64Content = attachment.content.toString('base64')
                const base64WithLineBreaks = base64Content.match(/.{1,76}/g)?.join('\r\n') || base64Content
                rawEmail += `${base64WithLineBreaks}\r\n\r\n`
            }
            rawEmail += `--${attachmentBoundary}--\r\n`
        }

        return Buffer.from(rawEmail)
    }

    static async getSendQuota() {
        try {
            const command = new GetSendQuotaCommand({})
            const response = await this.sesClient.send(command)

            return {
                success: true,
                data: {
                    max24HourSend: response.Max24HourSend || 0,
                    maxSendRate: response.MaxSendRate || 0,
                    sentLast24Hours: response.SentLast24Hours || 0
                }
            }
        } catch (error: any) {
            return {
                success: false,
                error: error.message || 'Failed to get send quota'
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
                            emailsWithAttachments: {
                                $sum: {
                                    $cond: [{ $gt: [{ $ifNull: ['$customData.attachmentCount', 0] }, 0] }, 1, 0]
                                }
                            },
                            totalAttachments: { $sum: { $ifNull: ['$customData.attachmentCount', 0] } },
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
                        emailsWithAttachments: 0,
                        totalAttachments: 0,
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
}