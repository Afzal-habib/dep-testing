import { z } from 'zod'

// Constants
export const EMAIL_CONSTANTS = {
    SUBJECT: { MIN_LENGTH: 1, MAX_LENGTH: 200 },
    CONTENT: { MAX_LENGTH: 50000 },
    RECIPIENTS: { 
        MAX_COUNT: 50, // Per field (to, cc, bcc)
        TOTAL_MAX_COUNT: 100 // Total across all fields
    },
    ATTACHMENT: { MAX_SIZE: 25 * 1024 * 1024, MAX_COUNT: 10 }, // 25MB, 10 files
    CATEGORIES: ['auth', 'notification', 'marketing', 'system', 'client-portal'] as const,
    PRIORITIES: ['low', 'normal', 'high', 'urgent'] as const,
    STATUSES: ['queued', 'sent', 'delivered', 'bounced', 'complaint', 'failed'] as const
} as const

// Base schemas
export const emailAttachmentSchema = z.object({
    filename: z.string().min(1).max(255),
    content: z.string(), // Base64 encoded
    contentType: z.string().min(1)
})

export const sendEmailSchema = z.object({
    to: z.union([
        z.string().email(),
        z.array(z.string().email()).max(EMAIL_CONSTANTS.RECIPIENTS.MAX_COUNT)
    ]),
    cc: z.union([
        z.string().email(),
        z.array(z.string().email()).max(EMAIL_CONSTANTS.RECIPIENTS.MAX_COUNT)
    ]).optional(),
    bcc: z.union([
        z.string().email(),
        z.array(z.string().email()).max(EMAIL_CONSTANTS.RECIPIENTS.MAX_COUNT)
    ]).optional(),
    subject: z.string()
        .min(EMAIL_CONSTANTS.SUBJECT.MIN_LENGTH)
        .max(EMAIL_CONSTANTS.SUBJECT.MAX_LENGTH),
    htmlContent: z.string()
        .max(EMAIL_CONSTANTS.CONTENT.MAX_LENGTH)
        .optional(),
    textContent: z.string()
        .max(EMAIL_CONSTANTS.CONTENT.MAX_LENGTH)
        .optional(),
    category: z.enum(EMAIL_CONSTANTS.CATEGORIES),
    priority: z.enum(EMAIL_CONSTANTS.PRIORITIES).default('normal'),
    templateId: z.string().optional(),
    templateData: z.record(z.any()).optional(),
    attachments: z.array(emailAttachmentSchema)
        .max(EMAIL_CONSTANTS.ATTACHMENT.MAX_COUNT)
        .optional(),
    tags: z.record(z.string()).optional(),
    replyTo: z.string().email().optional(),
    clientId: z.string().optional()
}).refine((data) => {
    // Validate total recipient count across to, cc, and bcc
    const toCount = Array.isArray(data.to) ? data.to.length : 1
    const ccCount = data.cc ? (Array.isArray(data.cc) ? data.cc.length : 1) : 0
    const bccCount = data.bcc ? (Array.isArray(data.bcc) ? data.bcc.length : 1) : 0
    const totalRecipients = toCount + ccCount + bccCount
    
    return totalRecipients <= EMAIL_CONSTANTS.RECIPIENTS.TOTAL_MAX_COUNT
}, {
    message: `Total recipients (to + cc + bcc) cannot exceed ${EMAIL_CONSTANTS.RECIPIENTS.TOTAL_MAX_COUNT}`,
    path: ['recipients']
}).refine((data) => {
    // Ensure at least htmlContent or textContent is provided
    return data.htmlContent || data.textContent
}, {
    message: 'Either htmlContent or textContent must be provided',
    path: ['content']
})

export const emailQuerySchema = z.object({
    page: z.string().regex(/^\d+$/).transform(Number).default('1'),
    limit: z.string().regex(/^\d+$/).transform(Number).default('20'),
    search: z.string().optional(),
    category: z.enum([...EMAIL_CONSTANTS.CATEGORIES, '']).optional(),
    status: z.enum([...EMAIL_CONSTANTS.STATUSES, '']).optional(),
    priority: z.enum([...EMAIL_CONSTANTS.PRIORITIES, '']).optional(),
    userId: z.string().optional(),
    clientId: z.string().optional(),
    startDate: z.string().optional(),
    endDate: z.string().optional()
})

// Type exports
export type SendEmailData = z.infer<typeof sendEmailSchema>
export type EmailQueryParams = z.infer<typeof emailQuerySchema>
export type EmailAttachment = z.infer<typeof emailAttachmentSchema>