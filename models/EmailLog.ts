import mongoose, { Document, Schema } from 'mongoose'

export interface IEmailLog extends Document {
    messageId: string
    to: string[]
    cc?: string[]
    bcc?: string[]
    from: string
    subject: string
    content: {
        html?: string
        text?: string
    }
    category: 'auth' | 'notification' | 'marketing' | 'system' | 'client-portal'
    status: 'queued' | 'sent' | 'delivered' | 'bounced' | 'complaint' | 'failed'
    priority: 'low' | 'normal' | 'high' | 'urgent'
    events: Array<{
        type: 'send' | 'delivery' | 'bounce' | 'complaint' | 'open' | 'click'
        timestamp: Date
        metadata?: Record<string, any>
    }>
    userId?: string
    clientId?: string
    templateId?: string
    templateData?: Record<string, any>
    cost: number
    size: number
    tags?: Record<string, string>
    customData?: Record<string, any>
    createdAt: Date
    updatedAt: Date
}

const EmailLogSchema = new Schema<IEmailLog>({
    messageId: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    to: [{
        type: String,
        required: true
    }],
    cc: [{
        type: String
    }],
    bcc: [{
        type: String
    }],
    from: {
        type: String,
        required: true
    },
    subject: {
        type: String,
        required: true
    },
    content: {
        html: String,
        text: String,
    },
    category: {
        type: String,
        enum: ['auth', 'notification', 'marketing', 'system', 'client-portal'],
        required: true,
        index: true
    },
    status: {
        type: String,
        enum: ['queued', 'sent', 'delivered', 'bounced', 'complaint', 'failed'],
        default: 'queued',
        index: true
    },
    priority: {
        type: String,
        enum: ['low', 'normal', 'high', 'urgent'],
        default: 'normal'
    },
    events: [{
        type: {
            type: String,
            enum: ['send', 'delivery', 'bounce', 'complaint', 'open', 'click'],
            required: true
        },
        timestamp: { type: Date, default: Date.now },
        metadata: Schema.Types.Mixed
    }],
    userId: { type: String, index: true },
    clientId: { type: String, index: true },
    templateId: String,
    templateData: Schema.Types.Mixed,
    cost: { type: Number, default: 0 },
    size: { type: Number, required: true },
    tags: Schema.Types.Mixed,
    customData: Schema.Types.Mixed,
}, {
    timestamps: true,
    toJSON: { virtuals: true }
})

// Performance indexes
EmailLogSchema.index({ category: 1, status: 1, createdAt: -1 })
EmailLogSchema.index({ userId: 1, createdAt: -1 })
EmailLogSchema.index({ 'events.type': 1, 'events.timestamp': -1 })

export default mongoose.models.EmailLog || mongoose.model<IEmailLog>("EmailLog", EmailLogSchema)