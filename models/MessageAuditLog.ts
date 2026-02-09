import mongoose, { Schema, Document, Model } from 'mongoose'

/**
 * Message Audit Log - Stored in MongoDB for Compliance
 * 
 * This model tracks all message lifecycle events for compliance and investigation:
 * - Message creation
 * - Message edits
 * - Message trash/restore operations
 * - Permanent deletion (with content preserved)
 * 
 * Stored separately from real-time communication data (Supabase) for:
 * - Long-term retention
 * - Compliance requirements
 * - Investigation/audit trails
 */

export type MessageAuditAction = 'created' | 'edited' | 'trashed' | 'restored' | 'permanently_deleted'

export interface IMessageAuditLogMetadata {
  trash_reason?: string
  message_created_at?: Date
  days_in_trash?: number
  ip_address?: string
  user_agent?: string
  sender_mongo_id?: string
  sender_name?: string
  sender_email?: string
  retention_policy?: string
  trashed_at?: Date
  trashed_by?: string
  [key: string]: unknown
}

export interface IMessageAuditLog extends Document {
  // References to Supabase message (UUID string)
  supabase_message_id: string
  supabase_channel_id: string
  
  action: MessageAuditAction
  
  // Actor info (MongoDB user reference)
  actor_id: mongoose.Types.ObjectId
  actor_name: string
  actor_email: string
  actor_role?: string
  
  // Content snapshots (for compliance)
  previous_content?: string
  new_content?: string
  
  // Metadata
  metadata?: IMessageAuditLogMetadata
  
  created_at: Date
}

const MessageAuditLogSchema = new Schema<IMessageAuditLog>({
  supabase_message_id: { 
    type: String, 
    required: true,
    index: true 
  },
  supabase_channel_id: { 
    type: String, 
    required: true,
    index: true 
  },
  
  action: { 
    type: String, 
    enum: ['created', 'edited', 'trashed', 'restored', 'permanently_deleted'],
    required: true,
    index: true
  },
  
  actor_id: { 
    type: Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  actor_name: { 
    type: String, 
    required: true 
  },
  actor_email: { 
    type: String, 
    required: true 
  },
  actor_role: { 
    type: String 
  },
  
  previous_content: { 
    type: String 
  },
  new_content: { 
    type: String 
  },
  
  metadata: { 
    type: Schema.Types.Mixed,
    default: {}
  }
  
}, {
  timestamps: { createdAt: 'created_at', updatedAt: false },
  collection: 'message_audit_logs'
})

// Compound indexes for compliance queries
MessageAuditLogSchema.index({ supabase_channel_id: 1, created_at: -1 })
MessageAuditLogSchema.index({ actor_id: 1, action: 1 })
MessageAuditLogSchema.index({ action: 1, created_at: -1 })
MessageAuditLogSchema.index({ supabase_message_id: 1, action: 1 })

// Static methods for common queries
MessageAuditLogSchema.statics.getMessageHistory = function(messageId: string) {
  return this.find({ supabase_message_id: messageId })
    .sort({ created_at: -1 })
    .lean()
}

MessageAuditLogSchema.statics.getChannelAuditLog = function(
  channelId: string, 
  options: { limit?: number; skip?: number; actions?: MessageAuditAction[] } = {}
) {
  const query: Record<string, unknown> = { supabase_channel_id: channelId }
  if (options.actions?.length) {
    query.action = { $in: options.actions }
  }
  
  return this.find(query)
    .sort({ created_at: -1 })
    .skip(options.skip || 0)
    .limit(options.limit || 50)
    .lean()
}

MessageAuditLogSchema.statics.getUserActions = function(
  userId: mongoose.Types.ObjectId,
  options: { limit?: number; actions?: MessageAuditAction[] } = {}
) {
  const query: Record<string, unknown> = { actor_id: userId }
  if (options.actions?.length) {
    query.action = { $in: options.actions }
  }
  
  return this.find(query)
    .sort({ created_at: -1 })
    .limit(options.limit || 100)
    .lean()
}

// Interface for model with statics
interface IMessageAuditLogModel extends Model<IMessageAuditLog> {
  getMessageHistory(messageId: string): Promise<IMessageAuditLog[]>
  getChannelAuditLog(
    channelId: string,
    options?: { limit?: number; skip?: number; actions?: MessageAuditAction[] }
  ): Promise<IMessageAuditLog[]>
  getUserActions(
    userId: mongoose.Types.ObjectId,
    options?: { limit?: number; actions?: MessageAuditAction[] }
  ): Promise<IMessageAuditLog[]>
}

export const MessageAuditLog: IMessageAuditLogModel = 
  (mongoose.models.MessageAuditLog as IMessageAuditLogModel) || 
  mongoose.model<IMessageAuditLog, IMessageAuditLogModel>('MessageAuditLog', MessageAuditLogSchema)

export default MessageAuditLog
