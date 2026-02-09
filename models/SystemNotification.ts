import mongoose, { Document, Schema } from 'mongoose'

export interface ISystemNotification extends Document {
  // Core notification data
  type: 'project_created' | 'task_assigned' | 'project_approved' | 'task_completed' | 'project_status_changed' | 'department_assigned'
  category: 'project' | 'task' | 'system' | 'department'
  
  // Recipient info
  recipientId: mongoose.Types.ObjectId // MongoDB user ID
  recipientRole?: string // Optional: specific role requirement
  
  // Sender info
  senderId: mongoose.Types.ObjectId // MongoDB user ID
  senderName: string
  senderAvatar?: string
  
  // Notification content
  title: string
  message: string
  contentPreview?: string // Short description
  
  // Related entity data
  entityType: 'project' | 'task' | 'department' | 'user'
  entityId: mongoose.Types.ObjectId // MongoDB entity ID
  entityName?: string
  
  // Action data
  actionType: 'created' | 'updated' | 'assigned' | 'approved' | 'completed' | 'status_changed'
  actionUrl?: string // Deep link to the entity
  
  // Status tracking
  isRead: boolean
  readAt?: Date
  expiresAt?: Date // Optional: auto-cleanup
  
  // Additional metadata
  metadata?: Record<string, any> // Flexible data for future extensions
  priority: 1 | 2 | 3 | 4 // 1=low, 2=medium, 3=high, 4=urgent
  
  // Meta fields
  createdAt: Date
  updatedAt: Date
}

const SystemNotificationSchema = new Schema<ISystemNotification>({
  type: {
    type: String,
    enum: ['project_created', 'task_assigned', 'project_approved', 'task_completed', 'project_status_changed', 'department_assigned'],
    required: [true, 'Notification type is required']
  },
  category: {
    type: String,
    enum: ['project', 'task', 'system', 'department'],
    required: [true, 'Category is required']
  },
  recipientId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Recipient is required'],
    index: true
  },
  recipientRole: {
    type: String,
    trim: true
  },
  senderId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Sender is required']
  },
  senderName: {
    type: String,
    required: [true, 'Sender name is required'],
    trim: true
  },
  senderAvatar: {
    type: String,
    trim: true
  },
  title: {
    type: String,
    required: [true, 'Title is required'],
    trim: true,
    maxlength: [255, 'Title cannot exceed 255 characters']
  },
  message: {
    type: String,
    required: [true, 'Message is required'],
    trim: true,
    maxlength: [1000, 'Message cannot exceed 1000 characters']
  },
  contentPreview: {
    type: String,
    trim: true,
    maxlength: [200, 'Content preview cannot exceed 200 characters']
  },
  entityType: {
    type: String,
    enum: ['project', 'task', 'department', 'user'],
    required: [true, 'Entity type is required']
  },
  entityId: {
    type: Schema.Types.ObjectId,
    required: [true, 'Entity ID is required'],
    index: true
  },
  entityName: {
    type: String,
    trim: true
  },
  actionType: {
    type: String,
    enum: ['created', 'updated', 'assigned', 'approved', 'completed', 'status_changed'],
    required: [true, 'Action type is required']
  },
  actionUrl: {
    type: String,
    trim: true
  },
  isRead: {
    type: Boolean,
    default: false,
    index: true
  },
  readAt: {
    type: Date
  },
  expiresAt: {
    type: Date,
    index: true
  },
  metadata: {
    type: Schema.Types.Mixed,
    default: {}
  },
  priority: {
    type: Number,
    enum: [1, 2, 3, 4],
    default: 1
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
})

// Performance indexes
SystemNotificationSchema.index({ recipientId: 1, isRead: 1, createdAt: -1 })
SystemNotificationSchema.index({ type: 1, createdAt: -1 })
SystemNotificationSchema.index({ entityType: 1, entityId: 1 })
SystemNotificationSchema.index({ category: 1, createdAt: -1 })
SystemNotificationSchema.index({ priority: 1, isRead: 1 })
SystemNotificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }) // TTL index

// Virtuals
SystemNotificationSchema.virtual('recipient', {
  ref: 'User',
  localField: 'recipientId',
  foreignField: '_id',
  justOne: true
})

SystemNotificationSchema.virtual('sender', {
  ref: 'User',
  localField: 'senderId',
  foreignField: '_id',
  justOne: true
})

export default mongoose.models.SystemNotification || mongoose.model<ISystemNotification>('SystemNotification', SystemNotificationSchema)