import mongoose, { Document, Schema } from 'mongoose'

export interface ITaskOperation extends Document {
  // Task info
  taskId: mongoose.Types.ObjectId
  projectId: mongoose.Types.ObjectId
  departmentId?: mongoose.Types.ObjectId
  
  // Operation data
  operationType: 'create' | 'update' | 'delete' | 'assign' | 'status_change' | 'priority_change'
  oldData?: Record<string, any>
  newData: Record<string, any>
  
  // User info
  userId: mongoose.Types.ObjectId
  userName: string
  
  // Channel broadcast info
  broadcastChannels?: string[]
  broadcastStatus: 'pending' | 'sent' | 'failed'
  
  // Meta fields
  createdAt: Date
}

const TaskOperationSchema = new Schema<ITaskOperation>({
  taskId: {
    type: Schema.Types.ObjectId,
    ref: 'Task',
    required: [true, 'Task ID is required'],
    index: true
  },
  projectId: {
    type: Schema.Types.ObjectId,
    ref: 'Project',
    required: [true, 'Project ID is required'],
    index: true
  },
  departmentId: {
    type: Schema.Types.ObjectId,
    ref: 'Department',
    index: true
  },
  operationType: {
    type: String,
    enum: ['create', 'update', 'delete', 'assign', 'status_change', 'priority_change'],
    required: [true, 'Operation type is required']
  },
  oldData: {
    type: Schema.Types.Mixed
  },
  newData: {
    type: Schema.Types.Mixed,
    required: [true, 'New data is required']
  },
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'User ID is required'],
    index: true
  },
  userName: {
    type: String,
    required: [true, 'User name is required'],
    trim: true
  },
  broadcastChannels: [{
    type: String,
    trim: true
  }],
  broadcastStatus: {
    type: String,
    enum: ['pending', 'sent', 'failed'],
    default: 'pending'
  }
}, {
  timestamps: { createdAt: true, updatedAt: false },
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
})

// Performance indexes
TaskOperationSchema.index({ taskId: 1, createdAt: -1 })
TaskOperationSchema.index({ projectId: 1, createdAt: -1 })
TaskOperationSchema.index({ userId: 1, createdAt: -1 })
TaskOperationSchema.index({ operationType: 1, createdAt: -1 })

// TTL index to auto-cleanup old operations (keep for 30 days)
TaskOperationSchema.index({ createdAt: 1 }, { expireAfterSeconds: 2592000 })

export default mongoose.models.TaskOperation || mongoose.model<ITaskOperation>('TaskOperation', TaskOperationSchema)