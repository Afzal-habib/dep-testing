import mongoose, { Document, Schema } from 'mongoose'

export interface ITask extends Document {
  title: string
  description?: string
  projectId: mongoose.Types.ObjectId
  departmentId: mongoose.Types.ObjectId
  parentTaskId?: mongoose.Types.ObjectId // For sub-tasks
  assigneeId?: mongoose.Types.ObjectId
  
  
  status: 'pending' | 'in-progress' | 'completed' | 'on-hold' | 'cancelled' | 'closed' | 'deleted'
  priority: 'low' | 'medium' | 'high' | 'urgent'
  type: 'task' | 'sub-task'

  // Time tracking
  estimatedHours?: number
  actualHours?: number
  startDate?: Date
  dueDate?: Date
  completedAt?: Date

  // Ordering
  order?: number

  // Meta fields
  createdBy: mongoose.Types.ObjectId
  assignedBy?: mongoose.Types.ObjectId
  createdAt: Date
  updatedAt: Date
  isDeleted: boolean
  deletedAt?: Date
  deletedBy?: mongoose.Types.ObjectId
  deletionReason?: string
}


// Static methods interface
export interface TaskModel extends mongoose.Model<ITask> {
  findByProject(projectId: string, options?: any): Promise<ITask[]>
  findByDepartment(departmentId: string, options?: any): Promise<ITask[]>
  findByAssignee(assigneeId: string, options?: any): Promise<ITask[]>
  getTaskHierarchy(projectId: string): Promise<any[]>
}

const TaskSchema = new Schema<ITask>({
  title: {
    type: String,
    required: [true, "Task title is required"],
    trim: true,
    maxlength: [300, "Title cannot exceed 300 characters"],
    // index: true, // Removed - covered by text search index
  },
  description: {
    type: String,
    trim: true,
    maxlength: [2000, "Description cannot exceed 2000 characters"],
  },
  projectId: {
    type: Schema.Types.ObjectId,
    ref: 'Project',
    required: [true, "Project is required"],
    // index: true, // Removed - covered by compound indexes
  },
  departmentId: {
    type: Schema.Types.ObjectId,
    ref: 'Department',
    required: [true, "Department is required"],
    // index: true, // Removed - covered by compound indexes
  },
  parentTaskId: {
    type: Schema.Types.ObjectId,
    ref: 'Task',
    // index: true, // Removed - covered by compound indexes
    validate: {
      validator: function (value: mongoose.Types.ObjectId) {
        // Sub-tasks must have a parent task
        if (this.type === 'sub-task' && !value) {
          return false
        }
        // Tasks cannot have a parent
        if (this.type === 'task' && value) {
          return false
        }
        return true
      },
      message: 'Sub-tasks must have a parent task, tasks cannot have a parent'
    }
  },
  assigneeId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    // index: true, // Removed - covered by compound indexes
  },
  status: {
    type: String,
    enum: ['pending', 'in-progress', 'completed', 'on-hold', 'cancelled', 'closed', 'deleted'],
    default: 'pending',
    // index: true, // Removed - covered by compound indexes
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'urgent'],
    default: 'medium',
    // index: true, // Removed - not used in compound indexes, can be removed
  },
  type: {
    type: String,
    enum: ['task', 'sub-task'],
    default: 'task',
    required: [true, "Task type is required"],
    // index: true, // Removed - covered by compound indexes
  },

  // Time tracking
  estimatedHours: {
    type: Number,
    min: [0, "Estimated hours must be positive"],
  },
  actualHours: {
    type: Number,
    min: [0, "Actual hours must be positive"],
  },
  startDate: {
    type: Date,
  },
  dueDate: {
    type: Date,
  },
  completedAt: {
    type: Date,
  },

  // Ordering
  order: {
    type: Number,
    default: 0,
    min: [0, "Order must be non-negative"],
  },

  // Meta fields
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, "Creator is required"],
    // index: true, // Removed - covered by compound indexes
  },
  assignedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
  },
  isDeleted: {
    type: Boolean,
    default: false,
  },
  deletedAt: {
    type: Date,
  },
  deletedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
  },
  deletionReason: {
    type: String,
    trim: true,
  },
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
})

// Performance indexes
TaskSchema.index({ projectId: 1, status: 1 })
TaskSchema.index({ departmentId: 1, status: 1 })
TaskSchema.index({ assigneeId: 1, status: 1 })
TaskSchema.index({ parentTaskId: 1, status: 1 })
TaskSchema.index({ type: 1, status: 1 })
TaskSchema.index({ status: 1, dueDate: 1 })
TaskSchema.index({ createdBy: 1, status: 1 })
TaskSchema.index({ isDeleted: 1, status: 1, createdAt: -1 })

// Compound indexes for efficient queries
TaskSchema.index({ projectId: 1, departmentId: 1, type: 1 })
TaskSchema.index({ projectId: 1, type: 1, status: 1 })
// Index for efficient ordering within departments and statuses
TaskSchema.index({ departmentId: 1, status: 1, order: 1 })
TaskSchema.index({ projectId: 1, departmentId: 1, status: 1, order: 1 })

// Text search index
TaskSchema.index({
  title: 'text',
  description: 'text'
}, {
  weights: { title: 10, description: 5 },
  name: 'task_search_index'
})

// Virtuals for populated fields
TaskSchema.virtual('project', {
  ref: 'Project',
  localField: 'projectId',
  foreignField: '_id',
  justOne: true,
})

TaskSchema.virtual('department', {
  ref: 'Department',
  localField: 'departmentId',
  foreignField: '_id',
  justOne: true,
})

TaskSchema.virtual('assignee', {
  ref: 'User',
  localField: 'assigneeId',
  foreignField: '_id',
  justOne: true,
})

TaskSchema.virtual('creator', {
  ref: 'User',
  localField: 'createdBy',
  foreignField: '_id',
  justOne: true,
})

TaskSchema.virtual('assigner', {
  ref: 'User',
  localField: 'assignedBy',
  foreignField: '_id',
  justOne: true,
})

TaskSchema.virtual('parentTask', {
  ref: 'Task',
  localField: 'parentTaskId',
  foreignField: '_id',
  justOne: true,
})

// Virtual for sub-tasks
TaskSchema.virtual('subTasks', {
  ref: 'Task',
  localField: '_id',
  foreignField: 'parentTaskId',
})

// Virtual for sub-task count
TaskSchema.virtual('subTaskCount', {
  ref: 'Task',
  localField: '_id',
  foreignField: 'parentTaskId',
  count: true,
})


// Pre-save validation and logic
TaskSchema.pre('save', async function (next) {
  // Validate required ObjectId fields to prevent corruption
  if (this.isModified('departmentId')) {
    if (!this.departmentId || !mongoose.Types.ObjectId.isValid(this.departmentId)) {
      const error = new Error(`Invalid Department ID: ${this.departmentId}. Must be a valid ObjectId.`)
      return next(error)
    }
  }

  if (this.isModified('projectId')) {
    if (!this.projectId || !mongoose.Types.ObjectId.isValid(this.projectId)) {
      const error = new Error(`Invalid Project ID: ${this.projectId}. Must be a valid ObjectId.`)
      return next(error)
    }
  }

  if (this.isModified('createdBy')) {
    if (!this.createdBy || !mongoose.Types.ObjectId.isValid(this.createdBy)) {
      const error = new Error(`Invalid Creator ID: ${this.createdBy}. Must be a valid ObjectId.`)
      return next(error)
    }
  }

  // Validate optional ObjectId fields
  if (this.isModified('parentTaskId') && this.parentTaskId) {
    if (!mongoose.Types.ObjectId.isValid(this.parentTaskId)) {
      const error = new Error(`Invalid Parent Task ID: ${this.parentTaskId}. Must be a valid ObjectId or null.`)
      return next(error)
    }
  }

  if (this.isModified('assigneeId') && this.assigneeId) {
    if (!mongoose.Types.ObjectId.isValid(this.assigneeId)) {
      const error = new Error(`Invalid Assignee ID: ${this.assigneeId}. Must be a valid ObjectId or null.`)
      return next(error)
    }
  }

  if (this.isModified('assignedBy') && this.assignedBy) {
    if (!mongoose.Types.ObjectId.isValid(this.assignedBy)) {
      const error = new Error(`Invalid Assigned By ID: ${this.assignedBy}. Must be a valid ObjectId or null.`)
      return next(error)
    }
  }

  // Validate dates
  if (this.startDate && this.dueDate && this.startDate > this.dueDate) {
    const error = new Error('Start date cannot be after due date')
    return next(error)
  }

  // Validate parent task exists and is in same project/department for sub-tasks
  if (this.isModified('parentTaskId') && this.parentTaskId) {
    const Task = mongoose.model('Task')
    const parentTask = await Task.findById(this.parentTaskId)

    if (!parentTask) {
      const error = new Error('Parent task not found')
      return next(error)
    }

    if (parentTask.projectId.toString() !== this.projectId.toString()) {
      const error = new Error('Sub-task must belong to same project as parent task')
      return next(error)
    }

    if (parentTask.departmentId.toString() !== this.departmentId.toString()) {
      const error = new Error('Sub-task must belong to same department as parent task')
      return next(error)
    }

    if (parentTask.type === 'sub-task') {
      const error = new Error('Cannot create sub-task of a sub-task')
      return next(error)
    }
  }

  // Validate assignee belongs to task department
  if (this.isModified('assigneeId') && this.assigneeId) {
    const User = mongoose.model('User')
    const assignee = await User.findById(this.assigneeId)

    if (!assignee) {
      const error = new Error('Assignee not found')
      return next(error)
    }

    // if (assignee.departmentId?.toString() !== this.departmentId.toString()) {
    //   const error = new Error('Assignee must belong to task department')
    //   return next(error)
    // }
  }

  // Auto-set completion date
  if (this.isModified('status') && this.status === 'completed' && !this.completedAt) {
    this.completedAt = new Date()
  }

  // Clear completion date if not completed
  if (this.isModified('status') && this.status !== 'completed') {
    this.completedAt = undefined
  }

  // Auto-assign order for new tasks
  if (this.isNew && (this.order === undefined || this.order === 0)) {
    try {
      // Find the highest order in the same department and status
      const TaskModel = this.constructor as TaskModel
      const maxOrderTask = await TaskModel.findOne({
        departmentId: this.departmentId,
        status: this.status,
        _id: { $ne: this._id } // Exclude current task
      }).sort({ order: -1 }).limit(1)

      this.order = (maxOrderTask?.order || 0) + 1
    } catch (error) {
      console.warn('Failed to auto-assign task order:', error)
      this.order = 1 // Fallback to 1 if query fails
    }
  }

  next()
})

// Static methods
TaskSchema.statics.findByProject = function (projectId: string, options = {}) {
  return this.find({ projectId, ...options })
    .populate('assignee', 'name email')
    .populate('department', 'name')
    .populate('creator', 'name email')
    .sort({ createdAt: -1 })
}

TaskSchema.statics.findByDepartment = function (departmentId: string, options = {}) {
  return this.find({ departmentId, ...options })
    .populate('project', 'name clientId')
    .populate('assignee', 'name email')
    .populate('creator', 'name email')
    .sort({ createdAt: -1 })
}

TaskSchema.statics.findByAssignee = function (assigneeId: string, options = {}) {
  return this.find({ assigneeId, ...options })
    .populate('project', 'name clientId')
    .populate('department', 'name')
    .populate('creator', 'name email')
    .sort({ dueDate: 1, createdAt: -1 })
}

TaskSchema.statics.getTaskHierarchy = function (projectId: string) {
  return this.aggregate([
    { $match: { projectId: new mongoose.Types.ObjectId(projectId), status: { $ne: 'cancelled' } } },
    {
      $lookup: {
        from: 'tasks',
        localField: '_id',
        foreignField: 'parentTaskId',
        as: 'subTasks'
      }
    },
    { $match: { type: 'task' } }, // Only get main tasks, sub-tasks are in subTasks array
    {
      $lookup: {
        from: 'users',
        localField: 'assigneeId',
        foreignField: '_id',
        as: 'assignee'
      }
    },
    {
      $lookup: {
        from: 'departments',
        localField: 'departmentId',
        foreignField: '_id',
        as: 'department'
      }
    },
    { $sort: { createdAt: -1 } }
  ])
}

export default (mongoose.models.Task as TaskModel) || mongoose.model<ITask, TaskModel>("Task", TaskSchema)