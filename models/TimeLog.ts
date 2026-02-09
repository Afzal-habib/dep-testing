import mongoose, { Schema, Document, Model } from "mongoose";

// Interface for a single time log document
export interface ITimeLog extends Document {
  _id: string;
  taskId: mongoose.Types.ObjectId;
  projectId: mongoose.Types.ObjectId;
  userId: mongoose.Types.ObjectId;
  description: string;
  hours: number;
  date: Date;
  startTime?: Date;
  endTime?: Date;
  logType: 'manual' | 'timer';
  isApproved: boolean;
  approvedBy?: mongoose.Types.ObjectId;
  approvedAt?: Date;
  isDeleted: boolean;
  deletedAt?: Date;
  deletedBy?: mongoose.Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;

  // Virtual populated fields
  task?: any;
  project?: any;
  user?: any;
  approver?: any;
}

// Static methods interface
export interface TimeLogModel extends mongoose.Model<ITimeLog> {
  findByTaskId(taskId: string): Promise<ITimeLog[]>;
  findByProjectId(projectId: string): Promise<ITimeLog[]>;
  findByUserId(userId: string): Promise<ITimeLog[]>;
  getTotalHours(taskId: string): Promise<number>;
  createTimeLog(data: any): Promise<ITimeLog>;
  softDelete(id: string, deletedBy: string): Promise<ITimeLog | null>;
}

const TimeLogSchema = new Schema<ITimeLog>({
  taskId: {
    type: Schema.Types.ObjectId,
    ref: 'Task',
    required: [true, "Task reference is required"],
    // index: true, // Removed - covered by compound indexes
  },
  projectId: {
    type: Schema.Types.ObjectId,
    ref: 'Project',
    required: [true, "Project reference is required"],
    // index: true, // Removed - covered by compound indexes
  },
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, "User is required"],
    // index: true, // Removed - covered by compound indexes
  },
  description: {
    type: String,
    required: [true, "Description is required"],
    trim: true,
    maxlength: [500, "Description cannot exceed 500 characters"],
  },
  hours: {
    type: Number,
    required: [true, "Hours is required"],
    min: [0.01, "Hours must be at least 0.01"],
    max: [24, "Hours cannot exceed 24 per day"],
  },
  date: {
    type: Date,
    required: [true, "Date is required"],
    // index: true, // Removed - covered by compound indexes
  },
  startTime: {
    type: Date,
  },
  endTime: {
    type: Date,
  },
  logType: {
    type: String,
    enum: ['manual', 'timer'],
    default: 'manual',
    required: true,
  },
  isApproved: {
    type: Boolean,
    default: false,
    // index: true, // Removed - covered by compound indexes
  },
  approvedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
  },
  approvedAt: {
    type: Date,
  },
  isDeleted: {
    type: Boolean,
    default: false,
    // index: true, // Removed - covered by compound indexes
  },
  deletedAt: {
    type: Date,
  },
  deletedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
  },
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
});

// Indexes for performance
TimeLogSchema.index({ taskId: 1, isDeleted: 1, date: -1 });
TimeLogSchema.index({ projectId: 1, isDeleted: 1, date: -1 });
TimeLogSchema.index({ userId: 1, isDeleted: 1, date: -1 });
TimeLogSchema.index({ date: 1, isDeleted: 1 });
TimeLogSchema.index({ isApproved: 1, isDeleted: 1 });

// Virtual for task population
TimeLogSchema.virtual('task', {
  ref: 'Task',
  localField: 'taskId',
  foreignField: '_id',
  justOne: true,
});

// Virtual for project population
TimeLogSchema.virtual('project', {
  ref: 'Project',
  localField: 'projectId',
  foreignField: '_id',
  justOne: true,
});

// Virtual for user population
TimeLogSchema.virtual('user', {
  ref: 'User',
  localField: 'userId',
  foreignField: '_id',
  justOne: true,
});

// Virtual for approver population
TimeLogSchema.virtual('approver', {
  ref: 'User',
  localField: 'approvedBy',
  foreignField: '_id',
  justOne: true,
});

// Static methods
TimeLogSchema.statics.findByTaskId = async function (taskId: string) {
  return this.find({ taskId, isDeleted: false })
    .populate('user', 'name email avatar')
    .populate('approver', 'name email')
    .sort({ date: -1, createdAt: -1 });
};

TimeLogSchema.statics.findByProjectId = async function (projectId: string) {
  return this.find({ projectId, isDeleted: false })
    .populate('task', 'title')
    .populate('user', 'name email avatar')
    .sort({ date: -1, createdAt: -1 });
};

TimeLogSchema.statics.findByUserId = async function (userId: string) {
  return this.find({ userId, isDeleted: false })
    .populate('task', 'title')
    .populate('project', 'name')
    .sort({ date: -1, createdAt: -1 });
};

TimeLogSchema.statics.getTotalHours = async function (taskId: string) {
  const result = await this.aggregate([
    { $match: { taskId: new mongoose.Types.ObjectId(taskId), isDeleted: false } },
    { $group: { _id: null, totalHours: { $sum: '$hours' } } }
  ]);

  return result.length > 0 ? result[0].totalHours : 0;
};

TimeLogSchema.statics.createTimeLog = async function (data: any) {
  const timeLog = new this(data);
  return timeLog.save();
};

TimeLogSchema.statics.softDelete = async function (id: string, deletedBy: string) {
  return this.findByIdAndUpdate(
    id,
    {
      isDeleted: true,
      deletedAt: new Date(),
      deletedBy: new mongoose.Types.ObjectId(deletedBy)
    },
    { new: true }
  );
};

// Pre-save middleware to validate time ranges
TimeLogSchema.pre('save', function (next) {
  // Validate start/end time consistency
  if (this.startTime && this.endTime) {
    if (this.startTime >= this.endTime) {
      return next(new Error('Start time must be before end time'));
    }

    // Auto-calculate hours if not provided
    if (!this.hours) {
      const diffMs = this.endTime.getTime() - this.startTime.getTime();
      this.hours = Math.round((diffMs / (1000 * 60 * 60)) * 100) / 100; // Round to 2 decimal places
    }
  }

  // Validate date is not in the future
  if (this.date > new Date()) {
    return next(new Error('Date cannot be in the future'));
  }

  next();
});

// Ensure virtual fields are serialized
TimeLogSchema.set('toJSON', {
  virtuals: true,
  transform: function (doc, ret) {
    if (ret.__v !== undefined) {
      delete (ret as any).__v;
    }
    return ret;
  }
});

export default mongoose.models.TimeLog || mongoose.model<ITimeLog>("TimeLog", TimeLogSchema);