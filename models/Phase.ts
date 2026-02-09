import mongoose, { Schema, type Document } from "mongoose";

// Interface for a single phase document
export interface IPhase extends Document {
  _id: string;
  title: string;
  description?: string;
  projectId: mongoose.Types.ObjectId;
  order: number;
  startDate: Date;
  endDate: Date;
  actualStartDate?: Date;
  actualEndDate?: Date;
  status: 'pending' | 'planning' | 'in-progress' | 'on-hold' | 'completed' | 'cancelled';
  progress: number; // 0-100
  budgetAllocation?: number;
  actualCost?: number;
  objectives: string[];
  deliverables: string[];
  resources: string[];
  risks: string[];
  dependencies: mongoose.Types.ObjectId[]; // Other phase IDs
  approvalRequired: boolean;
  approvedBy?: mongoose.Types.ObjectId;
  approvedAt?: Date;
  isDeleted: boolean;
  deletedAt?: Date;
  deletedBy?: mongoose.Types.ObjectId;
  createdBy: mongoose.Types.ObjectId;
  updatedBy?: mongoose.Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

// Static methods interface
export interface PhaseModel extends mongoose.Model<IPhase> {
  findByProject(projectId: string): Promise<IPhase[]>;
  calculateProjectPhaseProgress(projectId: string): Promise<number>;
  findActivePhases(): Promise<IPhase[]>;
  reorderPhases(projectId: string, phaseOrders: Array<{ id: string, order: number }>): Promise<void>;
  getPhaseAnalytics(projectId?: string, departmentId?: string): Promise<any>;
  getPhaseTimeline(projectId: string): Promise<any[]>;
  getPhaseTaskAnalytics(phaseId: string): Promise<any>;
}

const PhaseSchema = new Schema<IPhase>({
  title: {
    type: String,
    required: [true, "Phase title is required"],
    trim: true,
    maxlength: [200, "Title cannot exceed 200 characters"],
    minlength: [2, "Title must be at least 2 characters"]
  },
  description: {
    type: String,
    trim: true,
    maxlength: [1000, "Description cannot exceed 1000 characters"]
  },
  projectId: {
    type: Schema.Types.ObjectId,
    ref: 'Project',
    required: [true, "Project reference is required"],
    // index: true, // Removed - covered by compound indexes
  },
  order: {
    type: Number,
    required: [true, "Phase order is required"],
    min: [1, "Order must be positive"],
  },
  startDate: {
    type: Date,
    required: [true, "Start date is required"],
    // index: true, // Removed - not frequently queried alone
  },
  endDate: {
    type: Date,
    required: [true, "End date is required"],
    // index: true, // Removed - covered by compound indexes
  },
  actualStartDate: {
    type: Date,
  },
  actualEndDate: {
    type: Date,
  },
  status: {
    type: String,
    enum: ['pending', 'planning', 'in-progress', 'on-hold', 'completed', 'cancelled'],
    default: 'pending',
    // index: true, // Removed - covered by compound indexes
  },
  progress: {
    type: Number,
    min: [0, "Progress cannot be negative"],
    max: [100, "Progress cannot exceed 100%"],
    default: 0,
  },
  budgetAllocation: {
    type: Number,
    min: [0, "Budget allocation cannot be negative"],
  },
  actualCost: {
    type: Number,
    min: [0, "Actual cost cannot be negative"],
  },
  objectives: [{
    type: String,
    trim: true,
    maxlength: [500, "Objective description too long"]
  }],
  deliverables: [{
    type: String,
    trim: true,
    maxlength: [500, "Deliverable description too long"]
  }],
  resources: [{
    type: String,
    trim: true,
    maxlength: [200, "Resource description too long"]
  }],
  risks: [{
    type: String,
    trim: true,
    maxlength: [500, "Risk description too long"]
  }],
  dependencies: [{
    type: Schema.Types.ObjectId,
    ref: 'Phase',
  }],
  approvalRequired: {
    type: Boolean,
    default: false,
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
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, "Creator is required"],
  },
  updatedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
  },
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
});

// Compound indexes for performance
PhaseSchema.index({ projectId: 1, order: 1 });
PhaseSchema.index({ projectId: 1, isDeleted: 1, status: 1 });
PhaseSchema.index({ status: 1, endDate: 1 });
PhaseSchema.index({ createdAt: -1 });

// Virtuals
PhaseSchema.virtual('duration').get(function () {
  const start = new Date(this.startDate);
  const end = new Date(this.endDate);
  const diffTime = end.getTime() - start.getTime();
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24)); // Days
});

PhaseSchema.virtual('actualDuration').get(function () {
  if (!this.actualStartDate || !this.actualEndDate) return null;
  const start = new Date(this.actualStartDate);
  const end = new Date(this.actualEndDate);
  const diffTime = end.getTime() - start.getTime();
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24)); // Days
});

PhaseSchema.virtual('isOverdue').get(function () {
  return this.status !== 'completed' && this.endDate < new Date();
});

PhaseSchema.virtual('daysRemaining').get(function () {
  const now = new Date();
  const end = new Date(this.endDate);
  const diffTime = end.getTime() - now.getTime();
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
});

// Pre-save middleware
PhaseSchema.pre('save', function (next) {
  // Validate date ranges
  if (this.startDate >= this.endDate) {
    return next(new Error('End date must be after start date'));
  }

  // Auto-update status based on dates and progress
  const now = new Date();

  if (this.progress === 100 && this.status !== 'completed') {
    this.status = 'completed';
    if (!this.actualEndDate) {
      this.actualEndDate = now;
    }
  } else if (this.progress > 0 && this.status === 'pending') {
    this.status = 'in-progress';
    if (!this.actualStartDate) {
      this.actualStartDate = now;
    }
  }

  next();
});

// Pre-validation middleware
PhaseSchema.pre('validate', function (next) {
  if (this.actualStartDate && this.actualEndDate) {
    if (this.actualStartDate >= this.actualEndDate) {
      return next(new Error('Actual end date must be after actual start date'));
    }
  }
  next();
});

// Static methods
PhaseSchema.statics.findByProject = function (projectId: string) {
  return this.find({
    projectId,
    isDeleted: false
  })
    .sort({ order: 1 });
};

PhaseSchema.statics.calculateProjectPhaseProgress = async function (projectId: string) {
  const phases = await this.find({
    projectId,
    isDeleted: false
  });

  if (phases.length === 0) return 0;

  const totalProgress = phases.reduce((sum: number, phase: any) => sum + phase.progress, 0);
  return Math.round(totalProgress / phases.length);
};

PhaseSchema.statics.findActivePhases = function () {
  return this.find({
    isDeleted: false,
    status: { $in: ['in-progress', 'planning'] }
  })
    .populate('projectId', 'name')
    .sort({ endDate: 1 });
};

PhaseSchema.statics.reorderPhases = async function (projectId: string, phaseOrders: Array<{ id: string, order: number }>) {
  const session = await mongoose.startSession();

  try {
    await session.withTransaction(async () => {
      for (const { id, order } of phaseOrders) {
        await this.findByIdAndUpdate(
          id,
          { order },
          { session }
        );
      }
    });
  } finally {
    await session.endSession();
  }
};

// Calculate comprehensive phase analytics
PhaseSchema.statics.getPhaseAnalytics = async function (projectId?: string, departmentId?: string) {
  const matchQuery: any = { isDeleted: false };
  
  if (projectId) {
    matchQuery.projectId = new mongoose.Types.ObjectId(projectId);
  }
  
  // If departmentId provided, need to filter by projects in that department
  let projectIds: mongoose.Types.ObjectId[] = [];
  if (departmentId && !projectId) {
    const Project = mongoose.models.Project;
    const departmentProjects = await Project.find({ 
      departmentId: new mongoose.Types.ObjectId(departmentId),
      isDeleted: false 
    }).select('_id');
    
    projectIds = departmentProjects.map((p: any) => p._id);
    matchQuery.projectId = { $in: projectIds };
  }

  const analytics = await this.aggregate([
    { $match: matchQuery },
    {
      $group: {
        _id: null,
        totalPhases: { $sum: 1 },
        completedPhases: {
          $sum: { $cond: [{ $eq: ["$status", "completed"] }, 1, 0] }
        },
        inProgressPhases: {
          $sum: { $cond: [{ $eq: ["$status", "in-progress"] }, 1, 0] }
        },
        pendingPhases: {
          $sum: { $cond: [{ $eq: ["$status", "pending"] }, 1, 0] }
        },
        blockedPhases: {
          $sum: { $cond: [{ $eq: ["$status", "on-hold"] }, 1, 0] }
        },
        cancelledPhases: {
          $sum: { $cond: [{ $eq: ["$status", "cancelled"] }, 1, 0] }
        },
        averageProgress: { $avg: "$progress" },
        totalBudgetAllocated: { $sum: "$budgetAllocation" },
        totalActualCost: { $sum: "$actualCost" },
        overduePhases: {
          $sum: {
            $cond: [
              {
                $and: [
                  { $lt: ["$endDate", new Date()] },
                  { $ne: ["$status", "completed"] }
                ]
              },
              1,
              0
            ]
          }
        }
      }
    }
  ]);

  const result = analytics[0] || {
    totalPhases: 0,
    completedPhases: 0,
    inProgressPhases: 0,
    pendingPhases: 0,
    blockedPhases: 0,
    cancelledPhases: 0,
    averageProgress: 0,
    totalBudgetAllocated: 0,
    totalActualCost: 0,
    overduePhases: 0
  };

  // Calculate completion rate and budget variance
  result.completionRate = result.totalPhases > 0 
    ? Math.round((result.completedPhases / result.totalPhases) * 100)
    : 0;

  result.budgetVariance = result.totalBudgetAllocated > 0
    ? Math.round(((result.totalActualCost - result.totalBudgetAllocated) / result.totalBudgetAllocated) * 100)
    : 0;

  result.averageProgress = Math.round(result.averageProgress || 0);

  return result;
};

// Get phase timeline analytics
PhaseSchema.statics.getPhaseTimeline = async function (projectId: string) {
  const phases = await this.find({
    projectId: new mongoose.Types.ObjectId(projectId),
    isDeleted: false
  })
    .sort({ order: 1 })
    .select('title startDate endDate actualStartDate actualEndDate status progress order');

  const timeline = phases.map((phase: any) => {
    const plannedDuration = Math.ceil(
      (new Date(phase.endDate).getTime() - new Date(phase.startDate).getTime()) / (1000 * 60 * 60 * 24)
    );

    let actualDuration = null;
    if (phase.actualStartDate && phase.actualEndDate) {
      actualDuration = Math.ceil(
        (new Date(phase.actualEndDate).getTime() - new Date(phase.actualStartDate).getTime()) / (1000 * 60 * 60 * 24)
      );
    }

    const isDelayed = phase.status !== 'completed' && new Date(phase.endDate) < new Date();
    const delayDays = isDelayed 
      ? Math.ceil((new Date().getTime() - new Date(phase.endDate).getTime()) / (1000 * 60 * 60 * 24))
      : 0;

    return {
      phaseId: phase._id,
      title: phase.title,
      order: phase.order,
      status: phase.status,
      progress: phase.progress,
      startDate: phase.startDate,
      endDate: phase.endDate,
      actualStartDate: phase.actualStartDate,
      actualEndDate: phase.actualEndDate,
      plannedDuration,
      actualDuration,
      isDelayed,
      delayDays,
      completionRate: phase.progress,
    };
  });

  return timeline;
};

// Get phase task distribution analytics
PhaseSchema.statics.getPhaseTaskAnalytics = async function (phaseId: string) {
  const Task = mongoose.models.Task;
  
  if (!Task) {
    throw new Error('Task model not available');
  }

  const taskAnalytics = await Task.aggregate([
    { 
      $match: { 
        phaseId: new mongoose.Types.ObjectId(phaseId),
        status: { $nin: ['deleted', 'cancelled'] }
      }
    },
    {
      $group: {
        _id: null,
        totalTasks: { $sum: 1 },
        completedTasks: {
          $sum: { $cond: [{ $eq: ["$status", "completed"] }, 1, 0] }
        },
        inProgressTasks: {
          $sum: { $cond: [{ $eq: ["$status", "in-progress"] }, 1, 0] }
        },
        pendingTasks: {
          $sum: { $cond: [{ $eq: ["$status", "pending"] }, 1, 0] }
        },
        blockedTasks: {
          $sum: { $cond: [{ $eq: ["$status", "blocked"] }, 1, 0] }
        },
        overdueTasks: {
          $sum: {
            $cond: [
              {
                $and: [
                  { $lt: ["$dueDate", new Date()] },
                  { $ne: ["$status", "completed"] }
                ]
              },
              1,
              0
            ]
          }
        },
        highPriorityTasks: {
          $sum: { $cond: [{ $eq: ["$priority", "high"] }, 1, 0] }
        }
      }
    }
  ]);

  const result = taskAnalytics[0] || {
    totalTasks: 0,
    completedTasks: 0,
    inProgressTasks: 0,
    pendingTasks: 0,
    blockedTasks: 0,
    overdueTasks: 0,
    highPriorityTasks: 0
  };

  result.taskCompletionRate = result.totalTasks > 0 
    ? Math.round((result.completedTasks / result.totalTasks) * 100)
    : 0;

  return result;
};

// Ensure virtual fields are serialized
PhaseSchema.set('toJSON', {
  virtuals: true,
  transform: function (doc, ret) {
    if (ret.__v !== undefined) {
      delete (ret as any).__v;
    }
    return ret;
  }
});

// Export the model with proper typing for static methods
export default (mongoose.models.Phase || mongoose.model<IPhase>("Phase", PhaseSchema)) as unknown as PhaseModel;