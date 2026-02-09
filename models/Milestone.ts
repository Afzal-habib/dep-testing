import mongoose, { Schema, type Document } from "mongoose";

// Interface for a single milestone document
export interface IMilestone extends Document {
  _id: string;
  title: string;
  description?: string;
  projectId: mongoose.Types.ObjectId;
  phaseId?: mongoose.Types.ObjectId;
  dueDate: Date;
  completedDate?: Date;
  status: 'pending' | 'in-progress' | 'completed' | 'overdue';
  priority: 'low' | 'medium' | 'high' | 'urgent';
  progress: number; // 0-100
  assigneeId?: mongoose.Types.ObjectId;
  linkedTaskIds: mongoose.Types.ObjectId[];
  deliverables: string[];
  successCriteria: string[];
  dependencies: mongoose.Types.ObjectId[]; // Other milestone IDs
  budgetAllocation?: number;
  actualCost?: number;
  isDeleted: boolean;
  deletedAt?: Date;
  deletedBy?: mongoose.Types.ObjectId;
  createdBy: mongoose.Types.ObjectId;
  updatedBy?: mongoose.Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
  
  // Instance methods
  calculateProgressFromTasks(): Promise<number>;
}

// Static methods interface
export interface MilestoneModel extends mongoose.Model<IMilestone> {
  findByProject(projectId: string): Promise<IMilestone[]>;
  findByPhase(phaseId: string): Promise<IMilestone[]>;
  calculateProjectProgress(projectId: string): Promise<number>;
  findOverdue(): Promise<IMilestone[]>;
  updateProjectMilestoneProgress(projectId: string): Promise<Array<{ milestoneId: string, progress: number }>>;
}

const MilestoneSchema = new Schema<IMilestone>({
  title: {
    type: String,
    required: [true, "Milestone title is required"],
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
  phaseId: {
    type: Schema.Types.ObjectId,
    ref: 'Phase',
    // index: true, // Removed - covered by compound indexes
  },
  dueDate: {
    type: Date,
    required: [true, "Due date is required"],
    // index: true, // Removed - covered by compound indexes
  },
  completedDate: {
    type: Date,
  },
  status: {
    type: String,
    enum: ['pending', 'in-progress', 'completed', 'overdue'],
    default: 'pending',
    // index: true, // Removed - covered by compound indexes
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'urgent'],
    default: 'medium',
    // index: true, // Removed - not used in compound indexes
  },
  progress: {
    type: Number,
    min: [0, "Progress cannot be negative"],
    max: [100, "Progress cannot exceed 100%"],
    default: 0,
  },
  assigneeId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    // index: true, // Removed - covered by compound indexes
  },
  linkedTaskIds: [{
    type: Schema.Types.ObjectId,
    ref: 'Task',
  }],
  deliverables: [{
    type: String,
    trim: true,
    maxlength: [500, "Deliverable description too long"]
  }],
  successCriteria: [{
    type: String,
    trim: true,
    maxlength: [500, "Success criteria description too long"]
  }],
  dependencies: [{
    type: Schema.Types.ObjectId,
    ref: 'Milestone',
  }],
  budgetAllocation: {
    type: Number,
    min: [0, "Budget allocation cannot be negative"],
  },
  actualCost: {
    type: Number,
    min: [0, "Actual cost cannot be negative"],
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

// Indexes for performance
MilestoneSchema.index({ projectId: 1, isDeleted: 1, status: 1 });
MilestoneSchema.index({ dueDate: 1, status: 1 });
MilestoneSchema.index({ phaseId: 1, isDeleted: 1 });
MilestoneSchema.index({ assigneeId: 1, status: 1 });
MilestoneSchema.index({ createdAt: -1 });

// Virtuals
MilestoneSchema.virtual('isOverdue').get(function () {
  return this.status !== 'completed' && this.dueDate < new Date();
});

MilestoneSchema.virtual('daysUntilDue').get(function () {
  const now = new Date();
  const due = new Date(this.dueDate);
  const diffTime = due.getTime() - now.getTime();
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
});

// Pre-save middleware
MilestoneSchema.pre('save', function (next) {
  // Auto-update status based on progress and due date
  if (this.progress === 100 && this.status !== 'completed') {
    this.status = 'completed';
    this.completedDate = new Date();
  } else if (this.progress > 0 && this.status === 'pending') {
    this.status = 'in-progress';
  } else if (this.status !== 'completed' && this.dueDate < new Date()) {
    this.status = 'overdue';
  }

  next();
});

// Static methods
MilestoneSchema.statics.findByProject = function (projectId: string) {
  return this.find({
    projectId,
    isDeleted: false
  })
    .populate('assigneeId', 'name email')
    .populate('phaseId', 'title')
    .sort({ dueDate: 1 });
};

MilestoneSchema.statics.findByPhase = function (phaseId: string) {
  return this.find({
    phaseId,
    isDeleted: false
  })
    .populate('assigneeId', 'name email')
    .sort({ dueDate: 1 });
};

MilestoneSchema.statics.calculateProjectProgress = async function (projectId: string) {
  const milestones = await this.find({
    projectId,
    isDeleted: false
  });

  if (milestones.length === 0) return 0;

  const totalProgress = milestones.reduce((sum: number, milestone: IMilestone) => sum + milestone.progress, 0);
  return Math.round(totalProgress / milestones.length);
};

MilestoneSchema.statics.findOverdue = function () {
  return this.find({
    isDeleted: false,
    status: { $nin: ['completed'] },
    dueDate: { $lt: new Date() }
  })
    .populate('projectId', 'name')
    .populate('assigneeId', 'name email');
};

// Calculate milestone progress based on linked tasks
MilestoneSchema.methods.calculateProgressFromTasks = async function () {
  const Task = mongoose.model('Task');
  
  // Get all tasks linked to this milestone
  const linkedTasks = await Task.find({
    milestoneId: this._id,
    status: { $nin: ['cancelled', 'deleted'] }
  }).select('status').lean();

  if (linkedTasks.length === 0) {
    // If no tasks are linked, keep manual progress
    return this.progress;
  }

  // Calculate automatic progress based on completed tasks
  const completedTasks = linkedTasks.filter(task => task.status === 'completed').length;
  const automaticProgress = Math.round((completedTasks / linkedTasks.length) * 100);

  // Update progress and status
  this.progress = automaticProgress;
  
  // Auto-update status based on progress
  if (automaticProgress === 100) {
    this.status = 'completed';
    if (!this.completedDate) {
      this.completedDate = new Date();
    }
  } else if (automaticProgress > 0) {
    this.status = 'in-progress';
  } else {
    this.status = 'pending';
  }

  // Check if overdue
  if (this.dueDate < new Date() && this.status !== 'completed') {
    this.status = 'overdue';
  }

  await this.save();
  return automaticProgress;
};

// Static method to update all milestone progress for a project
MilestoneSchema.statics.updateProjectMilestoneProgress = async function (projectId: string) {
  const milestones = await this.find({
    projectId,
    isDeleted: false
  });

  const results = [];
  for (const milestone of milestones) {
    const progress = await milestone.calculateProgressFromTasks();
    results.push({ milestoneId: milestone._id, progress });
  }

  return results;
};

// Ensure virtual fields are serialized
MilestoneSchema.set('toJSON', {
  virtuals: true,
  transform: function (doc, ret) {
    if (ret.__v !== undefined) {
      delete (ret as any).__v;
    }
    return ret;
  }
});

export default mongoose.models.Milestone || mongoose.model<IMilestone>("Milestone", MilestoneSchema);