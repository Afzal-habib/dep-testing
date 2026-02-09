import mongoose, { Schema, Document, Model } from "mongoose";

// Interface for a single comment document
export interface IComment extends Document {
  _id: string;
  content: string;
  taskId: mongoose.Types.ObjectId;
  projectId: mongoose.Types.ObjectId;
  authorId: mongoose.Types.ObjectId;
  mentions: mongoose.Types.ObjectId[]; // Array of mentioned user IDs
  parentCommentId?: mongoose.Types.ObjectId; // For replies/threading
  isEdited: boolean;
  editedAt?: Date;
  isDeleted: boolean;
  deletedAt?: Date;
  deletedBy?: mongoose.Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;

  // Virtual populated fields
  author?: any;
  mentionedUsers?: any[];
  replies?: IComment[];
  repliesCount?: number;
}

// Static methods interface
export interface CommentModel extends mongoose.Model<IComment> {
  findByTaskId(taskId: string): Promise<IComment[]>;
  findActiveComments(taskId: string): Promise<IComment[]>;
  createComment(data: any): Promise<IComment>;
  softDelete(id: string, deletedBy: string): Promise<IComment | null>;
}

const CommentSchema = new Schema<IComment>({
  content: {
    type: String,
    required: [true, "Comment content is required"],
    trim: true,
    maxlength: [2000, "Comment cannot exceed 2000 characters"],
    minlength: [1, "Comment cannot be empty"]
  },
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
  authorId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: [true, "Author is required"],
    // index: true, // Removed - covered by compound indexes
  },
  mentions: [{
    type: Schema.Types.ObjectId,
    ref: 'User',
  }],
  parentCommentId: {
    type: Schema.Types.ObjectId,
    ref: 'Comment',
    // index: true, // Removed - covered by compound indexes
    default: null,
  },
  isEdited: {
    type: Boolean,
    default: false,
  },
  editedAt: {
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
CommentSchema.index({ taskId: 1, isDeleted: 1, createdAt: -1 });
CommentSchema.index({ projectId: 1, isDeleted: 1 });
CommentSchema.index({ authorId: 1, createdAt: -1 });
CommentSchema.index({ mentions: 1, isDeleted: 1 });
CommentSchema.index({ parentCommentId: 1, isDeleted: 1 });

// Virtual for author population
CommentSchema.virtual('author', {
  ref: 'User',
  localField: 'authorId',
  foreignField: '_id',
  justOne: true,
});

// Virtual for mentioned users population
CommentSchema.virtual('mentionedUsers', {
  ref: 'User',
  localField: 'mentions',
  foreignField: '_id',
});

// Virtual for replies (comments with this comment as parent)
CommentSchema.virtual('replies', {
  ref: 'Comment',
  localField: '_id',
  foreignField: 'parentCommentId',
});

// Virtual for replies count
CommentSchema.virtual('repliesCount', {
  ref: 'Comment',
  localField: '_id',
  foreignField: 'parentCommentId',
  count: true,
});

// Static methods
CommentSchema.statics.findByTaskId = async function (taskId: string) {
  return this.find({ taskId, isDeleted: false })
    .populate('author', 'name email avatar')
    .populate('mentionedUsers', 'name email')
    .sort({ createdAt: -1 });
};

CommentSchema.statics.findActiveComments = async function (taskId: string) {
  return this.find({ taskId, isDeleted: false, parentCommentId: null })
    .populate('author', 'name email avatar')
    .populate('mentionedUsers', 'name email')
    .populate({
      path: 'replies',
      match: { isDeleted: false },
      populate: {
        path: 'author',
        select: 'name email avatar'
      },
      options: { sort: { createdAt: 1 } }
    })
    .sort({ createdAt: -1 });
};

CommentSchema.statics.createComment = async function (data: any) {
  const comment = new this(data);
  return comment.save();
};

CommentSchema.statics.softDelete = async function (id: string, deletedBy: string) {
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

// Pre-save middleware to handle mentions extraction
CommentSchema.pre('save', function (next) {
  if (this.isModified('content')) {
    // Extract mentions from content (@username or @user_id)
    const mentionRegex = /@(\w+)/g;
    const mentions = [...this.content.matchAll(mentionRegex)];

    // This is simplified - in a real implementation, you'd resolve usernames to IDs
    // For now, we'll handle mentions in the frontend and pass the IDs directly

    if (this.isModified('content') && !this.isNew) {
      this.isEdited = true;
      this.editedAt = new Date();
    }
  }
  next();
});

// Ensure virtual fields are serialized
CommentSchema.set('toJSON', {
  virtuals: true,
  transform: function (doc, ret) {
    if (ret.__v !== undefined) {
      delete (ret as any).__v;
    }
    return ret;
  }
});

export default mongoose.models.Comment || mongoose.model<IComment>("Comment", CommentSchema);