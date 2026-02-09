import { NextRequest, NextResponse } from 'next/server';
import Comment from '@/models/Comment';
import Task from '@/models/Task';
import Project from '@/models/Project';
import { 
  commentQuerySchema, 
  createCommentSchema,
  extractMentions 
} from '@/lib/validations/comment';
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware';
import { executeGenericDbQuery } from '@/lib/mongodb';

// GET /api/comments - List comments with pagination and filtering
export async function GET(request: NextRequest) {
  try {
    // Security & Authentication
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'comments', 'read');

    const searchParams = request.nextUrl.searchParams;
    const queryParams = {
      taskId: searchParams.get('taskId') || '',
      projectId: searchParams.get('projectId') || '',
      authorId: searchParams.get('authorId') || '',
      page: searchParams.get('page') || '1',
      limit: searchParams.get('limit') || '20',
      sortBy: searchParams.get('sortBy') || 'createdAt',
      sortOrder: searchParams.get('sortOrder') || 'desc',
    };

    const validatedParams = commentQuerySchema.parse(queryParams);

    // Build MongoDB filter
    const filter: any = { isDeleted: false };
    
    if (validatedParams.taskId) {
      filter.taskId = validatedParams.taskId;
    }
    
    if (validatedParams.projectId) {
      filter.projectId = validatedParams.projectId;
    }
    
    if (validatedParams.authorId) {
      filter.authorId = validatedParams.authorId;
    }

    // Department-based filtering for non-admin users
    if (user.departmentId && !['support', 'admin'].includes(user.department?.name?.toLowerCase())) {
      // User can only see comments on tasks from their department projects
      // This requires joining with tasks and projects - we'll implement a more efficient query
      const userDepartmentTasks = await executeGenericDbQuery(async () => {
        return await Task.find({ departmentId: user.departmentId }).select('_id');
      }, `user-dept-tasks-${user.departmentId}`, 300000);
      
      const taskIds = userDepartmentTasks.map(task => task._id);
      filter.taskId = { $in: taskIds };
    }

    // Build sort
    const sort: any = {};
    sort[validatedParams.sortBy] = validatedParams.sortOrder === 'asc' ? 1 : -1;

    // Execute queries with caching
    const cacheKey = `comments-${JSON.stringify({ filter, sort, page: validatedParams.page, limit: validatedParams.limit })}`;
    
    const [comments, total] = await Promise.all([
      executeGenericDbQuery(async () => {
        return await Comment.find(filter)
          .populate('author', 'name email avatar role')
          .populate('mentionedUsers', 'name email')
          .populate({
            path: 'replies',
            match: { isDeleted: false },
            populate: {
              path: 'author',
              select: 'name email avatar role'
            },
            options: { sort: { createdAt: 1 } }
          })
          .sort(sort)
          .limit(validatedParams.limit)
          .skip((validatedParams.page - 1) * validatedParams.limit)
          .lean();
      }, cacheKey, 60000),

      executeGenericDbQuery(async () => {
        return await Comment.countDocuments(filter);
      }, `comments-count-${JSON.stringify(filter)}`, 60000),
    ]);

    return NextResponse.json({
      success: true,
      data: comments,
      pagination: {
        page: validatedParams.page,
        limit: validatedParams.limit,
        total,
        pages: Math.ceil(total / validatedParams.limit),
      },
      message: 'Comments retrieved successfully'
    });

  } catch (error: any) {
    console.error('Error fetching comments:', error);
    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to fetch comments'
    }, { status: 500 });
  }
}

// POST /api/comments - Create new comment
export async function POST(request: NextRequest) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'comments', 'create');

    const body = await request.json();
    
    // Validate request data
    const validatedData = createCommentSchema.parse(body);

    // Verify task and project exist and user has access
    const [task, project] = await Promise.all([
      executeGenericDbQuery(async () => {
        return await Task.findById(validatedData.taskId).populate('project');
      }, `task-${validatedData.taskId}`, 300000),
      
      executeGenericDbQuery(async () => {
        return await Project.findById(validatedData.projectId);
      }, `project-${validatedData.projectId}`, 300000)
    ]);

    if (!task) {
      return NextResponse.json({
        success: false,
        error: 'Task not found'
      }, { status: 404 });
    }

    if (!project) {
      return NextResponse.json({
        success: false,
        error: 'Project not found'
      }, { status: 404 });
    }

    // For now, all authenticated users can comment on tasks
    // Permissions will be added later manually

    // Extract mentions from content
    const mentions = extractMentions(validatedData.content);

    // Create comment
    const comment = await executeGenericDbQuery(async () => {
      return await Comment.create({
        ...validatedData,
        authorId: user.id,
        mentions,
      });
    }, undefined, 0); // No caching for create operations

    // Populate the created comment
    const populatedComment = await executeGenericDbQuery(async () => {
      return await Comment.findById(comment._id)
        .populate('author', 'name email avatar role')
        .populate('mentionedUsers', 'name email')
        .lean();
    }, `comment-${comment._id}`, 300000);

    return NextResponse.json({
      success: true,
      data: populatedComment,
      message: 'Comment created successfully'
    }, { status: 201 });

  } catch (error: any) {
    console.error('Error creating comment:', error);

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Validation failed',
        details: error.errors
      }, { status: 400 });
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to create comment'
    }, { status: 500 });
  }
}