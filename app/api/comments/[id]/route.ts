import { NextRequest, NextResponse } from 'next/server';
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware';
import Comment from '@/models/Comment';
import { 
  commentIdSchema, 
  updateCommentSchema,
  extractMentions 
} from '@/lib/validations/comment';
import { executeGenericDbQuery } from '@/lib/mongodb';

interface RouteParams {
  params: Promise<{ id: string }>
}

// GET /api/comments/[id] - Get comment by ID
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'comments', 'read');
    
    const resolvedParams = await params;
    const validatedParams = commentIdSchema.parse({ id: resolvedParams.id });

    // Fetch comment with caching
    const comment = await executeGenericDbQuery(async () => {
      return await Comment.findOne({ _id: validatedParams.id, isDeleted: false })
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
        .lean();
    }, `comment-${validatedParams.id}`, 300000);

    if (!comment) {
      return NextResponse.json({
        success: false,
        error: 'Comment not found'
      }, { status: 404 });
    }

    return NextResponse.json({
      success: true,
      data: comment,
      message: 'Comment retrieved successfully'
    });

  } catch (error: any) {
    console.error('Error fetching comment:', error);

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid comment ID format',
        details: error.errors
      }, { status: 400 });
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to fetch comment'
    }, { status: 500 });
  }
}

// PUT /api/comments/[id] - Update comment
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'comments', 'update');
    
    const resolvedParams = await params;
    const validatedParams = commentIdSchema.parse({ id: resolvedParams.id });
    const body = await request.json();
    
    // Validate update data
    const validatedData = updateCommentSchema.parse(body);

    // Fetch existing comment
    const existingComment = await executeGenericDbQuery(async () => {
      return await Comment.findOne({ _id: validatedParams.id, isDeleted: false });
    }, `comment-${validatedParams.id}`, 0); // No cache for updates

    if (!existingComment) {
      return NextResponse.json({
        success: false,
        error: 'Comment not found'
      }, { status: 404 });
    }

    // For now, all authenticated users can edit any comments
    // Permissions will be added later manually

    // Extract mentions from updated content
    const mentions = extractMentions(validatedData.content);

    // Update comment
    const updatedComment = await executeGenericDbQuery(async () => {
      return await Comment.findByIdAndUpdate(
        validatedParams.id,
        {
          ...validatedData,
          mentions,
          isEdited: true,
          editedAt: new Date(),
        },
        { new: true, runValidators: true }
      ).populate('author', 'name email avatar role')
       .populate('mentionedUsers', 'name email')
       .lean();
    }, "", 0); // No caching for updates

    return NextResponse.json({
      success: true,
      data: updatedComment,
      message: 'Comment updated successfully'
    });

  } catch (error: any) {
    console.error('Error updating comment:', error);

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Validation failed',
        details: error.errors
      }, { status: 400 });
    }

    if (error.name === 'CastError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid comment ID'
      }, { status: 400 });
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to update comment'
    }, { status: 500 });
  }
}

// DELETE /api/comments/[id] - Soft delete comment
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'comments', 'delete');
    
    const resolvedParams = await params;
    const validatedParams = commentIdSchema.parse({ id: resolvedParams.id });

    // Fetch existing comment
    const existingComment = await executeGenericDbQuery(async () => {
      return await Comment.findOne({ _id: validatedParams.id, isDeleted: false });
    }, `comment-${validatedParams.id}`, 0); // No cache for deletes

    if (!existingComment) {
      return NextResponse.json({
        success: false,
        error: 'Comment not found'
      }, { status: 404 });
    }

    // For now, all authenticated users can delete any comments
    // Permissions will be added later manually

    // Soft delete comment and its replies
    await executeGenericDbQuery(async () => {
      // Delete the comment
      await Comment.findByIdAndUpdate(validatedParams.id, {
        isDeleted: true,
        deletedAt: new Date(),
        deletedBy: user.id,
      });

      // Also soft delete all replies
      await Comment.updateMany(
        { parentCommentId: validatedParams.id, isDeleted: false },
        {
          isDeleted: true,
          deletedAt: new Date(),
          deletedBy: user.id,
        }
      );
    }, "", 0); // No caching for deletes

    return NextResponse.json({
      success: true,
      message: 'Comment deleted successfully'
    });

  } catch (error: any) {
    console.error('Error deleting comment:', error);

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid comment ID format',
        details: error.errors
      }, { status: 400 });
    }

    if (error.name === 'CastError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid comment ID'
      }, { status: 400 });
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to delete comment'
    }, { status: 500 });
  }
}