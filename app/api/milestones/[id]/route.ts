import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery, clearCache } from "@/lib/mongodb"
import Milestone from "@/models/Milestone"
import mongoose from "mongoose"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { 
  milestoneIdSchema,
  updateMilestoneSchema, 
} from '@/lib/validations/milestone'

const CACHE_TTL = 2 * 60 * 1000; // 2 minutes

// Helper to create consistent error responses
function createErrorResponse(message: string, status: number, details?: any) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details && { details })
  }, { status })
}

// GET /api/milestones/[id] - Get single milestone by ID
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user: currentUser, userEmail } = await genericApiRoutesMiddleware(request, 'milestones', 'read')

    const { id } = await params

    // Validate Object ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return createErrorResponse('Invalid milestone ID', 400)
    }

    const milestone = await executeGenericDbQuery(async () => {
      const milestoneData = await Milestone.findById(id)
        .populate('projectId', '_id name status')
        .populate('phaseId', '_id title order')
        .populate('assigneeId', '_id name email avatar')
        .populate('createdBy', '_id name email')
        .populate('updatedBy', '_id name email')
        .lean()
        .exec()

      if (!milestoneData) {
        throw new Error('Milestone not found')
      }
      return milestoneData
    }, `milestone-${id}`, CACHE_TTL) // Use built-in caching

    return NextResponse.json({
      success: true,
      data: milestone
    })

  } catch (error: any) {
    console.error('Error fetching milestone:', error);

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid milestone ID',
        details: error.errors
      }, { status: 400 });
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to fetch milestone'
    }, { status: 500 });
  }
}

// PUT /api/milestones/[id] - Update milestone
export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user: sessionUser, userEmail } = await genericApiRoutesMiddleware(request, 'milestones', 'update')

    const { id } = await params

    // Validate Object ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return createErrorResponse('Invalid milestone ID', 400)
    }

    const body = await request.json()

    // Basic validation
    const allowedFields = ['title', 'description', 'status', 'priority', 'dueDate', 'progress', 'assigneeId'];
    const updateData: any = {};
    
    for (const field of allowedFields) {
      if (body[field] !== undefined) {
        updateData[field] = body[field];
      }
    }

    if (Object.keys(updateData).length === 0) {
      return createErrorResponse('No valid fields to update', 400)
    }

    // Update milestone
    const updatedMilestone = await executeGenericDbQuery(async () => {
      return await Milestone.findByIdAndUpdate(
        id,
        {
          ...updateData,
          updatedAt: new Date(),
          updatedBy: sessionUser._id || sessionUser.id,
        },
        { new: true, runValidators: true }
      ).select('title description projectId phaseId dueDate status priority assigneeId progress createdAt updatedAt')
    })

    // Clear related caches
    clearCache(`milestone-${id}`)
    clearCache(`milestones`)

    return NextResponse.json({
      success: true,
      data: updatedMilestone,
      message: 'Milestone updated successfully'
    })

  } catch (error: any) {
    console.error('Error in PUT /api/milestones/[id]:', error)
    return createErrorResponse('Internal server error', 500)
  }
}

// DELETE /api/milestones/[id] - Soft delete milestone
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user: sessionUser, userEmail } = await genericApiRoutesMiddleware(request, 'milestones', 'delete')

    const { id } = await params

    // Validate Object ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return createErrorResponse('Invalid milestone ID', 400)
    }

    // Delete milestone (soft delete)
    await executeGenericDbQuery(async () => {
      return await Milestone.findByIdAndUpdate(id, { 
        isDeleted: true,
        deletedAt: new Date(),
        updatedBy: sessionUser._id || sessionUser.id,
        updatedAt: new Date()
      })
    })

    // Clear related caches
    clearCache(`milestone-${id}`)
    clearCache(`milestones`)

    return NextResponse.json({
      success: true,
      message: 'Milestone deleted successfully'
    })

  } catch (error: any) {
    console.error('Error in DELETE /api/milestones/[id]:', error)
    return createErrorResponse('Internal server error', 500)
  }
}