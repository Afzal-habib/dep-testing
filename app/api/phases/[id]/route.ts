import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery, clearCache } from "@/lib/mongodb"
import Phase from "@/models/Phase"
import User from "@/models/User"
import mongoose from "mongoose"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'

const CACHE_TTL = 2 * 60 * 1000; // 2 minutes

// Helper to create consistent error responses
function createErrorResponse(message: string, status: number, details?: any) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details && { details })
  }, { status })
}

// GET /api/phases/[id] - Get single phase by ID
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user: currentUser, userEmail } = await genericApiRoutesMiddleware(request, 'phases', 'read')

    const { id } = await params

    // Validate Object ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return createErrorResponse('Invalid phase ID', 400)
    }

    const phase = await executeGenericDbQuery(async () => {
      const phaseData = await Phase.findById(id)
        .populate('projectId', '_id name status')
        .populate('createdBy', '_id name email')
        .populate('updatedBy', '_id name email')
        .lean()
        .exec()

      if (!phaseData) {
        throw new Error('Phase not found')
      }
      return phaseData
    }, `phase-${id}`, CACHE_TTL) // Use built-in caching

    return NextResponse.json({
      success: true,
      data: phase
    })

  } catch (error: any) {
    console.error('Error in GET /api/phases/[id]:', error)
    return createErrorResponse('Internal server error', 500)
  }
}

// PUT /api/phases/[id] - Update phase
export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user: sessionUser, userEmail } = await genericApiRoutesMiddleware(request, 'phases', 'update')

    const { id } = await params

    // Validate Object ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return createErrorResponse('Invalid phase ID', 400)
    }

    const body = await request.json()

    // Basic validation
    const allowedFields = ['title', 'description', 'status', 'priority', 'startDate', 'endDate', 'progress', 'approvedBy', 'approvedAt', 'actualStartDate', 'actualEndDate'];
    const updateData: any = {};
    
    for (const field of allowedFields) {
      if (body[field] !== undefined) {
        updateData[field] = body[field];
      }
    }

    if (Object.keys(updateData).length === 0) {
      return createErrorResponse('No valid fields to update', 400)
    }

    // Get current user's role and existing phase data
    const [currentUser, existingPhase] = await Promise.all([
      executeGenericDbQuery(async () => {
        return await User.findOne({ email: userEmail }).populate('role').lean()
      }, `current-user-${userEmail}`, 60000), // 1-minute cache for current user
      
      executeGenericDbQuery(async () => {
        return await Phase.findById(id)
      }, `existing-phase-${id}`, 30000) // 30-second cache for existing phase
    ])

    if (!currentUser?.role) {
      return createErrorResponse('User or role not found', 403)
    }

    if (!existingPhase) {
      return createErrorResponse('Phase not found', 404)
    }

    const currentUserRole = currentUser.role as any

    // Check permissions - only creator, admin, or super_admin can update
    const canUpdate = currentUserRole.name === 'admin' || 
                     currentUserRole.name === 'super_admin' ||
                     currentUserRole === 'super_admin' ||
                     existingPhase.createdBy.toString() === currentUser._id

    if (!canUpdate) {
      return createErrorResponse('Insufficient permissions to update phase', 403)
    }

    // Update phase
    const updatedPhase = await executeGenericDbQuery(async () => {
      return await Phase.findByIdAndUpdate(
        id,
        {
          ...updateData,
          updatedAt: new Date(),
          updatedBy: currentUser._id
        },
        { new: true, runValidators: true }
      ).select('title description projectId status priority startDate endDate progress order createdBy createdAt updatedAt')
    })

    // Clear related caches
    clearCache(`phase-${id}`)
    clearCache(`phases`) // Clear any phase list caches

    return NextResponse.json({
      success: true,
      data: updatedPhase,
      message: 'Phase updated successfully'
    })

  } catch (error: any) {
    console.error('Error in PUT /api/phases/[id]:', error)
    return createErrorResponse('Internal server error', 500)
  }
}

// DELETE /api/phases/[id] - Delete phase
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user: sessionUser, userEmail } = await genericApiRoutesMiddleware(request, 'phases', 'delete')

    const { id } = await params

    // Validate Object ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return createErrorResponse('Invalid phase ID', 400)
    }

    // Get user permissions and target phase data
    const [currentUser, existingPhase] = await Promise.all([
      executeGenericDbQuery(async () => {
        return await User.findOne({ email: userEmail }).populate('role').lean()
      }, `current-user-${userEmail}`, 60000),
      
      executeGenericDbQuery(async () => {
        return await Phase.findById(id).lean()
      }, `phase-${id}`, 30000)
    ])

    if (!currentUser?.role) {
      return createErrorResponse('User or role not found', 403)
    }

    if (!existingPhase) {
      return createErrorResponse('Phase not found', 404)
    }

    // For now, allow super_admin and admin roles to delete phases, plus the creator
    const currentUserRole = currentUser.role as any
    const allowedRoles = ['super_admin', 'admin'];
    const canDelete = allowedRoles.includes(currentUserRole.name) ||  allowedRoles.includes(currentUserRole) || 
                     existingPhase.createdBy.toString() === currentUser._id

    if (!canDelete) {
      return createErrorResponse('Insufficient permissions', 403)
    }

    // Delete phase (or mark as inactive for soft delete)
    await executeGenericDbQuery(async () => {
      return await Phase.findByIdAndUpdate(id, { 
        isDeleted: true,
        deletedAt: new Date(),
        deletedBy: currentUser._id,
        updatedAt: new Date()
      })
    })

    // Clear related caches
    clearCache(`phase-${id}`)
    clearCache(`phases`)

    return NextResponse.json({
      success: true,
      message: 'Phase deleted successfully'
    })

  } catch (error: any) {
    console.error('Error in DELETE /api/phases/[id]:', error)
    return createErrorResponse('Internal server error', 500)
  }

}