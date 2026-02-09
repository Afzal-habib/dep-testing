import { type NextRequest, NextResponse } from "next/server"
import mongoose from "mongoose"
import { executeGenericDbQuery, clearCache } from "@/lib/mongodb"
import Lead from "@/models/Lead"
import User from "@/models/User"
import { updateLeadSchema, leadIdSchema, leadStatusUpdateSchema } from "@/lib/validations/lead"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { performSoftDelete, addSoftDeleteFilter } from "@/lib/utils/soft-delete"
import { createErrorResponse } from "@/lib/security/error-handler"

interface RouteParams {
  params: Promise<{ id: string }>
}

// GET /api/leads/[id] - Get lead by ID
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'leads', 'read')

    const resolvedParams = await params
    const validatedParams = leadIdSchema.parse({ id: resolvedParams.id })

    // Fetch lead with caching and soft delete filtering
    const lead = await executeGenericDbQuery(async () => {
      // Apply soft delete filter - only super admins can see deleted leads
      const filter = addSoftDeleteFilter({
        _id: validatedParams.id
      }, isSuperAdmin)

      const foundLead = await Lead.findOne(filter)
        .populate('createdBy', 'name email department')
        .populate('clientId', 'name email')
        .populate('qualifiedBy', 'name email')
        .lean()

      if (!foundLead) {
        throw new Error('Lead not found')
      }

      // Check permissions - sales agents can only access their own leads
      if (!isSuperAdmin) {
        const salesUser = await User.findById(user._id).populate('department', 'name')

        const deptName = (salesUser?.department as any)?.name?.toLowerCase()
        if (deptName !== 'sales') {
          throw new Error('Access denied. Only sales department members can access leads.')
        }

        if (foundLead.createdBy._id.toString() !== user._id.toString()) {
          throw new Error('Access denied. You can only access leads you created.')
        }
      }

      return foundLead
    }, `lead-${validatedParams.id}`, 60000) // 1-minute cache

    return NextResponse.json({
      success: true,
      data: lead,
      message: 'Lead retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error fetching lead:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid lead ID format',
        details: error.errors
      }, { status: 400 })
    }

    if (error.message === 'Lead not found') {
      return NextResponse.json({
        success: false,
        error: 'Lead not found'
      }, { status: 404 })
    }

    if (error.message.includes('Access denied')) {
      return NextResponse.json({
        success: false,
        error: error.message
      }, { status: 403 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to fetch lead'
    }, { status: 500 })
  }
}

// PUT /api/leads/[id] - Update lead
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'leads', 'update')

    const resolvedParams = await params
    const validatedParams = leadIdSchema.parse({ id: resolvedParams.id })
    const body = await request.json()

    // Check if this is a status update (which has special logic)
    if (body.status && Object.keys(body).length === 1) {
      return await handleStatusUpdate(validatedParams.id, body, user, isSuperAdmin || false)
    }

    const validatedData = updateLeadSchema.parse(body)

    // Update lead with automatic connection management
    const updatedLead = await executeGenericDbQuery(async () => {
      // Find the existing lead with soft delete filtering
      const filter = addSoftDeleteFilter({
        _id: validatedParams.id
      }, isSuperAdmin)

      const existingLead = await Lead.findOne(filter)

      if (!existingLead) {
        throw new Error('Lead not found or has been deleted')
      }

      // Check if lead is deleted
      if (!isSuperAdmin && (existingLead.status === 'deleted' || existingLead.isDeleted === true)) {
        throw new Error('Cannot update Deleted entity')
      }

      // Check permissions - sales agents can only update their own leads
      if (!isSuperAdmin) {
        const salesUser = await User.findById(user._id).populate('department', 'name')

        const deptName = (salesUser?.department as any)?.name?.toLowerCase()
        if (deptName !== 'sales') {
          throw new Error('Access denied. Only sales department members can update leads.')
        }

        if (existingLead.createdBy.toString() !== user._id.toString()) {
          throw new Error('Access denied. You can only update leads you created.')
        }
      }

      // Check email uniqueness if email is being changed
      if (validatedData.email && validatedData.email !== existingLead.email) {
        // Ensure the new email is not already used by another lead
        const existingEmailLead = await Lead.findOne({
          email: { $regex: new RegExp(`^${validatedData.email}$`, 'i') },
          _id: { $ne: validatedParams.id }
        })

        if (existingEmailLead) {
          throw new Error('A lead with this email already exists')
        }

        // Also ensure the new email is not used by any registered user
        const existingEmailUser = await User.findOne({
          email: { $regex: new RegExp(`^${validatedData.email}$`, 'i') }
        })

        if (existingEmailUser) {
          throw new Error('A user with this email already exists')
        }
      }

      // Update the lead
      Object.assign(existingLead, validatedData)

      return await existingLead.save()
    })

    // Clear relevant cache patterns after update
    clearCache('leads')
    clearCache(`lead-${validatedParams.id}`)

    // Return updated lead with populated fields
    const populatedLead = await executeGenericDbQuery(async () => {
      return await Lead.findById(updatedLead._id)
        .populate('createdBy', 'name email')
        .populate('clientId', 'name email')
        .populate('qualifiedBy', 'name email')
        .lean()
    })

    return NextResponse.json({
      success: true,
      data: populatedLead,
      message: 'Lead updated successfully'
    })

  } catch (error: any) {
    console.error('Error updating lead:', error)

    if (error.message === 'Cannot update Deleted entity') {
      return NextResponse.json({
        success: false,
        error: error.message
      }, { status: 400 })
    }

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid lead data',
        details: error.errors
      }, { status: 400 })
    }

    if (error.message === 'Lead not found') {
      return NextResponse.json({
        success: false,
        error: 'Lead not found'
      }, { status: 404 })
    }

    if (error.message.includes('Access denied')) {
      return NextResponse.json({
        success: false,
        error: error.message
      }, { status: 403 })
    }

    if (error.message.includes('already exists')) {
      return NextResponse.json({
        success: false,
        error: error.message
      }, { status: 409 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to update lead'
    }, { status: 500 })
  }
}

// DELETE /api/leads/[id] - Soft delete lead
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'leads', 'delete')

    const resolvedParams = (await params) as { id: string }
    const validatedParams = leadIdSchema.parse({ id: resolvedParams.id })

    // Check permissions and business rules before deletion
    await executeGenericDbQuery(async () => {
      const existingLead = await Lead.findById(validatedParams.id)

      if (!existingLead) {
        throw new Error('Lead not found')
      }

      // Check permissions - sales agents can only delete their own leads
      if (!isSuperAdmin) {
        const salesUser = await User.findById(user._id).populate('department', 'name')

        const deptName = (salesUser?.department as any)?.name?.toLowerCase()
        if (deptName !== 'sales') {
          throw new Error('Access denied. Only sales department members can delete leads.')
        }

        if (existingLead.createdBy.toString() !== user._id.toString()) {
          throw new Error('Access denied. You can only delete leads you created.')
        }
      }

      // Cannot delete qualified leads that have active clients
      if (existingLead.status === 'qualified' && existingLead.clientId) {
        // Check if client still exists and is active
        const clientExists = await User.findOne({
          _id: existingLead.clientId,
          isClient: true,
          status: { $ne: 'deleted' }
        })

        if (clientExists) {
          throw new Error('Cannot delete qualified lead: an active client is linked to this lead. Delete the client first.')
        }
      }

      return existingLead
    })

    // Use generic soft delete utility
    const deleteResult = await performSoftDelete('lead', validatedParams.id, userEmail)

    if (!deleteResult.success) {
      return createErrorResponse(deleteResult.message, 400)
    }

    return NextResponse.json({
      success: true,
      data: deleteResult.data,
      message: deleteResult.message
    })

  } catch (error: any) {
    console.error('Error deleting lead:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid lead ID format',
        details: error.errors
      }, { status: 400 })
    }

    if (error.message === 'Lead not found') {
      return NextResponse.json({
        success: false,
        error: 'Lead not found'
      }, { status: 404 })
    }

    if (error.message.includes('Access denied') || error.message.includes('Cannot delete')) {
      return NextResponse.json({
        success: false,
        error: error.message
      }, { status: 403 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to delete lead'
    }, { status: 500 })
  }
}

// Helper function to handle status updates with special logic
async function handleStatusUpdate(leadId: string, statusData: any, user: any, isSuperAdmin: boolean) {
  try {
    const validatedStatusData = leadStatusUpdateSchema.parse(statusData)

    const result = await executeGenericDbQuery(async () => {
      // Apply soft delete filter - prevent status updates on deleted leads unless super admin
      const filter = addSoftDeleteFilter({
        _id: leadId
      }, isSuperAdmin)

      const existingLead = await Lead.findOne(filter)

      if (!existingLead) {
        throw new Error('Lead not found or has been deleted')
      }

      // Check if lead is deleted
      if (existingLead.status === 'deleted' || existingLead.isDeleted === true) {
        throw new Error('Cannot update Deleted entity')
      }

      // Check permissions
      if (!isSuperAdmin) {
        const salesUser = await User.findById(user._id).populate('department', 'name')

        const deptName = (salesUser?.department as any)?.name?.toLowerCase()
        if (deptName !== 'sales') {
          throw new Error('Access denied. Only sales department members can update lead status.')
        }

        if (existingLead.createdBy.toString() !== user._id.toString()) {
          throw new Error('Access denied. You can only update leads you created.')
        }
      }

      // Validate status transition
      const transitionCheck = existingLead.canTransitionTo(validatedStatusData.status)
      if (!transitionCheck.allowed) {
        throw new Error(transitionCheck.reason || 'Invalid status transition')
      }

      const originalStatus = existingLead.status

      // Handle qualification - create client user
      if (validatedStatusData.status === 'qualified' && originalStatus !== 'qualified') {
        // Find client role
        const clientRole = await User.findOne({ 'role.name': /^client$/i }).populate('role')
        if (!clientRole) {
          throw new Error('Client role not found. Please create a client role first.')
        }

        // Create client user from lead data
        const clientUser = await User.createClientFromLead(existingLead, user._id)

        // Update lead with client reference
        existingLead.clientId = clientUser._id as mongoose.Types.ObjectId
        existingLead.qualifiedBy = user._id
        existingLead.qualifiedAt = new Date()
      }

      // Handle unqualification
      if (validatedStatusData.status === 'unqualified') {
        existingLead.unqualifiedReason = validatedStatusData.reason
        existingLead.unqualifiedAt = new Date()

        // If there's a linked client, update their status too
        if (existingLead.clientId) {
          const client = await User.findById(existingLead.clientId)
          if (client) {
            await client.unqualifyClient(validatedStatusData.reason)
          }
        }
      }

      // Update status
      existingLead.status = validatedStatusData.status

      await existingLead.save()

      // Return lead with populated data for qualification
      return await Lead.findById(existingLead._id)
        .populate('createdBy', 'name email')
        .populate('clientId', 'name email')
        .populate('qualifiedBy', 'name email')
        .lean()
    })

    // Clear cache
    clearCache('leads')
    clearCache(`lead-${leadId}`)
    if (result && result.clientId) {
      clearCache('clients')
    }

    return NextResponse.json({
      success: true,
      data: result,
      message: validatedStatusData.status === 'qualified'
        ? 'Lead qualified and client created successfully'
        : `Lead status updated to ${validatedStatusData.status}`,
      ...(validatedStatusData.status === 'qualified' && result && result.clientId && {
        clientId: (result.clientId as any)._id,
        redirectTo: `/clients/edit/${(result.clientId as any)._id}`
      })
    })

  } catch (error: any) {
    console.error('Error updating lead status:', error)
    throw error // Re-throw to be handled by the main PUT handler
  }
}