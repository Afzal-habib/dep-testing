import { type NextRequest, NextResponse } from "next/server"
import { executeGenericDbQuery, clearCache } from "@/lib/mongodb"
import User from "@/models/User"
import Lead from "@/models/Lead"
import { updateClientSchema, clientIdSchema, clientStatusUpdateSchema } from "@/lib/validations/client"
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { performSoftDelete, addSoftDeleteFilter } from "@/lib/utils/soft-delete"
import { createErrorResponse } from "@/lib/security/error-handler"

interface RouteParams {
  params: Promise<{ id: string }>
}

// GET /api/clients/[id] - Get client by ID
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'clients', 'read')

    const resolvedParams = await params
    const validatedParams = clientIdSchema.parse({ id: resolvedParams.id })
    console.log("clientId18", validatedParams.id);
    // Fetch client with caching
    const client = await executeGenericDbQuery(async () => {
      // Apply soft delete filter - only super admins can see deleted clients
      const filter = addSoftDeleteFilter({
        _id: validatedParams.id,
        isClient: true
      }, isSuperAdmin)

      const foundClient = await User.findOne(filter)
        .populate('role', 'name permissions')
        .populate('department', 'name')
        .populate('leadId', 'name projectName status createdAt createdBy')
        .select('-password -resetPasswordToken -resetPasswordExpire')
        .lean()
      console.log("client filter used:", JSON.stringify(filter, null, 2));
      console.log("foundClient30", foundClient);
      if (!foundClient) {
        throw new Error('Client not found')
      }

      // Check permissions - department-based access control
      if (!isSuperAdmin) {
        const currentUser = await User.findById(user._id).populate('department', 'name')
        const deptName = (currentUser?.department as any)?.name?.toLowerCase()

        // Sales and support can see all clients, others may have restrictions
        if (!['sales', 'support'].includes(deptName || '')) {
          // Add department-specific access rules here if needed
          // For now, allow access but you can restrict further based on business rules
        }
      }

      return foundClient
    }, `client-${validatedParams.id}-${isSuperAdmin ? 'admin' : 'user'}`, 60000) // 1-minute cache

    return NextResponse.json({
      success: true,
      data: client,
      message: 'Client retrieved successfully'
    })

  } catch (error: any) {
    console.error('Error fetching client:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid client ID format',
        details: error.errors
      }, { status: 400 })
    }

    if (error.message === 'Client not found') {
      return NextResponse.json({
        success: false,
        error: 'Client not found'
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
      error: error.message || 'Failed to fetch client'
    }, { status: 500 })
  }
}

// PUT /api/clients/[id] - Update client
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'clients', 'update')

    const resolvedParams = await params
    const validatedParams = clientIdSchema.parse({ id: resolvedParams.id })
    const body = await request.json()

    // Check if this is a status update (which has special logic)
    if ((body.clientStatus || body.status) && Object.keys(body).filter(k => k !== 'reason').length <= 2) {
      return await handleClientStatusUpdate(validatedParams.id, body, user, isSuperAdmin || false)
    }

    const validatedData = updateClientSchema.parse(body)

    // Prevent setting status to 'deleted' through update (use DELETE endpoint)
    if (validatedData.status === 'deleted') {
      return NextResponse.json({
        success: false,
        error: 'Cannot set status to deleted through update. Use DELETE endpoint instead.'
      }, { status: 400 })
    }

    // Update client with automatic connection management
    const updatedClient = await executeGenericDbQuery(async () => {
      // Find the existing client (apply soft delete filter - prevent updates on deleted records unless super admin)
      const filter = addSoftDeleteFilter({
        _id: validatedParams.id,
        isClient: true
      }, isSuperAdmin)

      console.log("client filter for update:", JSON.stringify(filter, null, 2));
      const existingClient = await User.findOne(filter)

      if (!existingClient) {
        throw new Error('Client not found or has been deleted')
      }

      // Check if client is deleted
      if (!isSuperAdmin && (existingClient.status === 'deleted' || existingClient.isDeleted === true)) {
        throw new Error('Cannot update Deleted entity')
      }

      // Check permissions
      if (!isSuperAdmin) {
        const currentUser = await User.findById(user._id).populate('department', 'name')
        const deptName = (currentUser?.department as any)?.name?.toLowerCase()

        // Sales and support can update clients, others may have restrictions
        if (!['sales', 'support'].includes(deptName || '')) {
          throw new Error('Access denied. Only sales and support can update clients.')
        }
      }

      // Handle password update if provided
      if (validatedData.password) {
        // The password will be automatically hashed by the pre-save hook
        existingClient.password = validatedData.password
        existingClient.passwordChangedAt = new Date()
        delete validatedData.password // Remove from direct assignment
      }

      // Update other fields
      Object.assign(existingClient, validatedData)

      return await existingClient.save()
    })

    // Clear relevant cache patterns after update
    clearCache('clients')
    clearCache(`client-${validatedParams.id}`)

    // Return updated client with populated fields
    const populatedClient = await executeGenericDbQuery(async () => {
      return await User.findById(updatedClient._id)
        .populate('role', 'name')
        .populate('department', 'name')
        .populate('leadId', 'name projectName status createdAt')
        .select('-password -resetPasswordToken -resetPasswordExpire')
        .lean()
    })

    return NextResponse.json({
      success: true,
      data: populatedClient,
      message: 'Client updated successfully'
    })

  } catch (error: any) {
    console.error('Error updating client:', error)

    if (error.message === 'Cannot update Deleted entity') {
      return NextResponse.json({
        success: false,
        error: error.message
      }, { status: 400 })
    }

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid client data',
        details: error.errors
      }, { status: 400 })
    }

    if (error.message === 'Client not found') {
      return NextResponse.json({
        success: false,
        error: 'Client not found'
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
      error: error.message || 'Failed to update client'
    }, { status: 500 })
  }
}

// DELETE /api/clients/[id] - Soft delete client
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'clients', 'delete')

    const resolvedParams = await params
    const validatedParams = clientIdSchema.parse({ id: resolvedParams.id })

    // Check if client exists (exclude already deleted clients)
    const existingClient = await executeGenericDbQuery(async () => {
      const filter = addSoftDeleteFilter({
        _id: validatedParams.id,
        isClient: true
      }, false) // Don't include deleted for validation
      return await User.findOne(filter)
    })

    if (!existingClient) {
      return NextResponse.json({
        success: false,
        error: 'Client not found or already deleted'
      }, { status: 404 })
    }

    // Check permissions
    if (!isSuperAdmin) {
      const currentUser = await User.findById(user._id).populate('department', 'name')
      const deptName = (currentUser?.department as any)?.name?.toLowerCase()

      // Only support can delete clients (business rule)
      if (deptName !== 'support') {
        return NextResponse.json({
          success: false,
          error: 'Access denied. Only support department can delete clients.'
        }, { status: 403 })
      }
    }

    // Perform soft delete using the generic utility
    const deleteResult = await performSoftDelete('user', validatedParams.id, userEmail)

    if (!deleteResult.success) {
      return NextResponse.json({
        success: false,
        error: deleteResult.message
      }, { status: 400 })
    }

    return NextResponse.json({
      success: true,
      message: deleteResult.message,
      data: deleteResult.data
    })

  } catch (error: any) {
    console.error('Error deleting client:', error)

    if (error.name === 'ZodError') {
      return NextResponse.json({
        success: false,
        error: 'Invalid client ID format',
        details: error.errors
      }, { status: 400 })
    }

    return NextResponse.json({
      success: false,
      error: error.message || 'Failed to delete client'
    }, { status: 500 })
  }
}

// Helper function to handle client status updates with lead synchronization
async function handleClientStatusUpdate(clientId: string, statusData: any, user: any, isSuperAdmin: boolean) {
  try {
    // Build status update object
    const updateData: any = {}

    if (statusData.clientStatus) {
      updateData.clientStatus = statusData.clientStatus
    }

    if (statusData.status) {
      updateData.status = statusData.status
    }

    if (statusData.reason) {
      updateData.reason = statusData.reason
    }

    const validatedStatusData = clientStatusUpdateSchema.parse(updateData)

    const result = await executeGenericDbQuery(async () => {
      // Apply soft delete filter to prevent status updates on deleted clients
      const filter = addSoftDeleteFilter({
        _id: clientId,
        isClient: true
      }, isSuperAdmin)

      const existingClient = await User.findOne(filter).populate('leadId')

      if (!existingClient) {
        throw new Error('Client not found or has been deleted')
      }

      // Check permissions
      if (!isSuperAdmin) {
        const currentUser = await User.findById(user._id).populate('department', 'name')
        const deptName = (currentUser?.department as any)?.name?.toLowerCase()

        if (!['sales', 'support'].includes(deptName || '')) {
          throw new Error('Access denied. Only sales and support can update client status.')
        }
      }

      const originalClientStatus = existingClient.clientStatus

      // Handle unqualification - sync with lead
      if (validatedStatusData.clientStatus === 'unqualified' && originalClientStatus !== 'unqualified') {
        // Update client status
        await existingClient.unqualifyClient(validatedStatusData.reason)

        // Sync with linked lead if exists
        if (existingClient.leadId) {
          const linkedLead = await Lead.findById(existingClient.leadId)
          if (linkedLead && linkedLead.status === 'qualified') {
            linkedLead.status = 'unqualified'
            linkedLead.unqualifiedReason = validatedStatusData.reason || 'Client unqualified'
            linkedLead.unqualifiedAt = new Date()
            await linkedLead.save()

            // TODO: Send notification to sales team about unqualification
            console.log(`Notification: Client ${existingClient.name} unqualified. Reason: ${validatedStatusData.reason}`)
          }
        }
      } else {
        // Regular status update
        if (validatedStatusData.clientStatus) {
          existingClient.clientStatus = validatedStatusData.clientStatus
        }
        if (validatedStatusData.status) {
          existingClient.status = validatedStatusData.status
        }

        await existingClient.save()
      }

      // Return client with populated data
      return await User.findById(existingClient._id)
        .populate('role', 'name')
        .populate('department', 'name')
        .populate('leadId', 'name projectName status createdAt')
        .select('-password -resetPasswordToken -resetPasswordExpire')
        .lean()
    })

    // Clear cache
    clearCache('clients')
    clearCache(`client-${clientId}`)
    clearCache('leads') // Also clear leads cache due to sync

    return NextResponse.json({
      success: true,
      data: result,
      message: validatedStatusData.clientStatus === 'unqualified'
        ? 'Client unqualified and lead status synchronized'
        : `Client status updated to ${validatedStatusData.clientStatus || validatedStatusData.status}`,
    })

  } catch (error: any) {
    console.error('Error updating client status:', error)
    throw error // Re-throw to be handled by the main PUT handler
  }
}