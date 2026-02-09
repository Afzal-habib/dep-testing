import { NextRequest, NextResponse } from 'next/server'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import connectDB from '@/lib/mongodb'
import MessageAuditLog, { IMessageAuditLog } from '@/models/MessageAuditLog'
import User from '@/models/User'
import Role from '@/models/Role'
import { communicationLogger as logger } from '@/lib/logger'

/**
 * GET /api/communication/messages/audit-logs
 * 
 * Fetch message audit logs for compliance/investigation purposes
 * 
 * Query parameters:
 * - channel_id: Filter by specific channel
 * - message_id: Filter by specific message
 * - action: Filter by action type ('created', 'edited', 'trashed', 'restored', 'permanently_deleted')
 * - actor_id: Filter by actor
 * - start_date: Filter from date (ISO string)
 * - end_date: Filter to date (ISO string)
 * - limit: Number of records (default 50, max 100)
 * - offset: Pagination offset
 * 
 * Requires admin or appropriate compliance role
 */
export async function GET(request: NextRequest) {
  try {
    // Authenticate user using the middleware
    const { session, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'communication', 'read')
    
    if (!session?.user?.id) {
      return NextResponse.json(
        { success: false, error: 'Unauthorized' },
        { status: 401 }
      )
    }

    await connectDB()

    // Check if user has admin/compliance permissions
    const user = await User.findById(session.user.id).populate('role')
    if (!user) {
      return NextResponse.json(
        { success: false, error: 'User not found' },
        { status: 404 }
      )
    }

    // Check for admin role or audit_logs permission
    const userRole = user.role as any
    const isAdmin = isSuperAdmin || 
                    userRole?.name?.toLowerCase() === 'super admin' || 
                    userRole?.name?.toLowerCase() === 'admin'
    const hasAuditPermission = userRole?.permissions?.communication?.includes('audit_logs') ||
                               userRole?.permissions?.communication?.includes('manage') ||
                               userRole?.permissions?.all?.includes('*')

    if (!isAdmin && !hasAuditPermission) {
      return NextResponse.json(
        { success: false, error: 'Forbidden: Audit log access requires admin or compliance role' },
        { status: 403 }
      )
    }

    // Parse query parameters
    const searchParams = request.nextUrl.searchParams
    const channelId = searchParams.get('channel_id')
    const messageId = searchParams.get('message_id')
    const action = searchParams.get('action')
    const actorId = searchParams.get('actor_id')
    const startDate = searchParams.get('start_date')
    const endDate = searchParams.get('end_date')
    const limit = Math.min(parseInt(searchParams.get('limit') || '50'), 100)
    const offset = parseInt(searchParams.get('offset') || '0')
    const sortOrder = searchParams.get('sort') === 'asc' ? 1 : -1

    // Build query
    const query: Record<string, any> = {}

    if (channelId) {
      query.supabase_channel_id = channelId
    }

    if (messageId) {
      query.supabase_message_id = messageId
    }

    if (action) {
      // Support comma-separated actions
      const actions = action.split(',').map(a => a.trim())
      if (actions.length === 1) {
        query.action = actions[0]
      } else {
        query.action = { $in: actions }
      }
    }

    if (actorId) {
      query.actor_id = actorId
    }

    // Date range filtering
    if (startDate || endDate) {
      query.created_at = {}
      if (startDate) {
        query.created_at.$gte = new Date(startDate)
      }
      if (endDate) {
        query.created_at.$lte = new Date(endDate)
      }
    }

    // Execute query with pagination
    const [logs, total] = await Promise.all([
      MessageAuditLog.find(query)
        .sort({ created_at: sortOrder })
        .skip(offset)
        .limit(limit)
        .lean()
        .exec(),
      MessageAuditLog.countDocuments(query)
    ])

    // Get action statistics for the filter
    const actionStats = await MessageAuditLog.aggregate([
      { $match: channelId ? { supabase_channel_id: channelId } : {} },
      { $group: { _id: '$action', count: { $sum: 1 } } }
    ])

    const actionCounts = actionStats.reduce((acc, stat) => {
      acc[stat._id] = stat.count
      return acc
    }, {} as Record<string, number>)

    // Transform logs for response
    const transformedLogs = logs.map((log: any) => ({
      id: log._id.toString(),
      message_id: log.supabase_message_id,
      channel_id: log.supabase_channel_id,
      action: log.action,
      actor: {
        id: log.actor_id.toString(),
        name: log.actor_name,
        email: log.actor_email,
        role: log.actor_role
      },
      previous_content: log.previous_content,
      new_content: log.new_content,
      metadata: log.metadata || {},
      created_at: log.created_at
    }))

    return NextResponse.json({
      success: true,
      data: transformedLogs,
      pagination: {
        page: Math.floor(offset / limit) + 1,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        hasMore: offset + limit < total
      },
      stats: {
        actionCounts,
        totalLogs: total
      }
    })

  } catch (error: any) {
    logger.error('[Audit Log GET] Error:', error)
    return NextResponse.json(
      { 
        success: false, 
        error: error.message || 'Failed to fetch audit logs'
      },
      { status: 500 }
    )
  }
}

/**
 * GET action label for display
 */
function getActionLabel(action: string): string {
  const labels: Record<string, string> = {
    'created': 'Message Created',
    'edited': 'Message Edited',
    'trashed': 'Moved to Trash',
    'restored': 'Restored from Trash',
    'permanently_deleted': 'Permanently Deleted'
  }
  return labels[action] || action
}
