import { NextRequest, NextResponse } from 'next/server'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { NotificationService } from '@/lib/services/notification-service'
import { 
  notificationQuerySchema,
  systemNotificationResponseSchema 
} from '@/lib/validations/system-notification'
import { z } from 'zod'

// GET /api/system-notifications - Get user notifications with pagination
export async function GET(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user } = await genericApiRoutesMiddleware(request, 'system-notifications', 'read')

    const { searchParams } = new URL(request.url)
    
    // Parse and validate query parameters
    const queryParams = {
      limit: searchParams.get('limit') ? parseInt(searchParams.get('limit')!) : 20,
      offset: searchParams.get('offset') ? parseInt(searchParams.get('offset')!) : 0,
      unreadOnly: searchParams.get('unreadOnly') === 'true',
      category: searchParams.get('category') || undefined
    }

    const validatedParams = notificationQuerySchema.parse(queryParams)

    // Get notifications
    const notifications = await NotificationService.getUserNotifications(
      user.id,
      {
        limit: validatedParams.limit,
        offset: validatedParams.offset,
        unreadOnly: validatedParams.unreadOnly
      }
    )

    // Transform to response format
    const transformedNotifications = notifications.map(notification => ({
      id: notification._id.toString(),
      type: notification.type,
      category: notification.category,
      title: notification.title,
      message: notification.message,
      contentPreview: notification.contentPreview,
      entityType: notification.entityType,
      entityId: notification.entityId.toString(),
      entityName: notification.entityName,
      actionType: notification.actionType,
      actionUrl: notification.actionUrl,
      senderName: notification.senderName,
      senderAvatar: notification.senderAvatar,
      priority: notification.priority,
      isRead: notification.isRead,
      readAt: notification.readAt?.toISOString(),
      createdAt: notification.createdAt.toISOString(),
      metadata: notification.metadata
    }))

    return NextResponse.json({
      notifications: transformedNotifications,
      hasMore: notifications.length === validatedParams.limit,
      pagination: {
        limit: validatedParams.limit,
        offset: validatedParams.offset
      }
    })

  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Invalid parameters', details: error.errors },
        { status: 400 }
      )
    }

    console.error('Error fetching system notifications:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}