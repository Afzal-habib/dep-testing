import { NextRequest, NextResponse } from 'next/server'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { NotificationService } from '@/lib/services/notification-service'

// POST /api/system-notifications/test - Test notification creation
export async function POST(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user } = await genericApiRoutesMiddleware(request, 'system-notifications', 'create')

    const body = await request.json()
    const { type, message, targetUserId } = body

    // Create a test notification
    await NotificationService.createNotification({
      type: type || 'project_created',
      category: 'project',
      recipientId: targetUserId || user.id,
      senderId: user.id,
      senderName: user.name,
      senderAvatar: user.avatar,
      title: 'Test Notification',
      message: message || 'This is a test notification from the system',
      contentPreview: 'Testing the notification system',
      entityType: 'project',
      entityId: user.id, // Just using user ID as dummy entity ID
      entityName: 'Test Project',
      actionType: 'created',
      actionUrl: '/dashboard',
      priority: 2,
      metadata: { source: 'test-api' }
    })

    return NextResponse.json({ 
      success: true,
      message: 'Test notification sent successfully'
    })

  } catch (error) {
    console.error('Error sending test notification:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}