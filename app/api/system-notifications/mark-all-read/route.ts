import { NextRequest, NextResponse } from 'next/server'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { NotificationService } from '@/lib/services/notification-service'

// POST /api/system-notifications/mark-all-read - Mark all notifications as read
export async function POST(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user } = await genericApiRoutesMiddleware(request, 'system-notifications', 'update')

    // Mark all notifications as read for the user
    await NotificationService.markAllAsRead(user.id)

    return NextResponse.json({ 
      success: true,
      message: 'All notifications marked as read'
    })

  } catch (error) {
    console.error('Error marking all notifications as read:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}