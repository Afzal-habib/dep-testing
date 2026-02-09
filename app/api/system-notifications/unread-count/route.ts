import { NextRequest, NextResponse } from 'next/server'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { NotificationService } from '@/lib/services/notification-service'

// GET /api/system-notifications/unread-count - Get unread notification count
export async function GET(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user } = await genericApiRoutesMiddleware(request, 'system-notifications', 'read')

    const count = await NotificationService.getUnreadCount(user.id)

    return NextResponse.json({ count })

  } catch (error) {
    console.error('Error fetching unread notification count:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}