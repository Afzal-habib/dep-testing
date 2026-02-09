import { NextRequest, NextResponse } from 'next/server'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { NotificationService } from '@/lib/services/notification-service'
import { markAsReadSchema } from '@/lib/validations/system-notification'
import { z } from 'zod'

// POST /api/system-notifications/mark-read - Mark specific notifications as read
export async function POST(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user } = await genericApiRoutesMiddleware(request, 'system-notifications', 'update')

    const body = await request.json()
    
    // Validate request body
    const validatedData = markAsReadSchema.parse(body)

    // Mark notifications as read
    await NotificationService.markAsRead(validatedData.notificationIds, user.id)

    return NextResponse.json({ 
      success: true,
      message: `${validatedData.notificationIds.length} notification(s) marked as read`
    })

  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Invalid request data', details: error.errors },
        { status: 400 }
      )
    }

    console.error('Error marking notifications as read:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}