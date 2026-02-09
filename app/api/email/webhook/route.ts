import { type NextRequest, NextResponse } from "next/server"
import connectDB from '@/lib/mongodb'
import EmailLog from '@/models/EmailLog'
import crypto from 'crypto'

// POST /api/email/webhook - Handle SES notifications (bounces, complaints, deliveries)
export async function POST(request: NextRequest) {
  try {
    const body = await request.text()
    const signature = request.headers.get('x-amz-sns-message-signature')
    const messageType = request.headers.get('x-amz-sns-message-type')

    // Verify webhook signature (optional but recommended)
    const webhookSecret = process.env.WEBHOOK_SECRET
    if (webhookSecret) {
      const expectedSignature = crypto
        .createHmac('sha256', webhookSecret)
        .update(body)
        .digest('hex')
      
      if (signature !== expectedSignature) {
        console.error('Invalid webhook signature')
        return NextResponse.json({ error: 'Invalid signature' }, { status: 401 })
      }
    }

    const message = JSON.parse(body)
    
    // Handle SNS subscription confirmation
    if (messageType === 'SubscriptionConfirmation') {
      console.log('SNS Subscription confirmation:', message.SubscribeURL)
      return NextResponse.json({ message: 'Subscription confirmed' })
    }

    // Process SES notification
    if (messageType === 'Notification') {
      const sesMessage = JSON.parse(message.Message)
      await processSESNotification(sesMessage)
    }

    return NextResponse.json({ success: true })

  } catch (error: any) {
    console.error('SES webhook error:', error)
    return NextResponse.json(
      { success: false, error: error.message },
      { status: 500 }
    )
  }
}

async function processSESNotification(sesMessage: any) {
  await connectDB()

  const { eventType, mail, bounce, complaint, delivery } = sesMessage

  try {
    // Find the email log entry
    const emailLog = await EmailLog.findOne({
      messageId: mail?.messageId
    })

    if (!emailLog) {
      console.warn('Email log not found for message ID:', mail?.messageId)
      return
    }

    let updateData: any = {}
    let eventData: any = {
      timestamp: new Date(),
      metadata: sesMessage
    }

    switch (eventType) {
      case 'bounce':
        updateData = {
          status: 'bounced',
          $push: {
            events: {
              type: 'bounce',
              ...eventData,
              metadata: {
                ...eventData.metadata,
                bounceType: bounce?.bounceType,
                bounceSubType: bounce?.bounceSubType,
                bouncedRecipients: bounce?.bouncedRecipients
              }
            }
          }
        }
        console.log('Processing bounce for:', mail?.messageId)
        break

      case 'complaint':
        updateData = {
          status: 'complaint',
          $push: {
            events: {
              type: 'complaint',
              ...eventData,
              metadata: {
                ...eventData.metadata,
                complaintFeedbackType: complaint?.complaintFeedbackType,
                complainedRecipients: complaint?.complainedRecipients
              }
            }
          }
        }
        console.log('Processing complaint for:', mail?.messageId)
        break

      case 'delivery':
        updateData = {
          status: 'delivered',
          $push: {
            events: {
              type: 'delivery',
              ...eventData,
              metadata: {
                ...eventData.metadata,
                timestamp: delivery?.timestamp,
                processingTimeMillis: delivery?.processingTimeMillis
              }
            }
          }
        }
        console.log('Processing delivery for:', mail?.messageId)
        break

      case 'send':
        updateData = {
          $push: {
            events: {
              type: 'send',
              ...eventData
            }
          }
        }
        break

      case 'open':
        updateData = {
          $push: {
            events: {
              type: 'open',
              ...eventData
            }
          }
        }
        break

      case 'click':
        updateData = {
          $push: {
            events: {
              type: 'click',
              ...eventData
            }
          }
        }
        break

      default:
        console.warn('Unknown SES event type:', eventType)
        return
    }

    // Update the email log
    await EmailLog.findByIdAndUpdate(emailLog._id, updateData)
    
    console.log(`Updated email log ${emailLog._id} with ${eventType} event`)

  } catch (error) {
    console.error('Error processing SES notification:', error)
  }
}

// GET /api/email/webhook - Health check
export async function GET() {
  return NextResponse.json({ 
    status: 'ok',
    message: 'SES webhook endpoint is active'
  })
}