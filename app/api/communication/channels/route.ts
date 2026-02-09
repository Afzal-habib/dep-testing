import { type NextRequest, NextResponse } from "next/server"
import { prisma } from '@/lib/prisma'
import { channelOperations } from '@/lib/db-utils'
import { SecurityUtils } from '@/lib/security/validation'
import { getClientInfo } from '@/lib/security/error-handler'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { createAPIErrorResponse } from "@/lib/utils/api-responses"
import { enrichChannelWithUserData } from '@/lib/communication/utils'
import { default as User } from '@/models/User'
import { executeGenericDbQuery } from '@/lib/mongodb'
import { channelQuerySchema, createChannelSchema } from "@/lib/validations/channel"
import { apiLogger as logger } from '@/lib/logger'
import { broadcastToUser } from '@/lib/communication/broadcast'


// Helper to create consistent error responses
function createErrorResponse(message: string, status: number, details?: any) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details && { details })
  }, { status })
}

// GET /api/communication/channels - Get user's channels
export async function GET(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'communication', 'read')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    // Parse and validate query parameters
    const searchParams = request.nextUrl.searchParams

    // Parse query parameters properly
    const queryParams = {
      type: searchParams.get('type') || '',
      department_id: searchParams.get('department_id') || '',
      project_id: searchParams.get('project_id') || '',
    }

    // Convert and validate parameters
    const parsedParams = {
      type: queryParams.type.trim(),
      department_id: queryParams.department_id.trim(),
      project_id: queryParams.project_id.trim(),
    }

    const validatedParams = channelQuerySchema.parse(parsedParams)

    let where: any = {
      channel_members: {
        some: {
          mongo_member_id: session.user.id,
        },
      },
    }

    if (validatedParams.type) where.type = validatedParams.type
    if (validatedParams.department_id) where.mongo_department_id = validatedParams.department_id
    if (validatedParams.project_id) where.mongo_project_id = validatedParams.project_id

    const channels = await prisma.channels.findMany({
      where,
      include: {
        channel_members: true,
        messages: {
          orderBy: { created_at: 'desc' },
          take: 1,
          include: {
            read_receipts: true,
          },
        },
        _count: {
          select: { messages: true },
        },
      },
      orderBy: { updated_at: 'desc' },
    })

    // Sort channels: pinned first (by pinned_at desc), then by updated_at desc
    const sortedChannels = channels.sort((a: any, b: any) => {
      // Find current user's membership in each channel
      const aMember = a.channel_members?.find((m: any) => m.mongo_member_id === session.user.id)
      const bMember = b.channel_members?.find((m: any) => m.mongo_member_id === session.user.id)
      const aIsPinned = aMember?.is_pinned || false
      const bIsPinned = bMember?.is_pinned || false
      
      // Pinned channels first
      if (aIsPinned && !bIsPinned) return -1
      if (!aIsPinned && bIsPinned) return 1
      
      // If both pinned, sort by pinned_at (most recently pinned first)
      if (aIsPinned && bIsPinned) {
        const aPinnedAt = aMember?.pinned_at ? new Date(aMember.pinned_at).getTime() : 0
        const bPinnedAt = bMember?.pinned_at ? new Date(bMember.pinned_at).getTime() : 0
        return bPinnedAt - aPinnedAt
      }
      
      // For non-pinned, sort by updated_at desc
      const aUpdated = a.updated_at ? new Date(a.updated_at).getTime() : 0
      const bUpdated = b.updated_at ? new Date(b.updated_at).getTime() : 0
      return bUpdated - aUpdated
    })

    // Fetch all users for enrichment
    const allUsers = await executeGenericDbQuery(async () => {
      return await User.find({ isDeleted: { $ne: true } }).select('_id name email avatar isClient role').lean()
    })

    // Enrich channels with user data from MongoDB
    const enrichedChannels = await Promise.all(
      sortedChannels.map((channel: any) => enrichChannelWithUserData(channel, allUsers))
    )

    // Add pin info and unread count to each channel for easy access
    const channelsWithPinInfo = await Promise.all(enrichedChannels.map(async (channel: any) => {
      const memberInfo = channel.channel_members?.find((m: any) => m.mongo_member_id === session.user.id)
      
      // Calculate unread count
      let unreadCount = 0
      try {
        // Get all message ids in the channel not from user and not trashed
        const messageIds = await prisma.messages.findMany({
          where: {
            channel_id: channel.id,
            mongo_sender_id: { not: session.user.id },
            is_trashed: false
          },
          select: { id: true }
        })
        
        const messageIdsArray = messageIds.map((m: { id: string }) => m.id)
        
        if (messageIdsArray.length > 0) {
          // Count read receipts for those message ids
          const readReceiptsCount = await prisma.read_receipts.count({
            where: {
              message_id: { in: messageIdsArray },
              mongo_user_id: session.user.id
            }
          })
          unreadCount = Math.max(0, messageIdsArray.length - readReceiptsCount)
        }
      } catch (error) {
        logger.warn('Failed to calculate unread count for channel:', channel.id, error)
        unreadCount = 0
      }
      
      return {
        ...channel,
        is_pinned: memberInfo?.is_pinned || false,
        pinned_at: memberInfo?.pinned_at || null,
        unreadCount
      }
    }))

    return NextResponse.json({
      success: true,
      data: channelsWithPinInfo,
      meta: {
        total: channelsWithPinInfo.length,
        page: 1,
        limit: channelsWithPinInfo.length,
        pages: 1
      }
    })
  } catch (error: any) {
    logger.error('Error fetching channels:', error)
    return createAPIErrorResponse('Failed to fetch channels', 500, undefined, getClientInfo(request))
  }
}

// POST /api/communication/channels - Create a new channel
export async function POST(request: NextRequest) {
  try {
    // Apply middleware (rate limiting + authentication + permissions)
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'communication', 'create')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    // Parse and validate request body
    const body = await request.json()
    const validatedData = createChannelSchema.parse(body)

    // Import channel helpers
    const {
      getChannelMembers,
      generateChannelName
    } = await import('@/lib/communication/channel-helpers')

    // Get channel members based on type
    const memberIds = await getChannelMembers({
      type: validatedData.type,
      creator_id: session.user.id,
      name: validatedData.name,
      department_id: validatedData.mongo_department_id,
      project_id: validatedData.mongo_project_id,
      channel_members: validatedData.channel_members,
      category: validatedData.category,
      categories: validatedData.categories,
      client_id: validatedData.client_id,
      is_private: validatedData.is_private
    })
    logger.debug("Channel members created:", memberIds);
    // For DM channels, check if one already exists between these users
    if (validatedData.type === 'dm' && memberIds.length === 2) {
      const sortedMembers = memberIds.sort()
      const existingDM = await prisma.channels.findFirst({
        where: {
          type: 'dm',
          channel_members: {
            every: {
              mongo_member_id: { in: sortedMembers }
            }
          },
          AND: [
            { channel_members: { some: { mongo_member_id: sortedMembers[0] } } },
            { channel_members: { some: { mongo_member_id: sortedMembers[1] } } }
          ]
        },
        include: {
          channel_members: true,
        },
      })

      if (existingDM) {
        // Fetch all users for enrichment
        const allUsers = await executeGenericDbQuery(async () => {
          return await User.find({ isDeleted: { $ne: true } }).select('_id name email avatar isClient role').lean()
        })

        // Enrich existing channel with user data
        const enrichedChannel = await enrichChannelWithUserData(existingDM, allUsers)

        return NextResponse.json({
          success: true,
          data: enrichedChannel,
          message: 'DM channel already exists'
        })
      }
    }

    // Generate channel name if not provided
    const channelName = validatedData.name || await generateChannelName({
      type: validatedData.type,
      creator_id: session.user.id,
      name: validatedData.name,
      department_id: validatedData.mongo_department_id,
      project_id: validatedData.mongo_project_id,
      channel_members: validatedData.channel_members,
      category: validatedData.category,
      categories: validatedData.categories,
      client_id: validatedData.client_id,
      is_private: validatedData.is_private
    })

    // Create channel
    const channel = await prisma.channels.create({
      data: {
        id: crypto.randomUUID(),
        type: validatedData.type,
        name: channelName,
        mongo_creator_id: session.user.id,
        mongo_department_id: validatedData.mongo_department_id,
        mongo_project_id: validatedData.mongo_project_id,
        is_private: validatedData.is_private,
        categories: validatedData.categories,
        member_count: memberIds.length,
        created_at: new Date(),
        updated_at: new Date(),
        // Channel settings
        auto_sync_enabled: validatedData.auto_sync_enabled ?? true,
        allow_external_members: validatedData.allow_external_members ?? false,
        admin_only_post: validatedData.admin_only_post ?? false,
        admin_only_add: validatedData.admin_only_add ?? false,
      },
    })

    // Add members to channel
    const memberInserts = memberIds.map((memberId, index) => ({
      id: crypto.randomUUID(),
      channel_id: channel.id,
      mongo_member_id: memberId,
      role: index === 0 ? 'admin' : 'member', // First member is admin
      joined_at: new Date(),
    }))

    await prisma.channel_members.createMany({
      data: memberInserts,
    })

    // Fetch complete channel with members
    const completeChannel = await prisma.channels.findUnique({
      where: { id: channel.id },
      include: {
        channel_members: true,
      },
    })

    // Fetch all users for enrichment
    const allUsers = await executeGenericDbQuery(async () => {
      return await User.find({ isDeleted: { $ne: true } }).select('_id name email avatar isClient role').lean()
    })

    // Enrich channel with user data
    const enrichedChannel = await enrichChannelWithUserData(completeChannel, allUsers)

    // Broadcast new channel to all members for real-time sync (non-blocking)
    // Uses Phase 1 broadcastToUser for centralized broadcast handling
    for (const memberId of memberIds) {
      broadcastToUser({
        userId: memberId,
        event: 'new_message', // Using 'new_message' as it's a valid NotificationEvent
        payload: {
          id: enrichedChannel.id,
          type: 'new_channel',
          channel: enrichedChannel,
          members: enrichedChannel.channel_members || []
        }
      }).catch(err => logger.debug(`Failed to broadcast new channel to ${memberId}:`, err))
    }

    return NextResponse.json({
      success: true,
      data: enrichedChannel,
      message: 'Channel created successfully'
    })
  } catch (error: any) {
    logger.error('Error creating channel:', error)
    return createAPIErrorResponse('Failed to create channel', 500, undefined, getClientInfo(request))
  }
}