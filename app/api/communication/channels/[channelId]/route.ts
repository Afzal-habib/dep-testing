/**
 * Channels [channelId] API Route - CONSOLIDATED (Phase 2)
 * 
 * Handles ALL channel operations via action query parameter:
 * - GET: Get channel details, or with ?action=pin get pin status, or ?action=settings get settings, or ?action=members list members
 * - PUT: Update channel, or with ?action=archive archive/unarchive, or ?action=settings update settings, or ?action=member-role update member role
 * - POST: Execute actions: ?action=pin toggle pin, ?action=leave leave channel, ?action=members add members
 * - DELETE: Delete channel, or with ?action=remove-member remove a member
 * 
 * Uses centralized services from Phase 1:
 * - channelOps from operations.ts for database operations
 * - broadcast functions from broadcast.ts for real-time updates
 */
import { type NextRequest, NextResponse } from 'next/server'
import { prisma } from '@/lib/prisma'
import { executeGenericDbQuery } from '@/lib/mongodb'
import User from '@/models/User'
import { channelOps } from '@/lib/communication/operations'
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'
import { broadcastToChannel, broadcastToUser, broadcastMemberChange, broadcastChannelUpdate } from '@/lib/communication/broadcast'
import { apiLogger as logger } from '@/lib/logger'
import { z } from 'zod'
import type { Prisma, channels } from '.prisma/client'

// ============================================
// Type Definitions
// ============================================

type ChannelWithArchive = channels & {
  is_archived?: boolean
  archived_at?: Date | null
  archived_by?: string | null
}

interface RouteContext {
  params: Promise<{ channelId: string }>
}

// ============================================
// Validation Schemas
// ============================================

const updateSettingsSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  avatar_url: z.string().optional().nullable().transform(val => val === '' ? null : val),
  auto_sync_enabled: z.boolean().optional(),
  allow_external_members: z.boolean().optional(),
  admin_only_post: z.boolean().optional(),
  admin_only_add: z.boolean().optional(),
  is_private: z.boolean().optional()
}).partial()

const addMembersSchema = z.object({
  userId: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
  role: z.enum(['admin', 'member']).default('member')
})

const updateMemberRoleSchema = z.object({
  memberId: z.string().min(1, 'Member ID is required'),
  role: z.enum(['admin', 'member'])
})

// ============================================
// Constants
// ============================================

const MAX_PINNED_CHANNELS = 5

// ============================================
// Helper Functions
// ============================================

function createErrorResponse(message: string, status: number, details?: unknown) {
  return NextResponse.json({
    success: false,
    error: message,
    ...(details ? { details } : {})
  }, { status })
}

async function enrichChannelMembers(channel: any) {
  const memberIds = channel.channel_members?.map((m: { mongo_member_id: string }) => m.mongo_member_id) || []
  if (memberIds.length === 0) return channel

  const users = await executeGenericDbQuery(async () => {
    return await User.find({ _id: { $in: memberIds } })
      .select('_id name email avatar department position role isClient')
      .lean()
  })

  const userMap = (users as any[]).reduce<Record<string, any>>((acc, user) => {
    const id = typeof user._id === 'string' ? user._id : user._id?.toString?.() ?? ''
    if (id) acc[id] = user
    return acc
  }, {})

  const enrichedMembers = channel.channel_members.map((member: any) => ({
    ...member,
    name: userMap[member.mongo_member_id]?.name || 'Unknown User',
    email: userMap[member.mongo_member_id]?.email || '',
    avatar: userMap[member.mongo_member_id]?.avatar || '',
    userRole: userMap[member.mongo_member_id]?.role || 'member',
    department: userMap[member.mongo_member_id]?.department || null,
    position: userMap[member.mongo_member_id]?.position || '',
    isClient: userMap[member.mongo_member_id]?.isClient || false
  }))

  return { ...channel, channel_members: enrichedMembers }
}

// ============================================
// GET Handler
// ============================================

export async function GET(request: NextRequest, { params: paramsPromise }: RouteContext) {
  try {
    const params = await paramsPromise
    const { session, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'communication', 'read')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    const channelId = params.channelId
    const { searchParams } = new URL(request.url)
    const action = searchParams.get('action')

    // Check membership using Phase 1 channelOps
    const memberRole = await channelOps.getMemberRole(channelId, session.user.id)
    const isMember = !!memberRole || isSuperAdmin

    if (!isMember) {
      return createErrorResponse('Access denied to this channel', 403)
    }

    // GET?action=pin - Get pin status
    if (action === 'pin') {
      const channelMember = await prisma.channel_members.findFirst({
        where: { channel_id: channelId, mongo_member_id: session.user.id },
        select: { is_pinned: true, pinned_at: true }
      })

      return NextResponse.json({
        success: true,
        data: {
          channel_id: channelId,
          is_pinned: channelMember?.is_pinned || false,
          pinned_at: channelMember?.pinned_at
        }
      })
    }

    // GET?action=settings - Get channel settings
    if (action === 'settings') {
      const channel = await prisma.channels.findUnique({ where: { id: channelId } }) as any

      if (!channel) {
        return createErrorResponse('Channel not found', 404)
      }

      const isOwner = memberRole === 'owner' || channel.mongo_creator_id === session.user.id
      const isAdmin = memberRole === 'admin' || isOwner

      return NextResponse.json({
        success: true,
        data: {
          id: channel.id,
          name: channel.name,
          type: channel.type,
          avatar_url: channel.avatar_url,
          auto_sync_enabled: channel.auto_sync_enabled ?? true,
          allow_external_members: channel.allow_external_members ?? false,
          admin_only_post: channel.admin_only_post ?? false,
          admin_only_add: channel.admin_only_add ?? false,
          is_private: channel.is_private,
          mongo_creator_id: channel.mongo_creator_id,
          mongo_department_id: channel.mongo_department_id,
          mongo_project_id: channel.mongo_project_id,
          member_count: channel.member_count,
          created_at: channel.created_at,
          updated_at: channel.updated_at,
          isAdmin,
          isOwner,
          currentUserRole: memberRole
        }
      })
    }

    // GET?action=members - List channel members
    if (action === 'members') {
      const members = await prisma.channel_members.findMany({
        where: { channel_id: channelId },
        orderBy: [{ role: 'asc' }, { joined_at: 'asc' }]
      })

      const memberIds = members.map((m: { mongo_member_id: string }) => m.mongo_member_id)
      const users = await executeGenericDbQuery(async () => {
        return await User.find({ _id: { $in: memberIds } })
          .select('_id name email avatar role department')
          .populate('department', 'name')
          .lean()
      })

      const userMap = new Map((users as any[]).map((u: any) => [u._id.toString(), u]))

      const enrichedMembers = members.map((member: any) => ({
        ...member,
        user: userMap.get(member.mongo_member_id) || { _id: member.mongo_member_id, name: 'Unknown User', email: '' }
      }))

      return NextResponse.json({ success: true, data: enrichedMembers })
    }

    // Default: Get channel details
    const channel = await channelOps.getById(channelId, { includeMembers: true })

    if (!channel) {
      return createErrorResponse('Channel not found', 404)
    }

    const { enrichChannelWithUserData } = await import('@/lib/communication/utils')
    const allUsers = await executeGenericDbQuery(async () => {
      return await User.find({ isDeleted: { $ne: true } }).select('_id name email avatar isClient role').lean()
    })
    const enrichedChannel = await enrichChannelWithUserData(channel, allUsers as any[])

    return NextResponse.json({ channel: enrichedChannel })
  } catch (error) {
    logger.error('Error in GET channel:', error)
    return createErrorResponse('Internal server error', 500)
  }
}

// PUT /api/communication/channels/[channelId] - Update channel (consolidated)
// Supports: ?action=settings, ?action=member-role, ?action=archive
export async function PUT(
  request: NextRequest,
  { params: paramsPromise }: { params: Promise<{ channelId: string }> }
) {
  try {
    const params = await paramsPromise
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'communication', 'update')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    const channelId = params.channelId
    const userId = session.user.id
    const { searchParams } = new URL(request.url)
    const action = searchParams.get('action')
    const body = await request.json().catch(() => ({}))

    // Get user's role in the channel
    const memberRole = await channelOps.getMemberRole(channelId, userId)

    // Action: settings - Update channel settings
    if (action === 'settings') {
      const validation = updateSettingsSchema.safeParse(body)
      if (!validation.success) {
        return createErrorResponse('Invalid settings', 400, { errors: validation.error.errors })
      }
      const validated = validation.data

      if (!memberRole || !['admin', 'owner'].includes(memberRole)) {
        return createErrorResponse('Admin permission required', 403)
      }

      const channel = await prisma.channels.findUnique({ where: { id: channelId } })
      if (!channel) {
        return createErrorResponse('Channel not found', 404)
      }

      // DM channels cannot be modified
      if (channel.type === 'dm') {
        return createErrorResponse('Cannot modify DM channel settings', 400)
      }

      // Update settings
      const updatedChannel = await prisma.channels.update({
        where: { id: channelId },
        data: {
          ...validated,
          updated_at: new Date()
        }
      })

      // Broadcast settings update (non-blocking)
      broadcastChannelUpdate(channelId, {
        type: 'update',
        channel: updatedChannel
      }).catch(err => logger.debug('Failed to broadcast settings update:', err))

      return NextResponse.json({
        success: true,
        data: updatedChannel,
        message: 'Settings updated successfully'
      })
    }

    // Action: member-role - Update member's role
    if (action === 'member-role') {
      const { memberId, role: newRole } = body

      if (!memberId || !newRole) {
        return createErrorResponse('memberId and role are required', 400)
      }

      if (!['admin', 'member'].includes(newRole)) {
        return createErrorResponse('Invalid role. Use "admin" or "member"', 400)
      }

      if (!memberRole || !['admin', 'owner'].includes(memberRole)) {
        return createErrorResponse('Admin permission required', 403)
      }

      const channel = await prisma.channels.findUnique({ where: { id: channelId } })
      if (!channel) {
        return createErrorResponse('Channel not found', 404)
      }

      // Cannot change owner role
      const targetRole = await channelOps.getMemberRole(channelId, memberId)
      if (!targetRole) {
        return createErrorResponse('Member not found', 404)
      }
      if (targetRole === 'owner') {
        return createErrorResponse('Cannot change owner role', 403)
      }

      // Get target member record for update
      const target = await prisma.channel_members.findFirst({
        where: { channel_id: channelId, mongo_member_id: memberId }
      })
      if (!target) {
        return createErrorResponse('Member not found', 404)
      }

      // Update role
      const updatedMember = await prisma.channel_members.update({
        where: { id: target.id },
        data: { role: newRole }
      })

      // Broadcast update (non-blocking)
      broadcastMemberChange(channelId, 'role_changed', {
        memberId,
        memberName: '',
        role: newRole
      }).catch(err => logger.debug('Failed to broadcast role update:', err))

      return NextResponse.json({ 
        success: true, 
        data: updatedMember,
        message: 'Role updated successfully' 
      })
    }

    // Action: archive - Archive or unarchive channel
    if (action === 'archive' || action === 'unarchive') {
      const channelResult = await prisma.channels.findUnique({ where: { id: channelId } })
      if (!channelResult) {
        return createErrorResponse('Channel not found', 404)
      }
      
      const channel = channelResult as ChannelWithArchive
      const isCreator = channel.mongo_creator_id === userId
      const isAdminOrOwner = memberRole && ['admin', 'owner'].includes(memberRole)

      if (!isAdminOrOwner && !isCreator && !isSuperAdmin) {
        return createErrorResponse('Only channel admins can archive/unarchive channels', 403)
      }

      if (action === 'archive') {
        if (channel.is_archived) {
          return createErrorResponse('Channel is already archived', 400)
        }

        const updatedChannel = await prisma.channels.update({
          where: { id: channelId },
          data: {
            is_archived: true,
            archived_at: new Date(),
            archived_by: userId,
            updated_at: new Date()
          } as any,
          include: { channel_members: true }
        })

        broadcastChannelUpdate(channelId, {
          type: 'archive',
          channel: { id: updatedChannel.id, is_archived: true, archived_at: (updatedChannel as any).archived_at, archived_by: (updatedChannel as any).archived_by }
        }).catch(err => logger.debug('Failed to broadcast channel archive:', err))

        return NextResponse.json({ 
          success: true, 
          action: 'archived',
          channel: updatedChannel,
          message: 'Channel has been archived' 
        })
      } else {
        if (!channel.is_archived) {
          return createErrorResponse('Channel is not archived', 400)
        }

        const updatedChannel = await prisma.channels.update({
          where: { id: channelId },
          data: {
            is_archived: false,
            archived_at: null,
            archived_by: null,
            updated_at: new Date()
          } as any,
          include: { channel_members: true }
        })

        broadcastChannelUpdate(channelId, {
          type: 'unarchive',
          channel: { id: updatedChannel.id, is_archived: false, archived_at: null, archived_by: null }
        }).catch(err => logger.debug('Failed to broadcast channel unarchive:', err))

        return NextResponse.json({ 
          success: true, 
          action: 'unarchived',
          channel: updatedChannel,
          message: 'Channel has been unarchived' 
        })
      }
    }

    // Default: Update channel basic info (name, is_private)
    if (!memberRole || !['admin', 'owner'].includes(memberRole)) {
      return createErrorResponse('Access denied - admin required', 403)
    }

    const { name, is_private } = body
    const updatedChannel = await prisma.channels.update({
      where: { id: channelId },
      data: {
        name,
        is_private,
        updated_at: new Date(),
      },
      include: { channel_members: true },
    })

    const { default: User } = await import('@/models/User')
    const { enrichChannelWithUserData } = await import('@/lib/communication/utils')
    
    const allUsers = await executeGenericDbQuery(async () => {
      return await User.find({ isDeleted: { $ne: true } }).select('_id name email avatar isClient role').lean()
    })
    
    const enrichedChannel = await enrichChannelWithUserData(updatedChannel, allUsers)

    return NextResponse.json({ channel: enrichedChannel })
  } catch (error) {
    logger.error('Error updating channel:', error)
    return createErrorResponse('Internal server error', 500)
  }
}

// POST /api/communication/channels/[channelId] - Post actions (consolidated)
// Supports: ?action=pin toggle pin, ?action=leave leave channel, ?action=members add members
export async function POST(
  request: NextRequest,
  { params: paramsPromise }: { params: Promise<{ channelId: string }> }
) {
  try {
    const params = await paramsPromise
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'communication', 'update')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    const channelId = params.channelId
    const userId = session.user.id
    const { searchParams } = new URL(request.url)
    const action = searchParams.get('action')
    const body = await request.json().catch(() => ({}))

    // Action: pin - Toggle pin status
    if (action === 'pin') {
      const channelMember = await prisma.channel_members.findFirst({
        where: { channel_id: channelId, mongo_member_id: userId }
      })

      if (!channelMember) {
        return createErrorResponse('You are not a member of this channel', 404)
      }

      const isPinning = !channelMember.is_pinned

      if (isPinning) {
        const pinnedCount = await prisma.channel_members.count({
          where: { mongo_member_id: userId, is_pinned: true }
        })

        if (pinnedCount >= MAX_PINNED_CHANNELS) {
          return createErrorResponse(
            `You can only pin up to ${MAX_PINNED_CHANNELS} channels. Unpin a channel first.`,
            400
          )
        }
      }

      const updated = await prisma.channel_members.update({
        where: { id: channelMember.id },
        data: { is_pinned: isPinning, pinned_at: isPinning ? new Date() : null }
      })

      // Broadcast pin change (non-blocking)
      broadcastToUser({
        userId,
        event: 'new_message',
        payload: { id: channelId, type: 'pin_update', channel: { id: channelId, is_pinned: isPinning, pinned_at: updated.pinned_at } }
      }).catch(err => logger.debug('Failed to broadcast pin change:', err))

      return NextResponse.json({
        success: true,
        data: { channel_id: channelId, is_pinned: isPinning, pinned_at: updated.pinned_at },
        message: isPinning ? 'Channel pinned successfully' : 'Channel unpinned successfully'
      })
    }

    // Action: mute - Toggle mute/notification status for the channel
    if (action === 'mute') {
      const channelMember = await prisma.channel_members.findFirst({
        where: { channel_id: channelId, mongo_member_id: userId }
      })

      if (!channelMember) {
        return createErrorResponse('You are not a member of this channel', 404)
      }

      // Toggle the mute status (notifications_enabled: false = muted)
      const isMuting = channelMember.notifications_enabled // if enabled, we're muting

      const updated = await prisma.channel_members.update({
        where: { id: channelMember.id },
        data: { notifications_enabled: !isMuting }
      })

      // Broadcast mute change to user (non-blocking)
      broadcastToUser({
        userId,
        event: 'new_message',
        payload: { 
          id: channelId, 
          type: 'mute_update', 
          channel: { 
            id: channelId, 
            notifications_enabled: updated.notifications_enabled 
          } 
        }
      }).catch(err => logger.debug('Failed to broadcast mute change:', err))

      return NextResponse.json({
        success: true,
        data: { 
          channel_id: channelId, 
          notifications_enabled: updated.notifications_enabled,
          is_muted: !updated.notifications_enabled 
        },
        message: updated.notifications_enabled ? 'Notifications enabled' : 'Notifications muted'
      })
    }

    // Action: leave - Leave the channel
    if (action === 'leave') {
      const channel = await prisma.channels.findUnique({
        where: { id: channelId },
        include: { channel_members: true }
      })

      if (!channel) {
        return createErrorResponse('Channel not found', 404)
      }

      const memberRole = await channelOps.getMemberRole(channelId, userId)
      if (!memberRole) {
        return createErrorResponse('You are not a member of this channel', 400)
      }

      const isAdminOrOwner = memberRole === 'admin' || memberRole === 'owner'

      if (isAdminOrOwner) {
        // Count other admins/owners
        const otherAdmins = await prisma.channel_members.count({
          where: { channel_id: channelId, mongo_member_id: { not: userId }, role: { in: ['admin', 'owner'] } }
        })

        if (otherAdmins === 0) {
          const otherMembers = await prisma.channel_members.findMany({
            where: { channel_id: channelId, mongo_member_id: { not: userId } },
            orderBy: { joined_at: 'asc' },
            take: 1
          })

          if (otherMembers.length === 0) {
            // Last member - archive channel instead of leaving
            await prisma.channels.update({
              where: { id: channelId },
              data: { is_archived: true, archived_at: new Date(), archived_by: userId } as any
            })
            
            await prisma.channel_members.delete({
              where: { channel_id_mongo_member_id: { channel_id: channelId, mongo_member_id: userId } }
            })

            return NextResponse.json({ 
              success: true, 
              archived: true,
              message: 'You were the last member. Channel has been archived.' 
            })
          }

          // Transfer admin role to the oldest member before leaving
          await prisma.channel_members.update({
            where: { channel_id_mongo_member_id: { channel_id: channelId, mongo_member_id: otherMembers[0].mongo_member_id } },
            data: { role: 'admin' }
          })
        }
      }

      // Remove user from channel_members
      await prisma.channel_members.delete({
        where: { channel_id_mongo_member_id: { channel_id: channelId, mongo_member_id: userId } }
      })

      // Broadcast member_left event (non-blocking)
      broadcastMemberChange(channelId, 'left', { memberId: userId, memberName: '' })
        .catch(err => logger.debug('Failed to broadcast member left:', err))

      // Update member count
      await prisma.channels.update({
        where: { id: channelId },
        data: { member_count: { decrement: 1 }, updated_at: new Date() }
      })

      // Check if no members left - archive the channel
      const remainingMembers = await prisma.channel_members.count({
        where: { channel_id: channelId }
      })

      if (remainingMembers === 0) {
        await prisma.channels.update({
          where: { id: channelId },
          data: { is_archived: true, archived_at: new Date(), archived_by: userId } as any
        })
        
        return NextResponse.json({ 
          success: true, 
          archived: true,
          message: 'Channel has been archived (no members left).' 
        })
      }

      return NextResponse.json({ success: true, message: 'Successfully left the channel' })
    }

    // Action: members - Add members to the channel
    if (action === 'members') {
      const addMembersSchema = z.object({
        userId: z.array(z.string().min(1)).min(1, 'At least one user ID is required'),
        role: z.enum(['admin', 'member']).default('member')
      })

      const validation = addMembersSchema.safeParse(body)
      if (!validation.success) {
        return createErrorResponse('Invalid request data', 400, { errors: validation.error.errors })
      }
      const validated = validation.data

      const channel = await prisma.channels.findUnique({
        where: { id: channelId },
        include: { channel_members: true }
      })

      if (!channel) {
        return createErrorResponse('Channel not found', 404)
      }

      // Check requester permissions
      const requesterRole = await channelOps.getMemberRole(channelId, userId)
      if (!requesterRole) {
        return createErrorResponse('You are not a member of this channel', 403)
      }

      const channelAny = channel as any
      if (channelAny.admin_only_add) {
        if (requesterRole !== 'admin' && requesterRole !== 'owner') {
          return createErrorResponse('Only admins can add members to this channel', 403)
        }
      }

      // Filter out existing members
      const existingMemberIds = channel.channel_members.map((m: any) => m.mongo_member_id)
      const newMemberIds = validated.userId.filter(id => !existingMemberIds.includes(id))

      if (newMemberIds.length === 0) {
        return createErrorResponse('All specified users are already members of this channel', 400)
      }

      // Check if allow_external_members is disabled
      if (channelAny.allow_external_members === false && (channel.mongo_department_id || channel.mongo_project_id)) {
        const newUsers = await executeGenericDbQuery(async () => {
          return await User.find({ _id: { $in: newMemberIds } }).select('department').lean()
        }) as any[]

        for (const userItem of newUsers) {
          if (channel.mongo_department_id && userItem?.department?.toString() !== channel.mongo_department_id) {
            return createErrorResponse('External members are not allowed in this channel', 403)
          }
        }
      }

      // Get user data for all new members
      const users = await executeGenericDbQuery(async () => {
        return await User.find({ _id: { $in: newMemberIds } }).select('_id name email avatar role').lean()
      }) as any[]

      if (users.length !== newMemberIds.length) {
        return createErrorResponse('One or more users not found', 404)
      }

      // Add members
      await prisma.$transaction(
        newMemberIds.map(memberId => 
          prisma.channel_members.create({
            data: {
              id: crypto.randomUUID(),
              channel_id: channelId,
              mongo_member_id: memberId,
              role: validated.role,
              joined_at: new Date(),
              added_by: userId,
              added_via: 'manual_add'
            } as any
          })
        )
      )

      // Update member count
      await prisma.channels.update({
        where: { id: channelId },
        data: { member_count: { increment: newMemberIds.length }, updated_at: new Date() }
      })

      // Broadcast to new members (non-blocking)
      for (const memberId of newMemberIds) {
        broadcastToUser({
          userId: memberId,
          event: 'new_message',
          payload: { id: channelId, type: 'new_channel' }
        }).catch(err => logger.debug(`Failed to notify user ${memberId} of new channel:`, err))
      }

      // Broadcast to channel (non-blocking)
      broadcastToChannel({
        channelId,
        event: 'member_joined',
        payload: {
          channelId,
          memberIds: newMemberIds,
          type: 'members_added',
          users: users.map(u => ({ mongo_member_id: u._id.toString(), name: u.name, email: u.email, avatar: u.avatar }))
        }
      }).catch(err => logger.debug('Failed to broadcast member add:', err))

      // Get updated channel with members
      const updatedChannel = await prisma.channels.findUnique({
        where: { id: channelId },
        include: { channel_members: { orderBy: [{ role: 'asc' }, { joined_at: 'asc' }] } }
      })

      if (!updatedChannel) {
        return createErrorResponse('Channel not found after update', 500)
      }

      // Enrich members with user data
      const memberIds = updatedChannel.channel_members.map((m: { mongo_member_id: string }) => m.mongo_member_id)
      const enrichedUsers = await executeGenericDbQuery(async () => {
        return await User.find({ _id: { $in: memberIds } }).select('_id name email avatar department position role isClient')
      })

      const userMap = (enrichedUsers as any[]).reduce<Record<string, any>>((acc, u) => {
        const id = typeof u._id === 'string' ? u._id : u._id?.toString?.() ?? ''
        if (id) acc[id] = u
        return acc
      }, {})

      const enrichedMembers = updatedChannel.channel_members.map((member: any) => ({
        ...member,
        name: userMap[member.mongo_member_id]?.name || 'Unknown User',
        email: userMap[member.mongo_member_id]?.email || '',
        avatar: userMap[member.mongo_member_id]?.avatar || '',
        userRole: userMap[member.mongo_member_id]?.role || 'member',
        department: userMap[member.mongo_member_id]?.department || null,
        position: userMap[member.mongo_member_id]?.position || '',
        isClient: userMap[member.mongo_member_id]?.isClient || false
      }))

      return NextResponse.json({
        success: true,
        channel: { ...updatedChannel, channel_members: enrichedMembers },
        message: `${newMemberIds.length} member(s) added successfully`
      })
    }

    // No valid action provided
    return createErrorResponse('Invalid action. Use pin, leave, or members', 400)
  } catch (error) {
    logger.error('Error in POST channel:', error)
    return createErrorResponse('Internal server error', 500)
  }
}

// DELETE /api/communication/channels/[channelId] - Delete channel (consolidated)
// Supports: ?action=remove-member (with mongo_member_id param)
export async function DELETE(
  request: NextRequest,
  { params: paramsPromise }: { params: Promise<{ channelId: string }> }
) {
  try {
    const params = await paramsPromise
    const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'communication', 'delete')

    if (!session?.user?.id) {
      return createErrorResponse('Unauthorized', 401)
    }

    const channelId = params.channelId
    const userId = session.user.id
    const { searchParams } = new URL(request.url)
    const action = searchParams.get('action')

    // Action: remove-member - Remove a member from the channel
    if (action === 'remove-member') {
      const memberId = searchParams.get('mongo_member_id')
      if (!memberId) {
        return createErrorResponse('mongo_member_id query parameter is required', 400)
      }

      const channel = await prisma.channels.findUnique({ where: { id: channelId } })
      if (!channel) {
        return createErrorResponse('Channel not found', 404)
      }

      // Check requester permissions
      const requesterRole = await channelOps.getMemberRole(channelId, userId)
      if (!requesterRole || !['admin', 'owner'].includes(requesterRole)) {
        return createErrorResponse('Admin permission required', 403)
      }

      // Cannot remove owner
      const targetRole = await channelOps.getMemberRole(channelId, memberId)
      if (!targetRole) {
        return createErrorResponse('Member not found', 404)
      }
      if (targetRole === 'owner') {
        return createErrorResponse('Cannot remove channel owner', 403)
      }

      // Get target member record for deletion
      const target = await prisma.channel_members.findFirst({
        where: { channel_id: channelId, mongo_member_id: memberId }
      })
      if (!target) {
        return createErrorResponse('Member not found', 404)
      }

      // Remove member
      await prisma.channel_members.delete({ where: { id: target.id } })

      // Update member count
      await prisma.channels.update({
        where: { id: channelId },
        data: { member_count: { decrement: 1 } }
      })

      // Get updated channel with members
      const updatedChannel = await prisma.channels.findUnique({
        where: { id: channelId },
        include: {
          channel_members: {
            orderBy: [{ role: 'asc' }, { joined_at: 'asc' }]
          }
        }
      })

      if (!updatedChannel) {
        return createErrorResponse('Channel not found after update', 500)
      }

      // Enrich members with user data
      const memberIds = updatedChannel.channel_members.map((m: { mongo_member_id: string }) => m.mongo_member_id)
      const users = await executeGenericDbQuery(async () => {
        return await User.find({ _id: { $in: memberIds } }).select('_id name email avatar department position role isClient')
      })

      const userMap: Record<string, any> = (users as any[]).reduce((acc: Record<string, any>, user: any) => {
        const id = typeof user._id === 'string' ? user._id : user._id?.toString?.() ?? ''
        if (id) acc[id] = user
        return acc
      }, {})

      const enrichedMembers = updatedChannel.channel_members.map((member: any) => ({
        ...member,
        name: userMap[member.mongo_member_id]?.name || 'Unknown User',
        email: userMap[member.mongo_member_id]?.email || '',
        avatar: userMap[member.mongo_member_id]?.avatar || '',
        userRole: userMap[member.mongo_member_id]?.role || 'member',
        department: userMap[member.mongo_member_id]?.department || null,
        position: userMap[member.mongo_member_id]?.position || '',
        isClient: userMap[member.mongo_member_id]?.isClient || false
      }))

      // Broadcast to removed user (non-blocking)
      broadcastToUser({
        userId: memberId,
        event: 'new_message',
        payload: { id: channelId, type: 'channel_removed' }
      }).catch(err => logger.debug(`Failed to notify removed user ${memberId}:`, err))

      // Broadcast to channel (non-blocking)
      broadcastMemberChange(channelId, 'left', { memberId, memberName: '' })
        .catch(err => logger.debug('Failed to broadcast member removal:', err))

      return NextResponse.json({
        success: true,
        message: 'Member removed successfully',
        channel: { ...updatedChannel, channel_members: enrichedMembers }
      })
    }

    // Default: Delete channel
    const channel = await channelOps.getById(channelId)

    if (!channel) {
      return createErrorResponse('Channel not found', 404)
    }

    const isCreator = channel.mongo_creator_id === userId
    const role = await channelOps.getMemberRole(channelId, userId)
    const isAdminOrOwner = role && ['admin', 'owner'].includes(role)

    if (!isCreator && !isAdminOrOwner && !isSuperAdmin) {
      return createErrorResponse('Access denied - admin required', 403)
    }

    // Delete channel (cascade will delete related data)
    await prisma.channels.delete({
      where: { id: channelId },
    })

    return NextResponse.json({ success: true })
  } catch (error) {
    logger.error('Error deleting channel:', error)
    return createErrorResponse('Internal server error', 500)
  }
}
