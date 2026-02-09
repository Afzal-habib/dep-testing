import { useCallback, useEffect, useMemo, useState, useRef } from 'react'
import { useAppSelector, useAppDispatch } from './redux'
import { useSession } from 'next-auth/react'
import type { User } from '@/types'
import { useUsers } from './use-users'
import {
  setActiveChannel,
  clearActiveChannel,
  setChannels,
  setMessages,
  prependMessages,
  addMessage,
  updateMessage,
  addMessageReadReceipt,
  setMessageDelivered,
  addReactionToMessage,
  removeReactionFromMessage,
  setTyping,
  removeTyping,
  clearTypingForChannel,
  setCurrentUserId,
  setOnlineUserIds,
  addOnlineUser,
  removeOnlineUser,
  updateOnlineUsers,
  toggleChannelList,
  toggleContextPanel,
  setChannelListExpanded,
  setContextPanelVisible,
  setFilters,
  setSort,
  setPagination,
  setLoading,
  setActionLoading,
  setMessagesLoading,
  clearError,
  setError,
  addNotification,
  clearNotifications,
  clearNotificationsForChannel,
  removeNotification,
  setChannelsInitialized,
  resetState,
  decrementUnreadCount,
  incrementUnreadCount,
  // Channel real-time updates (Phase 3)
  addChannel,
  updateChannel,
  removeChannel,
  // Trash management imports (Phase 2)
  moveMessageToTrash,
  restoreMessageFromTrash,
  hideMessageForSelf,
  permanentlyDeleteMessage,
  setTrashedMessages,
  appendTrashedMessages,
  setTrashedMessagesLoading,
  clearTrashedMessages,
  type ITrashedMessage
} from '@/store/slices/communicationSlice'
import type {
  FetchMessagesParams,
  CreateMessageData,
  CreateChannelData,
  CommunicationFilters,
  CommunicationSort,
  ITypingIndicator,
  IParticipant,
  ICommunication,
  IChannel,
  IChannelMember,
  IAttachment
} from '@/types/communication'
import { useToast } from '@/hooks/use-toast'
import { apiRequest } from '@/lib/utils/api-client'
import { getRealtimeManager, RealtimeEventHandlers } from '@/lib/realtime-manager'
import { communicationLogger as logger } from '@/lib/logger'
import { communicationCache } from '@/lib/communication/cache'

// Global maps to prevent duplicate fetches per user across component remounts
const globalFetchedUsers = new Map<string, boolean>()
const globalFetchedChannels = new Map<string, boolean>()

export function useCommunications() {
  const dispatch = useAppDispatch()
  const { toast } = useToast()
  const { data: session, status } = useSession()
  const { users: allUsers, loading: usersLoading } = useUsers()
  const realtimeManager = useMemo(() => getRealtimeManager(), [])
  const hasInitialized = useRef(false)  
  const hasUsersInitialized = useRef(false)
  const channelsFetchedRef = useRef(false)
  const presenceInitializedRef = useRef(false)
  const hasFetchedUsersRef = useRef(false)
  const hasFetchedChannelsRef = useRef(false)
  
  // Use ref for toast to prevent unnecessary callback recreations
  const toastRef = useRef(toast)
  useEffect(() => {
    toastRef.current = toast
  }, [toast])
  
  const {
    channels,
    activeChannelId,
    selectedChannel,
    messages,
    onlineUsers,
    onlineUserIds,
    typingUsers,
    isChannelListExpanded,
    isContextPanelVisible,
    loading,
    actionLoading,
    messagesLoading,
    channelsInitialized,
    error,
    filters,
    sort,
    pagination,
    currentUser,
    currentUserId: storeCurrentUserId,
    unreadCount,
    notifications,
    // Trash management state (Phase 2)
    trashedMessages,
    trashedMessagesLoading,
    trashedMessagesPagination
  } = useAppSelector((state) => state.communications)

  // Refs to get current values without causing re-renders
  const currentMessagesRef = useRef(messages)
  const currentChannelsRef = useRef(channels)
  const activeChannelIdRef = useRef(activeChannelId)
  
  // Update refs when values change
  useEffect(() => {
    currentMessagesRef.current = messages
  }, [messages])
  
  useEffect(() => {
    currentChannelsRef.current = channels
  }, [channels])

  useEffect(() => {
    activeChannelIdRef.current = activeChannelId
  }, [activeChannelId])

  // Type guard for session user with extended properties
  interface ExtendedSessionUser {
    id?: string
    name?: string | null
    email?: string | null
    role?: string
    image?: string | null
    avatar?: string
    permissions?: any[]
  }
  
  const sessionUser = session?.user as ExtendedSessionUser | undefined
  const sessionUserId = useMemo(() => (session?.user as ExtendedSessionUser)?.id, [session?.user])
  const sessionUserName = useMemo(() => sessionUser?.name || sessionUser?.email || 'Unknown', [sessionUser])
  const sessionUserAvatar = useMemo(() => sessionUser?.image || sessionUser?.avatar, [sessionUser])

  // ============================================
  // Realtime Event Handlers
  // ============================================

  const onNewMessage = useCallback((message: any) => {
    logger.debug('onNewMessage handler called with:', message)
    
    // Skip messages from self to avoid duplicates (optimistic updates handle this)
    if (message.mongo_sender_id === sessionUserId) {
      logger.debug('Skipping message from self')
      return
    }
    
    if (message && typeof message === 'object' && message.mongo_sender_id) {
      logger.debug('Received enriched message:', message)
      dispatch(addMessage({ channelId: message.channel_id, message }))
    } else {
      logger.error('Invalid message received, skipping:', message)
    }
  }, [dispatch, sessionUserId])

  const onMessageUpdate = useCallback((message: any) => {
    logger.debug('onMessageUpdate handler called')
    dispatch(updateMessage({
      channelId: message.channel_id,
      messageId: message.id,
      updates: message
    }))
  }, [dispatch])

  const onMessageDelete = useCallback((messageId: any) => {
    logger.debug('Message deleted:', messageId)
  }, [])

  const onUserJoined = useCallback((member: any) => {
    logger.debug('User joined:', member)
  }, [])

  const onUserLeft = useCallback((memberId: any) => {
    logger.debug('User left:', memberId)
  }, [])

  const onUserOnline = useCallback((userId: string) => {
    logger.debug('User online:', userId)
    dispatch(addOnlineUser(userId))
  }, [dispatch])

  const onUserOffline = useCallback((userId: string) => {
    logger.debug('User offline:', userId)
    dispatch(removeOnlineUser(userId))
  }, [dispatch])

  // Handle typing start with proper data structure
  const onTypingStart = useCallback((data: { userId: string; userName: string; channelId: string }) => {
    logger.debug('Typing start:', data)
    dispatch(setTyping({
      channelId: data.channelId,
      userId: data.userId,
      userName: data.userName || 'Someone',
      timestamp: new Date().toISOString()
    }))
  }, [dispatch])

  // Handle typing stop
  const onTypingStop = useCallback((data: { userId: string; channelId: string }) => {
    logger.debug('Typing stop:', data)
    dispatch(removeTyping({ channelId: data.channelId, userId: data.userId }))
  }, [dispatch])

  // Handle message read (real-time update from other users)
  const onMessageRead = useCallback((data: { 
    messageId: string; 
    userId: string; 
    channelId: string; 
    readAt: string 
  }) => {
    logger.debug('Message read:', data)
    // Don't process our own read receipts
    if (data.userId === sessionUserId) return
    
    dispatch(addMessageReadReceipt({
      channelId: data.channelId,
      messageId: data.messageId,
      userId: data.userId,
      readAt: data.readAt
    }))
  }, [dispatch, sessionUserId])

  // Handle message delivered (when server confirms message received)
  const onMessageDelivered = useCallback((data: { 
    messageId: string; 
    channelId: string 
  }) => {
    logger.debug('Message delivered:', data)
    dispatch(setMessageDelivered({
      channelId: data.channelId,
      messageId: data.messageId
    }))
  }, [dispatch])

  // Handle presence sync (initial load and updates)
  const onPresenceSync = useCallback((presenceState: Record<string, any[]>) => {
    logger.debug('Presence sync:', Object.keys(presenceState))
    const onlineIds = Object.keys(presenceState)
    dispatch(setOnlineUserIds(onlineIds))
  }, [dispatch])

  // Handle mention notifications
  const onMentionNotification = useCallback((data: {
    type: string
    message_id: string
    channel_id: string
    sender_name: string
    sender_avatar?: string
    content_preview: string
    created_at: string
  }) => {
    logger.debug('Mention notification received:', data)
    
    // Add notification to store
    dispatch(addNotification({
      id: `mention_${data.message_id}`,
      type: 'mention',
      title: `${data.sender_name} mentioned you`,
      channelId: data.channel_id,
      messageId: data.message_id,
      preview: data.content_preview,
      read: false
    }))

    // Show toast notification
    toastRef.current({
      title: `@${data.sender_name} mentioned you`,
      description: data.content_preview.slice(0, 60) + (data.content_preview.length > 60 ? '...' : ''),
    })
  }, [dispatch])

  // Handle new message notifications (for users not viewing the channel)
  // This is the key handler for real-time notifications
  const onNewMessageNotification = useCallback((data: { message: any }) => {
    logger.debug('📨 New message notification received:', data)
    
    const message = data.message
    if (!message || !message.channel_id) {
      logger.warn('Invalid message notification received:', data)
      return
    }
    
    // Skip notifications for messages from self
    if (message.mongo_sender_id === sessionUserId) {
      logger.debug('Skipping notification for own message')
      return
    }
    
    // Skip if this channel is currently active (user is viewing it)
    // In this case, messages come through onNewMessage handler and are already displayed
    const currentActiveChannelId = activeChannelIdRef.current
    if (currentActiveChannelId === message.channel_id) {
      logger.debug('📨 Skipping notification for active channel - message handled by onNewMessage')
      return
    }
    
    // Get channel info for context
    const currentChannels = currentChannelsRef.current
    const channel = currentChannels.find((c: IChannel) => c.id === message.channel_id)
    const newUnreadCount = (channel?.unreadCount || 0) + 1
    
    // Check if channel is muted for this user
    const currentMember = channel?.channel_members?.find((m: IChannelMember) => m.mongo_member_id === sessionUserId)
    const isMuted = currentMember?.notifications_enabled === false
    
    // Increment unread count for the channel in Redux (even for muted channels)
    dispatch(updateChannel({
      id: message.channel_id,
      unreadCount: newUnreadCount,
      last_message: message,
      last_message_at: message.created_at
    }))
    dispatch(incrementUnreadCount(1))
    
    // Also update the cache to keep it in sync
    communicationCache.updateChannelInCache(message.channel_id, { 
      unreadCount: newUnreadCount,
      last_message: message,
      last_message_at: message.created_at
    })
    
    // Skip notification and toast for muted channels
    if (isMuted) {
      logger.debug('📨 Skipping notification for muted channel:', message.channel_id)
      return
    }
    
    // Add notification to store
    const senderName = message.sender_name || message.sender?.name || 'Someone'
    const contentPreview = message.content || ''
    
    dispatch(addNotification({
      id: `msg_${message.id}`,
      type: 'message',
      title: senderName,
      channelId: message.channel_id,
      messageId: message.id,
      message: message,
      preview: contentPreview,
      read: false
    }))
    
    // Show toast notification for the new message
    const channelName = channel?.name || (channel?.type === 'dm' ? senderName : 'Channel')
    toastRef.current({
      title: channel?.type === 'dm' ? senderName : `#${channelName}`,
      description: contentPreview.slice(0, 80) + (contentPreview.length > 80 ? '...' : ''),
    })
    
    logger.debug('📨 Notification added for message:', message.id)
  }, [dispatch, sessionUserId])

  // Handle user pin updates (real-time)
  const onUserPin = useCallback((data: { pinner_id: string; pinned_user_id: string; is_pinned: boolean }) => {
    logger.debug('User pin update:', data)
    // Only process if it's for the current user
    if (data.pinner_id !== sessionUserId) return

    // For now, we don't have a Redux state for pinned users, so we'll rely on components to refetch
    // In the future, we could add a pinnedUsers state to the slice
    logger.info(`User ${data.pinned_user_id} ${data.is_pinned ? 'pinned' : 'unpinned'}`)
  }, [sessionUserId])

  // Handle reaction added (real-time) - WhatsApp style
  const onReactionAdd = useCallback((data: {
    id?: string;
    reactionId?: string;
    message_id?: string;
    messageId?: string;
    channel_id?: string;
    channelId?: string;
    mongo_user_id?: string;
    userId?: string;
    user_name?: string;
    userName?: string;
    emoji: string;
    created_at?: string;
  }) => {
    logger.debug('Reaction added via realtime:', data)
    
    // Normalize field names (handle both camelCase and snake_case)
    const userId = data.mongo_user_id || data.userId || ''
    const messageId = data.message_id || data.messageId || ''
    const channelId = data.channel_id || data.channelId || ''
    const reactionId = data.id || data.reactionId || ''
    const userName = data.user_name || data.userName || 'Someone'
    
    // Skip reactions from self (already handled optimistically)
    if (userId === sessionUserId) return
    
    // Ensure we have proper user info and emoji
    const reactionData = {
      id: reactionId,
      mongo_user_id: userId,
      user_name: userName,
      emoji: data.emoji,
      created_at: data.created_at || new Date().toISOString()
    }
    
    dispatch(addReactionToMessage({
      channelId: channelId,
      messageId: messageId,
      reaction: reactionData
    }))
  }, [dispatch, sessionUserId])

  // Handle reaction removed (real-time) - WhatsApp style
  const onReactionRemove = useCallback((data: {
    id?: string;
    reactionId?: string;
    message_id?: string;
    messageId?: string;
    channel_id?: string;
    channelId?: string;
    mongo_user_id?: string;
    userId?: string;
    emoji: string;
  }) => {
    logger.debug('Reaction removed via realtime:', data)
    
    // Normalize field names (handle both camelCase and snake_case)
    const userId = data.mongo_user_id || data.userId || ''
    const messageId = data.message_id || data.messageId || ''
    const channelId = data.channel_id || data.channelId || ''
    const reactionId = data.id || data.reactionId || ''
    
    // Skip reactions from self (already handled optimistically)
    if (userId === sessionUserId) return
    
    dispatch(removeReactionFromMessage({
      channelId: channelId,
      messageId: messageId,
      reactionId: reactionId,
      mongo_user_id: userId,
      emoji: data.emoji
    }))
  }, [dispatch, sessionUserId])

  // ============================================
  // Channel Real-time Event Handlers (Phase 3)
  // ============================================

  // Handle channel update (archive/unarchive, settings changes, new channels, etc.)
  const onChannelUpdate = useCallback((data: {
    id: string;
    type: 'update' | 'archive' | 'unarchive' | 'member_left' | 'new_channel' | 'channel_removed' | 'member_added' | 'member_removed';
    channel?: any;
    member_id?: string;
    members?: any[];
    channelId?: string;
    memberId?: string;
    user?: any;
  }) => {
    logger.debug('🔄 Channel update received:', data)
    
    if (data.type === 'new_channel' && data.channel) {
      // New channel created - check if current user is a member
      const channelMembers = data.channel.channel_members || data.channel.members || []
      const isMember = channelMembers.some((m: any) => 
        m.mongo_member_id === sessionUserId || m.user_id === sessionUserId || m.id === sessionUserId
      )
      
      logger.debug('🆕 New channel received, isMember:', isMember, 'userId:', sessionUserId)
      
      if (isMember) {
        dispatch(addChannel(data.channel as IChannel))
        // Update cache
        communicationCache.addChannelToCache(data.channel)
        toastRef.current({
          title: "New Channel",
          description: `You've been added to #${data.channel.name || 'the new channel'}`,
        })
        logger.debug('✅ Channel added to store and cache')
      } else {
        logger.debug('⚠️ User is not a member of this channel, skipping')
      }
    } else if (data.type === 'channel_removed') {
      // Current user was removed from channel
      dispatch(removeChannel(data.id))
      // Update cache
      communicationCache.removeChannelFromCache(data.id)
      toastRef.current({
        title: "Removed from Channel",
        description: `You've been removed from a channel`,
        variant: "destructive"
      })
      logger.debug('👋 Current user removed from channel:', data.id)
    } else if (data.type === 'member_added' && data.memberId === sessionUserId) {
      // Current user was added to channel
      // Note: This should be handled by the 'new_channel' event, but as backup
      logger.debug('➕ Current user added to channel:', data.channelId)
    } else if (data.type === 'member_removed' && data.memberId === sessionUserId) {
      // Current user was removed from channel
      dispatch(removeChannel(data.channelId || data.id))
      // Update cache
      communicationCache.removeChannelFromCache(data.channelId || data.id)
      toastRef.current({
        title: "Removed from Channel",
        description: `You've been removed from a channel`,
        variant: "destructive"
      })
      logger.debug('👋 Current user removed from channel:', data.channelId || data.id)
    } else if (data.type === 'member_left' && data.member_id === sessionUserId) {
      // Current user left channel
      dispatch(removeChannel(data.id))
      // Update cache
      communicationCache.removeChannelFromCache(data.id)
      logger.debug('👋 Current user left channel:', data.id)
    } else if (data.channel) {
      // Channel updated (archive/unarchive, name change, etc.)
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { id: _channelId, ...updates } = data.channel
      dispatch(updateChannel({
        id: data.id,
        ...updates
      }))
      // Update cache
      communicationCache.updateChannelInCache(data.id, data.channel)
      logger.debug('📝 Channel updated:', data.id)
    }
  }, [dispatch, sessionUserId])

  // Handle attachments added to message (real-time)
  const onAttachmentsAdded = useCallback((data: { channelId: string; messageId?: string; attachments: any[] }) => {
    logger.debug('📎 Attachments added to message:', data)
    
    if (data.messageId && data.attachments?.length > 0) {
      // Update the message with new attachments
      dispatch(updateMessage({
        channelId: data.channelId,
        messageId: data.messageId,
        updates: { attachments: data.attachments }
      }))
      
      toastRef.current({
        title: "Files uploaded",
        description: `${data.attachments.length} file(s) uploaded successfully`,
      })
    }
  }, [dispatch])

  // ============================================
  // Trash-Related Event Handlers (Phase 2)
  // ============================================

  // Handle message trashed (real-time)
  const onMessageTrashed = useCallback((data: {
    message_id: string;
    channel_id: string;
    trashed_by: string;
    trashed_at: string;
    trash_reason?: string;
  }) => {
    logger.debug('Message trashed:', data)
    
    // Don't process if we initiated the trash action (already handled optimistically)
    if (data.trashed_by === sessionUserId) return
    
    dispatch(moveMessageToTrash({
      channelId: data.channel_id,
      messageId: data.message_id,
      trashedAt: data.trashed_at,
      trashedBy: data.trashed_by,
      trashReason: data.trash_reason
    }))
  }, [dispatch, sessionUserId])

  // Handle message restored (real-time)
  const onMessageRestored = useCallback((data: {
    message: ICommunication;
    restored_by: string;
    channel_id: string;
  }) => {
    logger.debug('Message restored:', data)
    
    // Don't process if we initiated the restore (already handled optimistically)
    if (data.restored_by === sessionUserId) return
    
    dispatch(restoreMessageFromTrash({
      messageId: data.message.id,
      channelId: data.channel_id,
      restoredMessage: data.message
    }))
  }, [dispatch, sessionUserId])

  // Handle message hidden (real-time - only affects current user)
  const onMessageHidden = useCallback((data: {
    message_id: string;
    channel_id: string;
    hidden_by: string;
  }) => {
    logger.debug('Message hidden:', data)
    
    // Only hide if the current user initiated the hide
    if (data.hidden_by === sessionUserId) {
      dispatch(hideMessageForSelf({
        channelId: data.channel_id,
        messageId: data.message_id
      }))
    }
  }, [dispatch, sessionUserId])

  // Handle message permanently deleted (real-time)
  const onMessagePermanentlyDeleted = useCallback((data: {
    message_id: string;
    channel_id: string;
    deleted_by: string;
  }) => {
    logger.debug('Message permanently deleted:', data)
    
    // Remove from trash if present
    dispatch(permanentlyDeleteMessage({ messageId: data.message_id }))
    
    // Also remove from active messages in case it wasn't in trash
    if (messages[data.channel_id]) {
      const messageExists = messages[data.channel_id].some(m => m.id === data.message_id)
      if (messageExists) {
        dispatch(hideMessageForSelf({
          channelId: data.channel_id,
          messageId: data.message_id
        }))
      }
    }
  }, [dispatch, messages])

  // ============================================
  // Initialization Effects
  // ============================================

  // Set current user ID in store
  useEffect(() => {
    if (sessionUserId && sessionUserId !== storeCurrentUserId) {
      dispatch(setCurrentUserId(sessionUserId))
    }
  }, [sessionUserId, storeCurrentUserId, dispatch])

  // Initialize presence tracking
  useEffect(() => {
    const initPresence = async () => {
      if (sessionUserId && sessionUserName && !presenceInitializedRef.current) {
        presenceInitializedRef.current = true
        try {
          await realtimeManager.initializePresence(
            sessionUserId,
            sessionUserName,
            sessionUserAvatar
          )
          logger.debug('Presence initialized for:', sessionUserId)
        } catch (error) {
          logger.error('Failed to initialize presence:', error)
          presenceInitializedRef.current = false
        }
      }
    }
    
    initPresence()
    
    // Cleanup on unmount
    return () => {
      // Don't cleanup presence on component unmount, keep user online
    }
  }, [sessionUserId, sessionUserName, sessionUserAvatar, realtimeManager])

  // Fetch channels on mount - check cache expiry first
  useEffect(() => {
    logger.debug('Channels fetch useEffect running, hasFetchedChannels:', hasFetchedChannelsRef.current, 'sessionUserId:', sessionUserId, 'loading:', loading)
    if (sessionUserId && !loading) {
      // Check if we need to fetch channels
      const cachedChannels = communicationCache.getChannels()
      const shouldFetch = !cachedChannels || !globalFetchedChannels.get(sessionUserId)
      
      if (shouldFetch) {
        globalFetchedChannels.set(sessionUserId, true)
        hasFetchedChannelsRef.current = true
        channelsFetchedRef.current = true
        logger.debug('Fetching channels')
        fetchChannels()
      } else {
        logger.debug('Using cached channels, skipping fetch')
        // Still dispatch cached channels to ensure state is set
        dispatch(setChannels(cachedChannels))
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionUserId]) // Only depend on sessionUserId

  // Subscribe to active channel
  useEffect(() => {
    const subscribe = async () => {
      if (activeChannelId) {
        logger.debug('Subscribing to channel:', activeChannelId)
        try {
          await realtimeManager.subscribeToChannel(activeChannelId)
          // fetchMessages is now handled in selectChannel
        } catch (error) {
          logger.error('Failed to subscribe to channel:', error)
        }
      }
    }
    subscribe()

    return () => {
      if (activeChannelId) {
        logger.debug('Unsubscribing from channel:', activeChannelId)
        // Send typing stop if user was typing
        if (sessionUserId) {
          realtimeManager.sendTypingStop(activeChannelId, sessionUserId)
        }
        realtimeManager.unsubscribeFromChannel(activeChannelId)
        dispatch(clearTypingForChannel(activeChannelId))
      }
    }
  }, [activeChannelId, realtimeManager, sessionUserId, dispatch])

  // Track whether handlers have been set - use state to trigger re-render
  const [handlersReady, setHandlersReady] = useState(false)

  // Update handlers when they change - MUST happen before subscribing
  useEffect(() => {
    const handlers: RealtimeEventHandlers = {
      onNewMessage,
      onMessageUpdate,
      onMessageDelete,
      onMessageRead,
      onMessageDelivered,
      onUserJoined,
      onUserLeft,
      onUserOnline,
      onUserOffline,
      onTypingStart,
      onTypingStop,
      onPresenceSync,
      onMentionNotification,
      onNewMessageNotification,
      onReactionAdd,
      onReactionRemove,
      onChannelUpdate,
      onUserPin,
      onAttachmentsAdded
    }
    realtimeManager.updateHandlers(handlers)
    setHandlersReady(true)
    logger.debug('✅ Realtime handlers updated')
  }, [realtimeManager, onNewMessage, onMessageUpdate, onMessageDelete, onMessageRead, onMessageDelivered, onUserJoined, onUserLeft, onUserOnline, onUserOffline, onTypingStart, onTypingStop, onPresenceSync, onMentionNotification, onNewMessageNotification, onReactionAdd, onReactionRemove, onChannelUpdate, onUserPin, onAttachmentsAdded])

  // Subscribe to notifications when user is logged in AND handlers are set
  // NOTE: We don't unsubscribe on cleanup because notifications should persist
  // across component lifecycle. The RealtimeProvider manages the global lifecycle.
  useEffect(() => {
    // Wait for handlers to be set before subscribing
    if (!sessionUserId || !handlersReady) {
      logger.debug('⏳ Waiting for handlers to be ready before subscribing to notifications')
      return
    }
    
    const subscribeWithRetry = async () => {
      try {
        await realtimeManager.subscribeToNotifications(sessionUserId)
        logger.debug('✅ Subscribed to notifications for user:', sessionUserId)
      } catch (err) {
        logger.error('Failed to subscribe to notifications:', err)
        // Retry with exponential backoff
        const retryDelays = [2000, 4000, 8000]
        for (const delay of retryDelays) {
          await new Promise(resolve => setTimeout(resolve, delay))
          try {
            await realtimeManager.subscribeToNotifications(sessionUserId)
            logger.debug(`✅ Retry: Subscribed to notifications for user after ${delay}ms:`, sessionUserId)
            return
          } catch (retryErr) {
            logger.error(`Retry failed for notifications after ${delay}ms:`, retryErr)
          }
        }
      }
    }
    
    subscribeWithRetry()
    
    realtimeManager.subscribeToUserChannels(sessionUserId).catch(err => {
      logger.error('Failed to subscribe to user channels:', err)
    })
    // No cleanup - notification subscriptions are managed by RealtimeProvider
    // and should persist for the entire session
  }, [sessionUserId, realtimeManager, handlersReady])

  // Channel operations
  const fetchChannels = useCallback(async (
    params: { type?: string; department_id?: string; project_id?: string; forceRefresh?: boolean } = {}
  ) => {
    logger.debug('fetchChannels called with params:', params)
    
    // Check cache first (only for unfiltered requests)
    const isUnfiltered = !params.type && !params.department_id && !params.project_id
    if (isUnfiltered && !params.forceRefresh) {
      const cachedChannels = communicationCache.getChannels()
      if (cachedChannels) {
        logger.debug('Using cached channels:', cachedChannels.length)
        dispatch(setChannels(cachedChannels))
        return cachedChannels
      }
    }
    
    try {
      dispatch(setLoading(true))
      // Build query string
      const queryParams = new URLSearchParams()
      if (params.type) queryParams.append('type', params.type)
      if (params.department_id) queryParams.append('department_id', params.department_id)
      if (params.project_id) queryParams.append('project_id', params.project_id)
      
      const queryString = queryParams.toString()
      const url = `/api/communication/channels${queryString ? `?${queryString}` : ''}`
      
      const response = await apiRequest(url)
      logger.debug('Channels loaded:', response?.length || 0)
      
      // Cache the response (only for unfiltered requests)
      if (isUnfiltered) {
        communicationCache.setChannels(response)
      }
      
      dispatch(setChannels(response))
      return response  
    } catch (error) {
      dispatch(setError('Failed to fetch channels'))
      dispatch(setChannelsInitialized(true)) // Prevent infinite retries
      toastRef.current({
        title: "Error",
        description: "Failed to load channels",
        variant: "destructive"
      })
      return []
    } finally {
      dispatch(setLoading(false))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dispatch]) // Removed toast from dependencies to prevent infinite loop

  // Message operations
  const fetchMessages = useCallback(async (params: FetchMessagesParams) => {
    try {
      dispatch(setMessagesLoading(true))
      // Build query string
      const MESSAGE_LIMIT = params.limit || 50
      const queryParams = new URLSearchParams({
        channel_id: params.channel_id,
        limit: MESSAGE_LIMIT.toString(),
        offset: '0'
      })
      
      const response = await apiRequest(`/api/communication/messages?${queryParams.toString()}`)
      dispatch(setMessages({ channelId: params.channel_id, messages: response.data || response }))

      logger.debug('Fetched messages:', response.data?.length || response?.length || 0)
      return response
    } catch (error) {
      dispatch(setError('Failed to fetch messages'))
      toastRef.current({
        title: "Error",
        description: "Failed to load messages",
        variant: "destructive"
      })
      return []
    } finally {
      dispatch(setMessagesLoading(false))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dispatch]) // Removed toast to prevent infinite loop

  const selectChannel = useCallback(async (channel_id: string) => {
    // Get current unread count before any updates
    const currentChannels = currentChannelsRef.current
    const channel = currentChannels.find(c => c.id === channel_id)
    const currentUnread = channel?.unreadCount || 0

    // Set active channel and clear notifications for this channel
    dispatch(setActiveChannel(channel_id))
    dispatch(clearNotificationsForChannel(channel_id))
    
    // Optimistically reset unread count immediately
    if (currentUnread > 0) {
      dispatch(updateChannel({
        id: channel_id,
        unreadCount: 0
      }))
      dispatch(decrementUnreadCount(currentUnread))
      // Also update the cache to keep it in sync
      communicationCache.updateChannelInCache(channel_id, { unreadCount: 0 })
    }

    // Clear messages to force re-fetch with enriched data
    dispatch(setMessages({ channelId: channel_id, messages: [] }))

    // Mark all messages in this channel as read using the bulk API
    // This is done in parallel with fetching messages for better UX
    const markAllReadPromise = (async () => {
      if (currentUnread > 0) {
        try {
          await apiRequest('/api/communication/read-receipts', {
            method: 'POST',
            body: JSON.stringify({ 
              channel_id,
              mark_all: true
            })
          })
          logger.debug(`Marked all messages as read in channel ${channel_id}`)
        } catch (apiError) {
          // Revert optimistic update on failure
          dispatch(updateChannel({
            id: channel_id,
            unreadCount: currentUnread
          }))
          dispatch(incrementUnreadCount(currentUnread))
          // Revert cache update
          communicationCache.updateChannelInCache(channel_id, { unreadCount: currentUnread })
          logger.error('Failed to mark messages as read when selecting channel:', apiError)
        }
      }
    })()

    // Always fetch messages to ensure fresh data, even for the same channel
    const fetchMessagesPromise = fetchMessages({ channel_id })

    // Wait for both operations to complete
    await Promise.all([markAllReadPromise, fetchMessagesPromise])
  }, [dispatch, fetchMessages])

  const clearChannel = useCallback(() => {
    dispatch(clearActiveChannel())
  }, [dispatch])

  // Fetch older messages (pagination - prepend to existing)
  const fetchOlderMessages = useCallback(async (params: FetchMessagesParams & { offset: number }) => {
    try {
      const OLDER_MESSAGE_LIMIT = params.limit || 30
      const queryParams = new URLSearchParams({
        channel_id: params.channel_id,
        limit: OLDER_MESSAGE_LIMIT.toString(),
        offset: params.offset.toString()
      })
      
      const response = await apiRequest(`/api/communication/messages?${queryParams.toString()}`)
      const olderMessages = response.data || response
      
      return {
        messages: olderMessages,
        hasMore: olderMessages.length === OLDER_MESSAGE_LIMIT
      }
    } catch (error) {
      logger.error('Failed to fetch older messages:', error)
      return { messages: [], hasMore: false }
    }
  }, [])

  // Search messages in a channel (consolidated endpoint)
  const searchMessages = useCallback(async (channelId: string, query: string, limit = 20, offset = 0) => {
    try {
      const response = await fetch(`/api/communication/messages?channel_id=${channelId}&search=${encodeURIComponent(query)}&limit=${limit}&offset=${offset}`)
      const data = await response.json()
      if (data.success) {
        return {
          messages: data.data || [],
          total: data.meta?.total || 0,
          hasMore: data.meta?.hasMore || false
        }
      } else {
        return { messages: [], total: 0, hasMore: false }
      }
    } catch (error) {
      logger.error('Failed to search messages:', error)
      return { messages: [], total: 0, hasMore: false }
    }
  }, [])

  const sendMessage = useCallback(async (messageData: CreateMessageData) => {
    const tempId = crypto.randomUUID()
    try {
      // Note: Don't set actionLoading for text messages - use optimistic updates without blocking UI
      // This prevents the input from being disabled during send

      // Get sender info from session for optimistic update
      const senderName = sessionUser?.name || sessionUser?.email || 'Unknown User'
      const senderEmail = sessionUser?.email || ''
      const senderAvatar = sessionUser?.image || sessionUser?.avatar || ''
      const senderRole = sessionUser?.role || 'User'

      // Create optimistic message with denormalized sender fields
      const optimisticMessage = {
        id: tempId,
        channel_id: messageData.channel_id,
        mongo_sender_id: sessionUserId!,
        content: messageData.content,
        content_type: messageData.content_type || 'text',
        thread_id: messageData.thread_id,
        parent_message_id: messageData.parent_message_id,
        mongo_mentioned_user_ids: messageData.mongo_mentioned_user_ids || [],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        read_receipts: [],
        reactions: [],
        attachments: [],
        reply_count: 0,
        is_edited: false,
        isOptimistic: true, // Flag to identify optimistic messages
        // Denormalized sender fields (same as stored in Supabase)
        sender_name: senderName,
        sender_email: senderEmail,
        sender_avatar: senderAvatar,
        sender_role: senderRole,
        // Computed sender object for UI compatibility
        sender: {
          mongo_member_id: sessionUserId!,
          name: senderName,
          email: senderEmail,
          avatar: senderAvatar,
          role: senderRole,
          userType: 'User' as 'User' | 'Client',
          isOnline: true
        }
      }

      // Add optimistic message to state
      dispatch(addMessage({ channelId: messageData.channel_id, message: optimisticMessage }))

      // Send to API
      const response = await apiRequest('/api/communication/messages', {
        method: 'POST',
        body: JSON.stringify(messageData)
      })
      // Check if response is valid
      if (!response || !response.id) {
        logger.error('Invalid response from API:', response)
        dispatch(updateMessage({
          channelId: messageData.channel_id,
          messageId: tempId,
          updates: { isFailed: true }
        }))
        return
      }
      if (response.id) {
        dispatch(updateMessage({
          channelId: messageData.channel_id,
          messageId: tempId,
          updates: { ...response, isOptimistic: false }
        }))
      }

      // Broadcast is now handled by the API route
      // console.log('📤 Broadcasting message, channel_id:', messageData.channel_id)
      // await realtimeManager.broadcastMessage(messageData.channel_id, response)

      toastRef.current({
        title: "Message sent",
        description: "Your message has been sent successfully",
      })
      

      return response.message
    } catch (error) {
      // Mark optimistic message as failed
      dispatch(updateMessage({
        channelId: messageData.channel_id,
        messageId: tempId,
        updates: { isFailed: true }
      }))

      dispatch(setError('Failed to send message'))
      toastRef.current({
        title: "Error",
        description: "Failed to send message",
        variant: "destructive"
      })
      throw error
    }
    // Note: No finally block needed - we don't set actionLoading for text messages
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dispatch, sessionUserId, allUsers, realtimeManager]) // Removed toast to prevent infinite loop

  // Send message with file attachments
  const sendMessageWithFiles = useCallback(async (
    messageData: CreateMessageData,
    files: File[],
    onProgress?: (progress: number) => void
  ) => {
    const tempId = crypto.randomUUID()
    try {
      dispatch(setActionLoading(true))

      // Get sender info from session for optimistic update
      const senderName = sessionUser?.name || sessionUser?.email || 'Unknown User'
      const senderEmail = sessionUser?.email || ''
      const senderAvatar = sessionUser?.image || sessionUser?.avatar || ''
      const senderRole = sessionUser?.role || 'User'

      // Create optimistic message with placeholder attachments
      const optimisticAttachments = files.map((file, index) => ({
        id: `temp_${index}`,
        message_id: tempId,
        file_name: file.name,
        file_url: URL.createObjectURL(file),
        file_size: file.size,
        file_type: file.type,
        created_at: new Date().toISOString(),
        isUploading: true
      }))

      const optimisticMessage = {
        id: tempId,
        channel_id: messageData.channel_id,
        mongo_sender_id: sessionUserId!,
        content: messageData.content,
        content_type: files.length > 0 ? 'file' : (messageData.content_type || 'text'),
        thread_id: messageData.thread_id,
        parent_message_id: messageData.parent_message_id,
        mongo_mentioned_user_ids: messageData.mongo_mentioned_user_ids || [],
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        read_receipts: [],
        reactions: [],
        attachments: optimisticAttachments,
        reply_count: 0,
        is_edited: false,
        isOptimistic: true,
        sender_name: senderName,
        sender_email: senderEmail,
        sender_avatar: senderAvatar,
        sender_role: senderRole,
        sender: {
          mongo_member_id: sessionUserId!,
          name: senderName,
          email: senderEmail,
          avatar: senderAvatar,
          role: senderRole,
          userType: 'User' as 'User' | 'Client',
          isOnline: true
        }
      }

      // Add optimistic message to state
      dispatch(addMessage({ channelId: messageData.channel_id, message: optimisticMessage }))

      // Build form data
      const formData = new FormData()
      formData.append('channel_id', messageData.channel_id)
      formData.append('content', messageData.content || '')
      formData.append('content_type', messageData.content_type || 'text')
      if (messageData.thread_id) {
        formData.append('thread_id', messageData.thread_id)
      }
      if (messageData.parent_message_id) {
        formData.append('parent_message_id', messageData.parent_message_id)
      }
      if (messageData.mongo_mentioned_user_ids?.length) {
        formData.append('mongo_mentioned_user_ids', JSON.stringify(messageData.mongo_mentioned_user_ids))
      }
      files.forEach(file => {
        formData.append('files', file)
      })

      // Upload via XHR for progress tracking
      const response = await new Promise<any>((resolve, reject) => {
        const xhr = new XMLHttpRequest()

        xhr.upload.addEventListener('progress', (event) => {
          if (event.lengthComputable) {
            const progress = Math.round((event.loaded / event.total) * 100)
            onProgress?.(progress)
          }
        })

        xhr.addEventListener('load', () => {
          if (xhr.status === 200) {
            const response = JSON.parse(xhr.responseText)
            if (response.success) {
              resolve(response.data)
            } else {
              reject(new Error(response.error || 'Upload failed'))
            }
          } else {
            reject(new Error(`Upload failed with status ${xhr.status}`))
          }
        })

        xhr.addEventListener('error', () => {
          reject(new Error('Network error during upload'))
        })

        // Use consolidated messages endpoint (handles both JSON and FormData)
        xhr.open('POST', '/api/communication/messages')
        xhr.send(formData)
      })

      // Update optimistic message with real ID (keep optimistic attachments until real-time update)
      if (response?.id) {
        dispatch(updateMessage({
          channelId: messageData.channel_id,
          messageId: tempId,
          updates: { 
            id: response.id, 
            isOptimistic: false,
            // Keep optimistic attachments until real-time update with actual attachments
          }
        }))
      }

      toastRef.current({
        title: files.length > 0 ? "Files sent" : "Message sent",
        description: files.length > 0 
          ? `${files.length} file(s) uploaded successfully`
          : "Your message has been sent successfully",
      })

      return response
    } catch (error) {
      // Mark optimistic message as failed
      dispatch(updateMessage({
        channelId: messageData.channel_id,
        messageId: tempId,
        updates: { isFailed: true }
      }))

      dispatch(setError('Failed to send message with files'))
      toastRef.current({
        title: "Error",
        description: "Failed to send message with files",
        variant: "destructive"
      })
      throw error
    } finally {
      dispatch(setActionLoading(false))
    }
  }, [dispatch, sessionUserId, sessionUser])

  // Update an existing message (for editing)
  const editMessage = useCallback(async (messageId: string, updates: { content?: string; newFiles?: File[]; attachmentsToRemove?: string[] }) => {
    try {
      dispatch(setActionLoading(true))

      // Find the message to get channel_id
      let channelId = ''
      for (const [chId, msgs] of Object.entries(messages)) {
        const msg = msgs.find((m: ICommunication) => m.id === messageId)
        if (msg) {
          channelId = chId
          break
        }
      }

      if (!channelId) {
        throw new Error('Message not found')
      }

      // Prepare the update payload
      let requestBody: any
      let headers: any = {}

      // If we have new files, use FormData
      if (updates.newFiles && updates.newFiles.length > 0) {
        const formData = new FormData()
        formData.append('content', updates.content || '')
        
        if (updates.attachmentsToRemove && updates.attachmentsToRemove.length > 0) {
          formData.append('attachments_to_remove', JSON.stringify(updates.attachmentsToRemove))
        }
        
        updates.newFiles.forEach(file => {
          formData.append('files', file)
        })
        
        requestBody = formData
        // Don't set Content-Type header - let the browser set it for FormData
      } else {
        // Use JSON for content-only updates
        requestBody = JSON.stringify({
          content: updates.content,
          attachments_to_remove: updates.attachmentsToRemove || []
        })
        headers['Content-Type'] = 'application/json'
      }

      // Optimistically update the message
      const optimisticUpdates: any = {
        content: updates.content,
        is_edited: true,
        edited_at: new Date().toISOString()
      }

      // Handle attachment changes optimistically
      const currentMessage = messages[channelId]?.find((m: ICommunication) => m.id === messageId)
      if (currentMessage) {
        let updatedAttachments = [...(currentMessage.attachments || [])]
        
        // Remove attachments
        if (updates.attachmentsToRemove) {
          updatedAttachments = updatedAttachments.filter(att => 
            !updates.attachmentsToRemove!.includes(att.id)
          )
        }
        
        // For new files, we'll add placeholder attachments (they'll be replaced by real data from API)
        if (updates.newFiles && updates.newFiles.length > 0) {
          const placeholderAttachments: IAttachment[] = updates.newFiles.map(file => ({
            id: `temp-${Date.now()}-${Math.random()}`,
            message_id: messageId,
            file_name: file.name,
            file_size: file.size,
            file_type: file.type,
            file_url: undefined,
            uploaded_by: sessionUserId,
            created_at: new Date().toISOString()
          }))
          updatedAttachments = [...updatedAttachments, ...placeholderAttachments]
        }
        
        optimisticUpdates.attachments = updatedAttachments
      }

      dispatch(updateMessage({
        channelId,
        messageId,
        updates: optimisticUpdates
      }))

      // Send to API
      const response = await apiRequest(`/api/communication/messages/${messageId}`, {
        method: 'PUT',
        headers,
        body: requestBody
      })

      if (response?.id) {
        dispatch(updateMessage({
          channelId,
          messageId,
          updates: response
        }))
      }

      toastRef.current({
        title: "Message updated",
        description: "Your message has been edited",
      })

      return response
    } catch (error) {
      dispatch(setError('Failed to update message'))
      toastRef.current({
        title: "Error",
        description: "Failed to update message",
        variant: "destructive"
      })
      throw error
    } finally {
      dispatch(setActionLoading(false))
    }
  }, [dispatch, messages, sessionUserId])

  const createChannel = useCallback(async (channelData: CreateChannelData) => {
    try {
      dispatch(setActionLoading(true))
      const response = await apiRequest('/api/communication/channels', {
        method: 'POST',
        body: JSON.stringify(channelData)
      })

      // Add the new channel to Redux state immediately (optimistic update)
      if (response?.id) {
        dispatch(addChannel(response as IChannel))
        // Also update cache
        communicationCache.addChannelToCache(response)
      }

      toastRef.current({
        title: "Channel created",
        description: "New conversation started successfully",
      })

      return response
    } catch (error) {
      dispatch(setError('Failed to create channel'))
      toastRef.current({
        title: "Error",
        description: "Failed to create channel",
        variant: "destructive"
      })
      throw error
    } finally {
      dispatch(setActionLoading(false))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dispatch]) // Removed fetchChannels - using optimistic update now

  // ============================================
  // Channel Pin Operations
  // ============================================

  /**
   * Toggle pin status for a channel
   * User can pin up to 5 channels
   */
  const pinChannel = useCallback(async (channelId: string, currentlyPinned: boolean): Promise<void> => {
    if (!sessionUserId) {
      throw new Error('Not authenticated')
    }

    // Optimistic update
    dispatch(updateChannel({
      id: channelId,
      is_pinned: !currentlyPinned,
      pinned_at: !currentlyPinned ? new Date().toISOString() : null
    }))

    try {
      const response = await apiRequest(`/api/communication/channels/${channelId}?action=pin`, {
        method: 'POST'
      }, false)

      toastRef.current({
        title: response.is_pinned ? "Channel pinned" : "Channel unpinned",
        description: "Channel pin status updated successfully",
      })

      // No need to refresh channels - optimistic update and real-time sync handle it
    } catch (error: any) {
      // Revert optimistic update
      dispatch(updateChannel({
        id: channelId,
        is_pinned: currentlyPinned,
        pinned_at: currentlyPinned ? new Date().toISOString() : null
      }))

      throw error
    }
  }, [dispatch, sessionUserId])

  /**
   * Toggle pin status for a user
   * User can pin up to 10 users
   */
  const pinUser = useCallback(async (userId: string, currentlyPinned: boolean): Promise<void> => {
    if (!sessionUserId) {
      throw new Error('Not authenticated')
    }

    // Optimistic update - we need to handle this in the component since users are not in Redux
    // For now, we'll just make the API call and rely on real-time updates

    try {
      const response = await apiRequest(`/api/communication/users/${userId}/pin`, {
        method: 'POST'
      }, false)

      toastRef.current({
        title: response.is_pinned ? "User pinned" : "User unpinned",
        description: "User pin status updated successfully",
      })

      // Real-time sync will handle the update
    } catch (error: any) {
      throw error
    }
  }, [sessionUserId])

  /**
   * Toggle mute/notification status for a channel
   * When muted, notifications are disabled for this channel
   * Note: notifications_enabled is a per-member setting stored in channel_members
   */
  const muteChannel = useCallback(async (channelId: string, currentlyMuted: boolean): Promise<{ notifications_enabled: boolean }> => {
    if (!sessionUserId) {
      throw new Error('Not authenticated')
    }

    try {
      const response = await apiRequest(`/api/communication/channels/${channelId}?action=mute`, {
        method: 'POST'
      }, false)

      // Update the channel's member data with the new mute status
      const channel = channels.find(c => c.id === channelId)
      if (channel) {
        const updatedMembers = channel.channel_members.map(member => 
          member.mongo_member_id === sessionUserId 
            ? { ...member, notifications_enabled: response.data.notifications_enabled }
            : member
        )
        dispatch(updateChannel({
          id: channelId,
          channel_members: updatedMembers
        }))
      }

      toastRef.current({
        title: response.data.notifications_enabled ? "Notifications enabled" : "Notifications muted",
        description: response.data.notifications_enabled 
          ? "You will receive notifications for this channel"
          : "You won't receive notifications for this channel",
      })

      return { notifications_enabled: response.data.notifications_enabled }
    } catch (error: any) {
      throw error
    }
  }, [channels, dispatch, sessionUserId])

  const markAsRead = useCallback(async (messageId: string, channel_id: string) => {
    try {
      await apiRequest('/api/communication/read-receipts', {
        method: 'POST',
        body: JSON.stringify({ message_id: messageId, channel_id })
      })

      // Remove notification for this message
      dispatch(removeNotification(`message_${messageId}`))

      // Update unread count in Redux store
      const channel = channels.find(c => c.id === channel_id)
      const newUnreadCount = Math.max(0, (channel?.unreadCount || 0) - 1)
      dispatch(updateChannel({
        id: channel_id,
        unreadCount: newUnreadCount
      }))
      dispatch(decrementUnreadCount(1))

      // Broadcast read receipt to other users in the channel
      if (sessionUserId) {
        await realtimeManager.broadcastMessageRead(channel_id, messageId, sessionUserId)
      }
    } catch (error) {
      logger.error('Failed to mark message as read:', error)
    }
  }, [channels, dispatch, realtimeManager, sessionUserId])

  /**
   * Mark all messages in a channel as read.
   * Uses the bulk API endpoint for efficiency.
   */
  const markAllChannelMessagesAsRead = useCallback(async (channelId: string) => {
    try {
      const channel = channels.find(c => c.id === channelId)
      const currentUnread = channel?.unreadCount || 0
      
      if (currentUnread === 0) return
      
      // Optimistically update Redux state
      dispatch(updateChannel({
        id: channelId,
        unreadCount: 0
      }))
      dispatch(decrementUnreadCount(currentUnread))
      dispatch(clearNotificationsForChannel(channelId))
      
      // Also update the cache to keep it in sync
      communicationCache.updateChannelInCache(channelId, { unreadCount: 0 })

      // Call the bulk API
      await apiRequest('/api/communication/read-receipts', {
        method: 'POST',
        body: JSON.stringify({ 
          channel_id: channelId,
          mark_all: true
        })
      })
      
      logger.debug(`Marked all messages as read in channel ${channelId}`)
    } catch (error) {
      // Revert optimistic update
      const channel = channels.find(c => c.id === channelId)
      const currentUnread = channel?.unreadCount || 0
      dispatch(updateChannel({
        id: channelId,
        unreadCount: currentUnread
      }))
      dispatch(incrementUnreadCount(currentUnread))
      // Revert cache update
      communicationCache.updateChannelInCache(channelId, { unreadCount: currentUnread })
      logger.error('Failed to mark all channel messages as read:', error)
    }
  }, [channels, dispatch])

  // ============================================
  // Reaction Operations
  // ============================================

  /**
   * Toggle a reaction on a message.
   * If the user already reacted with this emoji, it will be removed.
   * Otherwise, it will be added.
   */
  const toggleReaction = useCallback(async (messageId: string, channelId: string, emoji: string) => {
    logger.debug('toggleReaction called:', { messageId, channelId, emoji, sessionUserId })
    
    if (!sessionUserId) return
    
    // Validate emoji parameter before proceeding
    if (!emoji || emoji.length > 10 || emoji.includes('-') || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(emoji)) {
      logger.error('Invalid emoji received:', emoji)
      toastRef.current({
        title: "Error",
        description: "Invalid emoji detected. Please try again.",
        variant: "destructive"
      })
      return
    }

    try {
      // Check if user already reacted with this emoji
      const channelMessages = messages[channelId] || []
      const message = channelMessages.find(m => m.id === messageId)
      const existingReaction = message?.reactions?.find(
        r => r.mongo_user_id === sessionUserId && r.emoji === emoji
      )

      if (existingReaction) {
        logger.debug('Removing existing reaction:', existingReaction.id)
        // Optimistically remove the reaction
        dispatch(removeReactionFromMessage({
          channelId,
          messageId,
          reactionId: existingReaction.id,
          mongo_user_id: sessionUserId,
          emoji
        }))
      } else {
        logger.debug('Adding new reaction with emoji:', emoji)
        // Optimistically add the reaction with proper user info
        const tempReactionId = crypto.randomUUID()
        const optimisticReaction = {
          id: tempReactionId,
          mongo_user_id: sessionUserId,
          user_name: sessionUserName || 'You',
          emoji: emoji, // Ensure emoji is properly set
          created_at: new Date().toISOString()
        }
        
        dispatch(addReactionToMessage({
          channelId,
          messageId,
          reaction: optimisticReaction
        }))
      }

      // Prepare API request data
      const apiData = {
        message_id: messageId,
        channel_id: channelId,
        emoji: emoji
      }
      
      logger.debug('Sending reaction API request:', apiData)

      // Send to API (toggle behavior handled on server)
      const result = await apiRequest('/api/communication/reactions', {
        method: 'POST',
        body: JSON.stringify(apiData)
      }, false) // Don't show error toast, we handle it ourselves

      logger.debug('Reaction API response:', { action: result?.action })
      logger.debug('Reaction toggled successfully:', { 
        action: result?.action,
        emoji,
        messageId,
        userId: sessionUserId 
      })
    } catch (error: any) {
      logger.error('Failed to toggle reaction:', error)
      
      // Check if user already reacted with this emoji (for reverting optimistic update)
      const channelMessages = messages[channelId] || []
      const message = channelMessages.find(m => m.id === messageId)
      const existingReaction = message?.reactions?.find(
        r => r.mongo_user_id === sessionUserId && r.emoji === emoji
      )
      
      // Revert optimistic update on error
      if (existingReaction) {
        // We had removed it, re-add it
        dispatch(addReactionToMessage({
          channelId,
          messageId,
          reaction: existingReaction
        }))
      } else {
        // We had added it, remove it
        dispatch(removeReactionFromMessage({
          channelId,
          messageId,
          mongo_user_id: sessionUserId,
          emoji
        }))
      }
      
      toastRef.current({
        title: "Error",
        description: error?.error || "Failed to toggle reaction",
        variant: "destructive"
      })
    }
  }, [dispatch, messages, sessionUserId, sessionUserName])

  // ============================================
  // Trash Operations (Phase 2: Message Lifecycle)
  // ============================================

  /**
   * Move a message to trash (soft delete with 30-day restoration window)
   * Only the message owner or admin can do this
   */
  const moveToTrash = useCallback(async (messageId: string, channelId: string, reason?: string) => {
    if (!sessionUserId) return { success: false, error: 'Not authenticated' }

    try {
      dispatch(setActionLoading(true))

      // Optimistically move to trash
      dispatch(moveMessageToTrash({
        channelId,
        messageId,
        trashedAt: new Date().toISOString(),
        trashedBy: sessionUserId,
        trashReason: reason
      }))

      // Send to API - use query params as expected by the API route
      const queryParams = new URLSearchParams({ deleteType: 'trash' })
      if (reason) queryParams.set('reason', reason)
      
      const response = await apiRequest(`/api/communication/messages/${messageId}?${queryParams.toString()}`, {
        method: 'DELETE'
      })

      toastRef.current({
        title: "Message moved to trash",
        description: "You can restore it within 30 days",
      })

      return { success: true, data: response }
    } catch (error: any) {
      logger.error('Failed to move message to trash:', error)
      
      // Revert optimistic update - refetch messages
      if (activeChannelId) {
        fetchMessages({ channel_id: activeChannelId })
      }

      toastRef.current({
        title: "Error",
        description: error?.error || "Failed to move message to trash",
        variant: "destructive"
      })

      return { success: false, error: error?.error || 'Failed to move to trash' }
    } finally {
      dispatch(setActionLoading(false))
    }
  }, [dispatch, sessionUserId, activeChannelId, fetchMessages])

  /**
   * Hide a message for the current user only (Delete for Me)
   * The message remains visible to other users
   */
  const hideForSelf = useCallback(async (messageId: string, channelId: string) => {
    if (!sessionUserId) return { success: false, error: 'Not authenticated' }

    try {
      dispatch(setActionLoading(true))

      // Optimistically hide the message
      dispatch(hideMessageForSelf({
        channelId,
        messageId
      }))

      // Send to API - use query params as expected by the API route
      await apiRequest(`/api/communication/messages/${messageId}?deleteType=self`, {
        method: 'DELETE'
      })

      toastRef.current({
        title: "Message hidden",
        description: "This message will no longer appear for you",
      })

      return { success: true }
    } catch (error: any) {
      logger.error('Failed to hide message:', error)
      
      // Revert optimistic update - refetch messages
      if (activeChannelId) {
        fetchMessages({ channel_id: activeChannelId })
      }

      toastRef.current({
        title: "Error",
        description: error?.error || "Failed to hide message",
        variant: "destructive"
      })

      return { success: false, error: error?.error || 'Failed to hide message' }
    } finally {
      dispatch(setActionLoading(false))
    }
  }, [dispatch, sessionUserId, activeChannelId, fetchMessages])

  /**
   * Restore a message from trash
   * Only available within 30 days of trashing
   */
  const restoreFromTrash = useCallback(async (messageId: string) => {
    if (!sessionUserId) return { success: false, error: 'Not authenticated' }

    try {
      dispatch(setActionLoading(true))

      // Send to API first to get the restored message
      // Note: apiRequest unwraps successful responses, so we get the data directly
      const restoredMessage = await apiRequest(`/api/communication/messages/${messageId}?action=restore`, {
        method: 'POST'
      })

      if (restoredMessage && restoredMessage.id && restoredMessage.channel_id) {
        // Update Redux state with restored message
        dispatch(restoreMessageFromTrash({
          messageId,
          channelId: restoredMessage.channel_id,
          restoredMessage: restoredMessage
        }))

        toastRef.current({
          title: "Message restored",
          description: "The message has been restored successfully",
        })

        return { success: true, data: restoredMessage }
      }

      throw new Error('Invalid restore response')
    } catch (error: any) {
      logger.error('Failed to restore message:', error)

      toastRef.current({
        title: "Error",
        description: error?.error || error?.message || "Failed to restore message",
        variant: "destructive"
      })

      return { success: false, error: error?.error || 'Failed to restore message' }
    } finally {
      dispatch(setActionLoading(false))
    }
  }, [dispatch, sessionUserId])

  /**
   * Permanently delete a message (no recovery possible)
   * Only admins can do this
   */
  const permanentlyDelete = useCallback(async (messageId: string) => {
    if (!sessionUserId) return { success: false, error: 'Not authenticated' }

    try {
      dispatch(setActionLoading(true))

      // Optimistically remove from trash
      dispatch(permanentlyDeleteMessage({ messageId }))

      // Send to API - use query params as expected by the API route
      await apiRequest(`/api/communication/messages/${messageId}?deleteType=permanent`, {
        method: 'DELETE'
      })

      toastRef.current({
        title: "Message permanently deleted",
        description: "This action cannot be undone",
      })

      return { success: true }
    } catch (error: any) {
      logger.error('Failed to permanently delete message:', error)
      
      // Refetch trashed messages to restore state
      fetchTrashedMessages()

      toastRef.current({
        title: "Error",
        description: error?.error || "Failed to permanently delete message",
        variant: "destructive"
      })

      return { success: false, error: error?.error || 'Failed to delete permanently' }
    } finally {
      dispatch(setActionLoading(false))
    }
  }, [dispatch, sessionUserId])

  /**
   * Fetch trashed messages for the current user
   */
  const fetchTrashedMessages = useCallback(async (params?: { limit?: number; offset?: number }) => {
    if (!sessionUserId) return { success: false, error: 'Not authenticated' }

    try {
      dispatch(setTrashedMessagesLoading(true))

      const queryParams = new URLSearchParams()
      if (params?.limit) queryParams.append('limit', params.limit.toString())
      if (params?.offset) queryParams.append('offset', params.offset.toString())
      
      queryParams.append('trash', 'true')
      const queryString = queryParams.toString()
      const url = `/api/communication/messages?${queryString}`

      // Note: apiRequest unwraps successful responses, so we may get data directly or full response
      const response = await apiRequest(url)

      // Handle both unwrapped array and full response object
      let messagesData: any[] = []
      let paginationData: any = null

      if (Array.isArray(response)) {
        // apiRequest unwrapped to just the data array
        messagesData = response
      } else if (response && typeof response === 'object') {
        // Full response object with success/data/pagination
        if (response.data && Array.isArray(response.data)) {
          messagesData = response.data
          paginationData = response.pagination
        } else if (response.success === false) {
          throw new Error(response.error || 'Failed to fetch trash')
        }
      }

      const trashedMessagesData: ITrashedMessage[] = messagesData.map((msg: any) => ({
        ...msg,
        trashed_at: msg.trashed_at,
        trashed_by: msg.trashed_by,
        trash_reason: msg.trash_reason,
        days_remaining: msg.days_remaining,
        expires_at: msg.expires_at,
        is_expiring_soon: msg.is_expiring_soon
      }))

      const defaultLimit = params?.limit || 20
      const calculatedPagination = {
        page: paginationData?.page || Math.floor((params?.offset || 0) / defaultLimit) + 1,
        limit: defaultLimit,
        total: paginationData?.total || trashedMessagesData.length,
        pages: paginationData?.totalPages || Math.ceil(trashedMessagesData.length / defaultLimit),
        hasMore: paginationData?.hasMore || trashedMessagesData.length === defaultLimit
      }

      if (params?.offset && params.offset > 0) {
        // Append for pagination
        dispatch(appendTrashedMessages({
          messages: trashedMessagesData,
          pagination: calculatedPagination
        }))
      } else {
        // Set fresh data
        dispatch(setTrashedMessages({
          messages: trashedMessagesData,
          pagination: calculatedPagination
        }))
      }

      return { success: true, data: trashedMessagesData }
    } catch (error: any) {
      logger.error('Failed to fetch trashed messages:', error)
      
      toastRef.current({
        title: "Error",
        description: "Failed to load trash",
        variant: "destructive"
      })

      return { success: false, error: error?.error || 'Failed to fetch trash' }
    } finally {
      dispatch(setTrashedMessagesLoading(false))
    }
  }, [dispatch, sessionUserId])

  /**
   * Clear all trashed messages from state
   */
  const clearTrash = useCallback(() => {
    dispatch(clearTrashedMessages())
  }, [dispatch])

  // ============================================
  // Optimized Typing Operations
  // ============================================
  
  /**
   * Send typing indicator - optimized with throttling.
   * Call this on every keystroke, the realtime manager handles debouncing.
   */
  const setUserTyping = useCallback(async (typingIndicator: ITypingIndicator) => {
    if (activeChannelId && sessionUserId) {
      // The realtime manager handles throttling internally
      await realtimeManager.sendTypingStart(
        activeChannelId, 
        sessionUserId,
        sessionUserName
      )
    }
  }, [activeChannelId, sessionUserId, sessionUserName, realtimeManager])

  /**
   * Stop typing indicator - call when user stops typing or sends message.
   */
  const removeUserTyping = useCallback(async (channelId: string, userId: string) => {
    await realtimeManager.sendTypingStop(channelId, userId)
  }, [realtimeManager])

  // UI state operations
  const handleToggleChannelList = useCallback(() => {
    dispatch(toggleChannelList())
  }, [dispatch])

  const handleToggleContextPanel = useCallback(() => {
    dispatch(toggleContextPanel())
  }, [dispatch])

  const handleSetChannelListExpanded = useCallback((expanded: boolean) => {
    dispatch(setChannelListExpanded(expanded))
  }, [dispatch])

  const handleSetContextPanelVisible = useCallback((visible: boolean) => {
    dispatch(setContextPanelVisible(visible))
  }, [dispatch])

  // Filter and search operations
  const handleSetFilters = useCallback((newFilters: CommunicationFilters) => {
    dispatch(setFilters(newFilters))
  }, [dispatch])

  const handleSetSort = useCallback((newSort: CommunicationSort) => {
    dispatch(setSort(newSort))
  }, [dispatch])

  const handleSetPagination = useCallback((newPagination: any) => {
    dispatch(setPagination(newPagination))
  }, [dispatch])

  // Error handling
  const handleClearError = useCallback(() => {
    dispatch(clearError())
  }, [dispatch])

  const handleSetError = useCallback((errorMessage: string) => {
    dispatch(setError(errorMessage))
  }, [dispatch])

  // Notifications
  const handleAddNotification = useCallback((notification: any) => {
    dispatch(addNotification(notification))
  }, [dispatch])

  const handleClearNotifications = useCallback(() => {
    dispatch(clearNotifications())
  }, [dispatch])

  const handleRemoveNotification = useCallback((notificationId: string) => {
    dispatch(removeNotification(notificationId))
  }, [dispatch])

  // Utility operations
  const handleResetState = useCallback(() => {
    dispatch(resetState())
  }, [dispatch])

  const refreshChannels = useCallback(() => {
    return fetchChannels({ forceRefresh: true })
  }, [fetchChannels])

  const refreshMessages = useCallback(() => {
    if (activeChannelId) {
      return fetchMessages({ channel_id: activeChannelId })
    }
  }, [fetchMessages, activeChannelId])

  // ============================================
  // Channel Leave/Archive Operations (Phase 2)
  // ============================================

  /**
   * Leave a channel.
   * If user is the only admin, admin role is transferred to the oldest member.
   * If user is the last member, channel is archived.
   */
  const leaveChannel = useCallback(async (channelId: string) => {
    try {
      dispatch(setActionLoading(true))
      
      const result = await apiRequest(`/api/communication/channels/${channelId}?action=leave`, {
        method: 'POST'
      })

      // Remove channel from local state immediately (optimistic)
      dispatch(removeChannel(channelId))
      
      // Update cache
      communicationCache.removeChannelFromCache(channelId)

      // Handle different response formats
      const wasArchived = result?.archived || result?.action === 'archived'
      const message = result?.message || (wasArchived ? "Channel was archived (you were the last member)" : "You have left the channel")

      toastRef.current({
        title: wasArchived ? "Channel archived" : "Left channel",
        description: message,
      })

      // If we left the currently active channel, clear it
      if (activeChannelId === channelId) {
        dispatch(clearActiveChannel())
      }

      return { success: true, ...result }
    } catch (error: any) {
      // Extract error message from various error formats
      const errorMessage = error?.error || error?.message || 'Failed to leave channel'
      
      // Check for specific error cases
      if (errorMessage.includes('cannot leave') || errorMessage.includes('admin')) {
        toastRef.current({
          title: "Cannot leave channel",
          description: "You must transfer admin role before leaving",
          variant: "destructive"
        })
        return { success: false, needsAdminTransfer: true }
      }
      
      dispatch(setError(errorMessage))
      toastRef.current({
        title: "Error",
        description: errorMessage,
        variant: "destructive"
      })
      return { success: false, error: errorMessage }
    } finally {
      dispatch(setActionLoading(false))
    }
  }, [dispatch, activeChannelId])

  /**
   * Archive or unarchive a channel.
   * Only channel admins can archive/unarchive.
   */
  const archiveChannel = useCallback(async (
    channelId: string, 
    action: 'archive' | 'unarchive' = 'archive'
  ) => {
    try {
      dispatch(setActionLoading(true))
      
      const result = await apiRequest(`/api/communication/channels/${channelId}?action=${action}`, {
        method: 'PUT'
      })

      // Optimistically update the channel in Redux state
      const archiveUpdates: Partial<IChannel> & { id: string } = {
        id: channelId,
        is_archived: action === 'archive'
      }
      if (action === 'archive') {
        archiveUpdates.archived_at = new Date().toISOString()
        archiveUpdates.archived_by = sessionUserId || undefined
      }
      dispatch(updateChannel(archiveUpdates))
      
      // Update cache
      communicationCache.updateChannelInCache(channelId, archiveUpdates)

      // Handle different response formats
      const message = result?.message || `Channel has been ${action === 'archive' ? 'archived' : 'unarchived'}`
      
      toastRef.current({
        title: action === 'archive' ? "Channel archived" : "Channel unarchived",
        description: message,
      })

      return { success: true, ...result }
    } catch (error: any) {
      // Extract error message from various error formats
      const errorMessage = error?.error || error?.message || `Failed to ${action} channel`
      
      // Check for specific error cases
      if (errorMessage.includes('already archived')) {
        toastRef.current({
          title: "Already archived",
          description: "This channel is already archived",
          variant: "default"
        })
        return { success: false, alreadyArchived: true }
      }
      
      if (errorMessage.includes('not archived')) {
        toastRef.current({
          title: "Not archived",
          description: "This channel is not archived",
          variant: "default"
        })
        return { success: false, notArchived: true }
      }
      
      dispatch(setError(errorMessage))
      toastRef.current({
        title: "Error",
        description: errorMessage,
        variant: "destructive"
      })
      return { success: false, error: errorMessage }
    } finally {
      dispatch(setActionLoading(false))
    }
  }, [dispatch, sessionUserId])

  // Get current user from session
  const currentUserFromSession = useMemo(() => {
    if (!sessionUser) return null
    
    return {
      _id: sessionUser.id || '',
      name: sessionUser.name || '',
      email: sessionUser.email || '',
      role: sessionUser.role || '',
      avatar: sessionUser.image || sessionUser.avatar || undefined,
      status: 'active' as const,
      permissions: sessionUser.permissions || [],
    } as User
  }, [sessionUser])

  // Filter active users (exclude current user)
  const activeUsers = useMemo(() => {
    return allUsers.filter(user => 
      user._id !== currentUserFromSession?._id && 
      user.status === 'active'
    )
  }, [allUsers, currentUserFromSession?._id])

  const hasChannels = channels.length > 0

  return {
    // State
    channels,
    activeChannelId,
    selectedChannel,
    messages,
    onlineUsers,
    typingUsers,
    isChannelListExpanded,
    isContextPanelVisible,
    loading,
    actionLoading,
    messagesLoading,
    error,
    filters,
    sort,
    pagination,
    currentUser,
    unreadCount,
    notifications,

    // Real user data
    mockUsers: activeUsers, // For backward compatibility with existing components
    mockCurrentUser: currentUserFromSession, // For backward compatibility with existing components
    allUsers,
    currentUserFromSession,
    usersLoading,
    sessionStatus: status,
    hasChannels,
    
    // Online presence
    onlineUserIds,
    isUserOnline: (userId: string) => realtimeManager.isUserOnline(userId),
    getOnlineUsers: () => realtimeManager.getOnlineUsers(),

    // Channel operations
    fetchChannels,
    selectChannel,
    clearActiveChannel: clearChannel,
    pinChannel,
    pinUser,
    muteChannel,

    // Message operations
    fetchMessages,
    fetchOlderMessages,
    searchMessages,
    prependMessagesToChannel: (channelId: string, newMessages: ICommunication[]) => {
      dispatch(prependMessages({ channelId, messages: newMessages }))
    },
    sendMessage,
    sendMessageWithFiles,
    updateMessage: editMessage,
    createChannel,
    markAsRead,
    markAllChannelMessagesAsRead,

    // Channel leave/archive operations (Phase 2)
    leaveChannel,
    archiveChannel,

    // Reaction operations
    toggleReaction,

    // Real-time operations
    setTyping: setUserTyping,
    removeTyping: removeUserTyping,

    // UI state operations
    toggleChannelList: handleToggleChannelList,
    toggleContextPanel: handleToggleContextPanel,
    setChannelListExpanded: handleSetChannelListExpanded,
    setContextPanelVisible: handleSetContextPanelVisible,

    // Filter and search operations
    setFilters: handleSetFilters,
    setSort: handleSetSort,
    setPagination: handleSetPagination,

    // Error handling
    clearError: handleClearError,
    setError: handleSetError,

    // Notifications
    addNotification: handleAddNotification,
    clearNotifications: handleClearNotifications,
    removeNotification: handleRemoveNotification,

    // Utility operations
    resetState: handleResetState,
    refreshChannels,
    refreshMessages,

    // Trash operations (Phase 2: Message Lifecycle)
    trashedMessages,
    trashedMessagesLoading,
    trashedMessagesPagination,
    moveToTrash,
    hideForSelf,
    restoreFromTrash,
    permanentlyDelete,
    fetchTrashedMessages,
    clearTrash
  }
}
