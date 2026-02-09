import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import { 
  ICommunication, 
  IChannel, 
  IParticipant, 
  ITypingIndicator, 
  CommunicationFilters, 
  CommunicationSort
} from '@/types/communication'

// Type for updateChannel payload that allows functions for numeric fields
type UpdateChannelPayload = {
  id: string;
} & Partial<{
  [K in keyof IChannel]: IChannel[K] | ((prev: IChannel[K]) => IChannel[K])
}>

// State interface
interface CommunicationState {
  // Channel management
  channels: IChannel[]
  activeChannelId: string | null
  selectedChannel: IChannel | null
  
  // Message management
  messages: Record<string, ICommunication[]> // Keyed by channelId
  
  // Real-time features
  onlineUsers: IParticipant[]
  onlineUserIds: string[] // Quick lookup for online status (array for Redux serialization)
  typingUsers: Record<string, ITypingIndicator[]> // Keyed by channelId
  
  // UI State
  isChannelListExpanded: boolean
  isContextPanelVisible: boolean
  
  // Loading states
  loading: boolean
  actionLoading: boolean
  messagesLoading: boolean
  channelsInitialized: boolean // Prevents multiple components from fetching channels
  
  // Error handling
  error: string | null
  
  // Filters and pagination
  filters: CommunicationFilters
  sort: CommunicationSort
  pagination: {
    page: number
    limit: number
    total: number
    pages: number
  }
  
  // Current user (from auth state)
  currentUser: IParticipant | null
  currentUserId: string | null
  
  // Notifications
  unreadCount: number
  notifications: Array<{
    id: string
    type: 'message' | 'mention'
    title?: string
    channelId: string
    message?: ICommunication
    messageId?: string
    preview?: string
    timestamp: string  // ISO string for Redux serialization
    read: boolean
  }>
  
  // Trash management (Phase 2: Message Lifecycle)
  trashedMessages: ITrashedMessage[]
  trashedMessagesLoading: boolean
  trashedMessagesPagination: {
    page: number
    limit: number
    total: number
    pages: number
    hasMore: boolean
  }
}

// Trashed message interface with expiry info
export interface ITrashedMessage extends ICommunication {
  trashed_at: string
  trashed_by: string
  trash_reason?: string
  days_remaining: number
  expires_at: string
  is_expiring_soon: boolean // < 7 days remaining
}

const initialState: CommunicationState = {
  channels: [],
  activeChannelId: null,
  selectedChannel: null,
  messages: {},
  onlineUsers: [],
  onlineUserIds: [],
  typingUsers: {},
  isChannelListExpanded: true,
  isContextPanelVisible: false,
  loading: false,
  actionLoading: false,
  messagesLoading: false,
  channelsInitialized: false,
  error: null,
  filters: {},
  sort: { field: 'created_at', direction: 'asc' },
  pagination: { page: 1, limit: 50, total: 0, pages: 0 },
  currentUser: null,
  currentUserId: null,
  unreadCount: 0,
  notifications: [],
  
  // Trash management (Phase 2)
  trashedMessages: [],
  trashedMessagesLoading: false,
  trashedMessagesPagination: { page: 1, limit: 20, total: 0, pages: 0, hasMore: false }
}

const communicationSlice = createSlice({
  name: "communications",
  initialState,
  reducers: {
    // ============================================
    // Channel Management
    // ============================================
    
    setActiveChannel: (state, action: PayloadAction<string>) => {
      state.activeChannelId = action.payload
      state.selectedChannel = state.channels.find(ch => ch.id === action.payload) || null
      
      // Clear unread count for this channel when selected
      const channelIndex = state.channels.findIndex(ch => ch.id === action.payload)
      if (channelIndex !== -1 && state.channels[channelIndex].unreadCount) {
        state.unreadCount -= state.channels[channelIndex].unreadCount
        state.channels[channelIndex].unreadCount = 0
      }
      
      // Clear typing indicators for this channel
      state.typingUsers[action.payload] = []
    },
    
    clearActiveChannel: (state) => {
      state.activeChannelId = null
      state.selectedChannel = null
    },
    
    // ============================================
    // Message Management with Channel Ordering
    // ============================================
    
    addMessage: (state, action: PayloadAction<{ channelId: string; message: ICommunication }>) => {
      const { channelId, message } = action.payload
      
      if (!state.messages[channelId]) {
        state.messages[channelId] = []
      }
      
      // Check for duplicate - don't add if message already exists
      const messageExists = state.messages[channelId].some(m => m.id === message.id)
      if (messageExists) {
        console.log('Message already exists, skipping duplicate:', message.id)
        return
      }
      
      // Create a fresh copy to avoid mutating frozen payload
      state.messages[channelId].push({ ...message })
      
      // Update channel's last message and move to top
      const channelIndex = state.channels.findIndex(ch => ch.id === channelId)
      if (channelIndex !== -1) {
        const channel = state.channels[channelIndex]
        channel.last_message = message
        channel.last_message_at = message.created_at
        
        // Update unread count ONLY if:
        // 1. Not the active channel
        // 2. currentUserId is set (to avoid false positives)
        // 3. Message is NOT from the current user
        const isActiveChannel = channelId === state.activeChannelId
        const isFromCurrentUser = state.currentUserId && message.mongo_sender_id === state.currentUserId
        
        if (!isActiveChannel && !isFromCurrentUser && state.currentUserId) {
          channel.unreadCount = (channel.unreadCount || 0) + 1
          state.unreadCount += 1
        }
        
        // Move channel to top of list (most recent first)
        if (channelIndex > 0) {
          state.channels.splice(channelIndex, 1)
          state.channels.unshift(channel)
        }
        
        // Update selectedChannel if it's the same channel
        if (state.selectedChannel?.id === channelId) {
          state.selectedChannel = { ...channel }
        }
      }
    },
    
    updateMessage: (state, action: PayloadAction<{ channelId: string; messageId: string; updates: Partial<ICommunication> }>) => {
      const { channelId, messageId, updates } = action.payload
      
      if (state.messages[channelId]) {
        const messageIndex = state.messages[channelId].findIndex(msg => msg.id === messageId)
        if (messageIndex !== -1) {
          state.messages[channelId][messageIndex] = {
            ...state.messages[channelId][messageIndex],
            ...updates
          }
        }
      }
    },
    
    // Add a read receipt to a message (real-time update)
    addMessageReadReceipt: (state, action: PayloadAction<{ 
      channelId: string; 
      messageId: string; 
      userId: string;
      readAt: string;
    }>) => {
      const { channelId, messageId, userId, readAt } = action.payload
      
      if (state.messages[channelId]) {
        const messageIndex = state.messages[channelId].findIndex(msg => msg.id === messageId)
        if (messageIndex !== -1) {
          const message = state.messages[channelId][messageIndex]
          // Initialize read_receipts if not present
          if (!message.read_receipts) {
            message.read_receipts = []
          }
          // Check if receipt already exists for this user
          const existingReceipt = message.read_receipts.find(r => r.mongo_user_id === userId)
          if (!existingReceipt) {
            message.read_receipts.push({
              message_id: messageId,
              mongo_user_id: userId,
              read_at: readAt
            })
          }
        }
      }
    },
    
    // Mark message as delivered (when receiver comes online or receives message)
    setMessageDelivered: (state, action: PayloadAction<{ 
      channelId: string; 
      messageId: string;
    }>) => {
      const { channelId, messageId } = action.payload
      
      if (state.messages[channelId]) {
        const messageIndex = state.messages[channelId].findIndex(msg => msg.id === messageId)
        if (messageIndex !== -1) {
          // Remove optimistic flag - message has been confirmed delivered
          state.messages[channelId][messageIndex].isOptimistic = false
        }
      }
    },
    
    // Decrement unread count (when message is marked as read)
    decrementUnreadCount: (state, action: PayloadAction<number | undefined>) => {
      const decrement = action.payload ?? 1
      state.unreadCount = Math.max(0, state.unreadCount - decrement)
    },

    incrementUnreadCount: (state, action: PayloadAction<number | undefined>) => {
      const increment = action.payload ?? 1
      state.unreadCount += increment
    },
    
    addReactionToMessage: (state, action: PayloadAction<{
      channelId: string;
      messageId: string;
      reaction: {
        id: string;
        mongo_user_id: string;
        user_name?: string;
        emoji: string;
        created_at: string;
      };
    }>) => {
      const { channelId, messageId, reaction } = action.payload
      
      if (state.messages[channelId]) {
        const messageIndex = state.messages[channelId].findIndex(msg => msg.id === messageId)
        if (messageIndex !== -1) {
          const message = state.messages[channelId][messageIndex]
          // Initialize reactions if not present
          if (!message.reactions) {
            message.reactions = []
          }
          // Check if this reaction already exists (same user + same emoji)
          const existingReaction = message.reactions.find(
            r => r.mongo_user_id === reaction.mongo_user_id && r.emoji === reaction.emoji
          )
          if (!existingReaction) {
            message.reactions.push({
              id: reaction.id,
              message_id: messageId,
              channel_id: channelId,
              mongo_user_id: reaction.mongo_user_id,
              user_name: reaction.user_name,
              emoji: reaction.emoji,
              created_at: reaction.created_at
            })
          }
        }
      }
    },
    
    removeReactionFromMessage: (state, action: PayloadAction<{
      channelId: string;
      messageId: string;
      reactionId?: string;
      mongo_user_id?: string;
      emoji?: string;
    }>) => {
      const { channelId, messageId, reactionId, mongo_user_id, emoji } = action.payload
      
      if (state.messages[channelId]) {
        const messageIndex = state.messages[channelId].findIndex(msg => msg.id === messageId)
        if (messageIndex !== -1) {
          const message = state.messages[channelId][messageIndex]
          if (message.reactions) {
            if (reactionId) {
              // Remove by reaction ID
              message.reactions = message.reactions.filter(r => r.id !== reactionId)
            } else if (mongo_user_id && emoji) {
              // Remove by user ID + emoji
              message.reactions = message.reactions.filter(
                r => !(r.mongo_user_id === mongo_user_id && r.emoji === emoji)
              )
            }
          }
        }
      }
    },
    
    // ============================================
    // Typing Indicators (Optimized)
    // ============================================
    
    setTyping: (state, action: PayloadAction<ITypingIndicator>) => {
      const typing = action.payload
      
      if (!state.typingUsers[typing.channelId]) {
        state.typingUsers[typing.channelId] = []
      }
      
      // Don't add typing from current user
      if (typing.userId === state.currentUserId) {
        return
      }
      
      const existingIndex = state.typingUsers[typing.channelId].findIndex(t => t.userId === typing.userId)
      if (existingIndex !== -1) {
        // Update existing typing indicator timestamp
        state.typingUsers[typing.channelId][existingIndex] = typing
      } else {
        // Add new typing indicator
        state.typingUsers[typing.channelId].push(typing)
      }
    },
    
    removeTyping: (state, action: PayloadAction<{ channelId: string; userId: string }>) => {
      const { channelId, userId } = action.payload
      
      if (state.typingUsers[channelId]) {
        state.typingUsers[channelId] = state.typingUsers[channelId].filter(t => t.userId !== userId)
      }
    },
    
    clearTypingForChannel: (state, action: PayloadAction<string>) => {
      const channelId = action.payload
      state.typingUsers[channelId] = []
    },
    
    // ============================================
    // Online Presence (New)
    // ============================================
    
    setCurrentUserId: (state, action: PayloadAction<string>) => {
      state.currentUserId = action.payload
    },
    
    setOnlineUserIds: (state, action: PayloadAction<string[]>) => {
      // Use array directly instead of Set for Redux serialization
      state.onlineUserIds = [...action.payload]
      
      // Update channel_members online status in channels
      state.channels = state.channels.map(channel => ({
        ...channel,
        channel_members: channel.channel_members?.map(member => ({
          ...member,
          isOnline: action.payload.includes(member.mongo_member_id)
        })) || []
      }))
      
      // Update selectedChannel if exists
      if (state.selectedChannel) {
        state.selectedChannel = {
          ...state.selectedChannel,
          channel_members: state.selectedChannel.channel_members?.map(member => ({
            ...member,
            isOnline: action.payload.includes(member.mongo_member_id)
          })) || []
        }
      }
    },
    
    addOnlineUser: (state, action: PayloadAction<string>) => {
      const userId = action.payload
      // Add to array if not already present
      if (!state.onlineUserIds.includes(userId)) {
        state.onlineUserIds.push(userId)
      }
      
      // Update channel members
      state.channels = state.channels.map(channel => ({
        ...channel,
        channel_members: channel.channel_members?.map(member => ({
          ...member,
          isOnline: member.mongo_member_id === userId ? true : member.isOnline
        })) || []
      }))
      
      if (state.selectedChannel) {
        state.selectedChannel = {
          ...state.selectedChannel,
          channel_members: state.selectedChannel.channel_members?.map(member => ({
            ...member,
            isOnline: member.mongo_member_id === userId ? true : member.isOnline
          })) || []
        }
      }
    },
    
    removeOnlineUser: (state, action: PayloadAction<string>) => {
      const userId = action.payload
      // Remove from array
      state.onlineUserIds = state.onlineUserIds.filter(id => id !== userId)
      
      // Update channel members
      state.channels = state.channels.map(channel => ({
        ...channel,
        channel_members: channel.channel_members?.map(member => ({
          ...member,
          isOnline: member.mongo_member_id === userId ? false : member.isOnline
        })) || []
      }))
      
      if (state.selectedChannel) {
        state.selectedChannel = {
          ...state.selectedChannel,
          channel_members: state.selectedChannel.channel_members?.map(member => ({
            ...member,
            isOnline: member.mongo_member_id === userId ? false : member.isOnline
          })) || []
        }
      }
    },
    
    updateOnlineUsers: (state, action: PayloadAction<IParticipant[]>) => {
      state.onlineUsers = action.payload
      
      // Update channel_members online status in channels
      state.channels = state.channels.map(channel => ({
        ...channel,
        channel_members: channel.channel_members?.map(member => ({
          ...member,
          isOnline: action.payload.some(user => user.mongo_member_id === member.mongo_member_id && user.isOnline)
        })) || []
      }))
    },
    
    // UI State management
    toggleChannelList: (state) => {
      state.isChannelListExpanded = !state.isChannelListExpanded
    },
    
    toggleContextPanel: (state) => {
      state.isContextPanelVisible = !state.isContextPanelVisible
    },
    
    setChannelListExpanded: (state, action: PayloadAction<boolean>) => {
      state.isChannelListExpanded = action.payload
    },
    
    setContextPanelVisible: (state, action: PayloadAction<boolean>) => {
      state.isContextPanelVisible = action.payload
    },
    
    // Filters and search
    setFilters: (state, action: PayloadAction<Partial<CommunicationFilters>>) => {
      state.filters = { ...state.filters, ...action.payload }
      state.pagination.page = 1 // Reset to first page when filters change
    },
    
    setSort: (state, action: PayloadAction<CommunicationSort>) => {
      state.sort = action.payload
      state.pagination.page = 1 // Reset to first page when sort changes
    },
    
    setPagination: (state, action: PayloadAction<{ page?: number; limit?: number }>) => {
      state.pagination = { ...state.pagination, ...action.payload }
    },
    
    // Error handling
    clearError: (state) => {
      state.error = null
    },
    
    setError: (state, action: PayloadAction<string>) => {
      state.error = action.payload
    },
    
    // Notifications
    addNotification: (state, action: PayloadAction<{ 
      id: string
      type: 'message' | 'mention'
      title?: string
      channelId: string
      message?: ICommunication
      messageId?: string
      preview?: string
      read?: boolean
    }>) => {
      // Check for duplicate notifications
      const exists = state.notifications.some(n => n.id === action.payload.id)
      if (exists) {
        console.log('📨 Notification already exists, skipping:', action.payload.id)
        return
      }
      
      state.notifications.push({
        id: action.payload.id,
        type: action.payload.type,
        title: action.payload.title,
        channelId: action.payload.channelId,
        message: action.payload.message,
        messageId: action.payload.messageId,
        preview: action.payload.preview,
        timestamp: new Date().toISOString(), // Use ISO string for serialization
        read: action.payload.read ?? false
      })
    },
    
    clearNotifications: (state) => {
      state.notifications = []
    },

    clearNotificationsForChannel: (state, action: PayloadAction<string>) => {
      state.notifications = state.notifications.filter(n => n.channelId !== action.payload)
    },

    removeNotification: (state, action: PayloadAction<string>) => {
      state.notifications = state.notifications.filter(n => n.id !== action.payload)
    },
    
    // ============================================
    // Channel Real-time Updates (Phase 3)
    // ============================================
    
    // Add a new channel (real-time)
    addChannel: (state, action: PayloadAction<IChannel>) => {
      const exists = state.channels.some(c => c.id === action.payload.id)
      if (!exists) {
        // Create a fresh copy to avoid mutating frozen payload
        const newChannel = { ...action.payload, unreadCount: action.payload.unreadCount ?? 0 }
        state.channels.unshift(newChannel) // Add to beginning (most recent)
      }
    },
    
    // Update an existing channel (real-time)
    updateChannel: (state, action: PayloadAction<UpdateChannelPayload>) => {
      const index = state.channels.findIndex(c => c.id === action.payload.id)
      if (index !== -1) {
        const channel = state.channels[index]
        Object.keys(action.payload).forEach(key => {
          if (key !== 'id') {
            const value = (action.payload as any)[key]
            if (typeof value === 'function') {
              (channel as any)[key] = value((channel as any)[key])
            } else {
              (channel as any)[key] = value
            }
          }
        })
        // Also update selectedChannel if it's the same
        if (state.selectedChannel?.id === action.payload.id) {
          const selectedChannel = state.selectedChannel
          Object.keys(action.payload).forEach(key => {
            if (key !== 'id') {
              const value = (action.payload as any)[key]
              if (typeof value === 'function') {
                (selectedChannel as any)[key] = value((selectedChannel as any)[key])
              } else {
                (selectedChannel as any)[key] = value
              }
            }
          })
        }
      }
    },
    
    // Remove a channel (real-time - when user leaves or channel is deleted)
    removeChannel: (state, action: PayloadAction<string>) => {
      state.channels = state.channels.filter(c => c.id !== action.payload)
      // Clear active channel if it was removed
      if (state.activeChannelId === action.payload) {
        state.activeChannelId = null
        state.selectedChannel = null
      }
      // Clean up messages for removed channel
      delete state.messages[action.payload]
    },
    
    // Data setters for TanStack Query integration
    setChannels: (state, action: PayloadAction<IChannel[]>) => {
      // Create fresh copies and transform messages array to last_message
      state.channels = action.payload.map(channel => {
        // Transform messages array to last_message for convenience
        const lastMessage = (channel as any).messages?.[0] || (channel as any).last_message || null
        return {
          ...channel,
          last_message: lastMessage,
          unreadCount: channel.unreadCount ?? 0
        }
      })
      state.channelsInitialized = true // Mark as initialized to prevent duplicate fetches
      // Calculate total unread count from all channels
      state.unreadCount = state.channels.reduce((total, channel) => total + (channel.unreadCount || 0), 0)
    },
    
    setMessages: (state, action: PayloadAction<{ channelId: string; messages: ICommunication[] }>) => {
      const { channelId, messages } = action.payload
      // Create fresh copies to avoid mutating frozen payload
      state.messages[channelId] = messages.map(m => ({ ...m }))
    },
    
    // Prepend older messages (for pagination)
    prependMessages: (state, action: PayloadAction<{ channelId: string; messages: ICommunication[] }>) => {
      const { channelId, messages } = action.payload
      if (!state.messages[channelId]) {
        state.messages[channelId] = []
      }
      // Filter out any duplicates and prepend older messages
      const existingIds = new Set(state.messages[channelId].map(m => m.id))
      const newMessages = messages.filter(m => !existingIds.has(m.id)).map(m => ({ ...m }))
      state.messages[channelId] = [...newMessages, ...state.messages[channelId]]
    },
    
    // Loading state setters
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.loading = action.payload
    },
    
    setActionLoading: (state, action: PayloadAction<boolean>) => {
      state.actionLoading = action.payload
    },
    
    setMessagesLoading: (state, action: PayloadAction<boolean>) => {
      state.messagesLoading = action.payload
    },
    
    // Reset state
    resetState: (state) => {
      Object.assign(state, initialState)
    },

    setChannelsInitialized: (state, action: PayloadAction<boolean>) => {
      state.channelsInitialized = action.payload
    },
    
    // ============================================
    // Trash Management (Phase 2: Message Lifecycle)
    // ============================================
    
    // Move message to trash (removes from active messages)
    moveMessageToTrash: (state, action: PayloadAction<{ 
      channelId: string; 
      messageId: string;
      trashedAt: string;
      trashedBy: string;
      trashReason?: string;
    }>) => {
      const { channelId, messageId, trashedAt, trashedBy, trashReason } = action.payload
      
      if (state.messages[channelId]) {
        // Find and remove the message from active messages
        const messageIndex = state.messages[channelId].findIndex(msg => msg.id === messageId)
        if (messageIndex !== -1) {
          const message = state.messages[channelId][messageIndex]
          
          // Calculate expiry info
          const trashedDate = new Date(trashedAt)
          const expiresAt = new Date(trashedDate)
          expiresAt.setDate(expiresAt.getDate() + 30)
          const daysRemaining = Math.max(0, Math.ceil((expiresAt.getTime() - Date.now()) / (1000 * 60 * 60 * 24)))
          
          // Add to trashed messages with expiry info
          state.trashedMessages.unshift({
            ...message,
            trashed_at: trashedAt,
            trashed_by: trashedBy,
            trash_reason: trashReason,
            days_remaining: daysRemaining,
            expires_at: expiresAt.toISOString(),
            is_expiring_soon: daysRemaining < 7
          } as any)
          
          // Remove from active messages
          state.messages[channelId].splice(messageIndex, 1)
        }
      }
    },
    
    // Restore message from trash (adds back to active messages)
    restoreMessageFromTrash: (state, action: PayloadAction<{ 
      messageId: string;
      channelId: string;
      restoredMessage: ICommunication;
    }>) => {
      const { messageId, channelId, restoredMessage } = action.payload
      
      // Remove from trashed messages
      state.trashedMessages = state.trashedMessages.filter(msg => msg.id !== messageId)
      
      // Add back to active messages for the channel
      if (!state.messages[channelId]) {
        state.messages[channelId] = []
      }
      
      // Insert message in correct chronological position
      const insertIndex = state.messages[channelId].findIndex(
        msg => new Date(msg.created_at) > new Date(restoredMessage.created_at)
      )
      
      if (insertIndex === -1) {
        // Message is the newest, add to end
        state.messages[channelId].push(restoredMessage)
      } else {
        // Insert at correct position
        state.messages[channelId].splice(insertIndex, 0, restoredMessage)
      }
    },
    
    // Hide message for current user only (doesn't affect trash)
    hideMessageForSelf: (state, action: PayloadAction<{ 
      channelId: string; 
      messageId: string;
    }>) => {
      const { channelId, messageId } = action.payload
      
      if (state.messages[channelId]) {
        // Remove message from view (it's hidden for current user)
        state.messages[channelId] = state.messages[channelId].filter(msg => msg.id !== messageId)
      }
    },
    
    // Permanently delete message (removes from trash completely)
    permanentlyDeleteMessage: (state, action: PayloadAction<{ messageId: string }>) => {
      const { messageId } = action.payload
      state.trashedMessages = state.trashedMessages.filter(msg => msg.id !== messageId)
    },
    
    // Set trashed messages (from API fetch)
    setTrashedMessages: (state, action: PayloadAction<{
      messages: ITrashedMessage[];
      pagination?: {
        page: number;
        limit: number;
        total: number;
        pages: number;
        hasMore: boolean;
      };
    }>) => {
      const { messages, pagination } = action.payload
      // Create fresh copies to avoid mutating frozen payload
      state.trashedMessages = messages.map(m => ({ ...m }))
      if (pagination) {
        state.trashedMessagesPagination = { ...pagination }
      }
    },
    
    // Append trashed messages (for pagination)
    appendTrashedMessages: (state, action: PayloadAction<{
      messages: ITrashedMessage[];
      pagination: {
        page: number;
        limit: number;
        total: number;
        pages: number;
        hasMore: boolean;
      };
    }>) => {
      const { messages, pagination } = action.payload
      // Filter out duplicates
      const existingIds = new Set(state.trashedMessages.map(m => m.id))
      const newMessages = messages.filter(m => !existingIds.has(m.id)).map(m => ({ ...m }))
      state.trashedMessages.push(...newMessages)
      state.trashedMessagesPagination = { ...pagination }
    },
    
    // Set trashed messages loading state
    setTrashedMessagesLoading: (state, action: PayloadAction<boolean>) => {
      state.trashedMessagesLoading = action.payload
    },
    
    // Update trashed message expiry info (for real-time updates)
    updateTrashedMessageExpiry: (state) => {
      state.trashedMessages = state.trashedMessages.map(msg => {
        const expiresAt = new Date(msg.expires_at)
        const daysRemaining = Math.max(0, Math.ceil((expiresAt.getTime() - Date.now()) / (1000 * 60 * 60 * 24)))
        return {
          ...msg,
          days_remaining: daysRemaining,
          is_expiring_soon: daysRemaining < 7
        }
      }).filter(msg => msg.days_remaining > 0) // Auto-remove expired messages
    },
    
    // Clear all trashed messages (reset)
    clearTrashedMessages: (state) => {
      state.trashedMessages = []
      state.trashedMessagesPagination = { page: 1, limit: 20, total: 0, pages: 0, hasMore: false }
    }
  }
})

export const {
  setActiveChannel,
  clearActiveChannel,
  setChannels,
  setMessages,
  prependMessages,
  addMessage,
  updateMessage,
  addMessageReadReceipt,
  setMessageDelivered,
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
  addReactionToMessage,
  removeReactionFromMessage,
  resetState,
  decrementUnreadCount,
  incrementUnreadCount,
  // Channel real-time updates (Phase 3)
  addChannel,
  updateChannel,
  removeChannel,
  // Trash management exports (Phase 2)
  moveMessageToTrash,
  restoreMessageFromTrash,
  hideMessageForSelf,
  permanentlyDeleteMessage,
  setTrashedMessages,
  appendTrashedMessages,
  setTrashedMessagesLoading,
  updateTrashedMessageExpiry,
  clearTrashedMessages
} = communicationSlice.actions

export default communicationSlice.reducer