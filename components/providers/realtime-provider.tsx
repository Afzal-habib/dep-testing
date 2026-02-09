"use client"

import { useEffect, useRef } from 'react'
import { useSession } from 'next-auth/react'
import { getRealtimeManager, RealtimeEventHandlers } from '@/lib/realtime-manager'
import { useToast } from '@/hooks/use-toast'
import { useAppDispatch, useAppSelector } from '@/hooks/redux'
import { 
  addNotification, 
  addMessage,
  setCurrentUserId,
  updateChannel
} from '@/store/slices/communicationSlice'

export function RealtimeProvider({ children }: { children: React.ReactNode }) {
  const { data: session, status } = useSession()
  const { toast } = useToast()
  const dispatch = useAppDispatch()
  const initializedUserIdRef = useRef<string | null>(null)
  const userIdRef = useRef<string | null>(null)
  
  // Get active channel ID to determine if we should show notifications
  const activeChannelId = useAppSelector((state) => state.communications.activeChannelId)
  const activeChannelIdRef = useRef(activeChannelId)
  
  // Keep ref updated
  useEffect(() => {
    activeChannelIdRef.current = activeChannelId
  }, [activeChannelId])

  useEffect(() => {
    const sessionUser = session?.user as any
    const userId = sessionUser?.id
    const userName = sessionUser?.name || sessionUser?.email || 'Unknown'
    const userAvatar = sessionUser?.image || sessionUser?.avatar

    // Store userId in ref for use in handlers
    userIdRef.current = userId

    // Skip if no user or already initialized for this user
    if (!userId) {
      // User logged out - reset initialization state
      if (initializedUserIdRef.current) {
        console.log('🔧 RealtimeProvider: User logged out, resetting state')
        initializedUserIdRef.current = null
      }
      return
    }

    // Skip if already initialized for this specific user
    if (initializedUserIdRef.current === userId) {
      console.log('🔧 RealtimeProvider: Already initialized for user:', userId)
      return
    }

    // Mark as initialized for this user
    initializedUserIdRef.current = userId
      
    // Set current user ID in Redux for proper unread count tracking
    dispatch(setCurrentUserId(userId))

      // Create event handlers for global notifications
      const eventHandlers: RealtimeEventHandlers = {
        onNewMessageNotification: (data: { message: any }) => {
          console.log('📨 RealtimeProvider: onNewMessageNotification called with data:', data)
          const message = data.message
          const channelId = message.channel_id
          const currentUserId = userIdRef.current
          const senderId = message.mongo_sender_id
          
          console.log('📨 RealtimeProvider: Self-check', {
            senderId,
            currentUserId,
            areEqual: senderId === currentUserId,
            senderIdType: typeof senderId,
            currentUserIdType: typeof currentUserId
          })
          
          // CRITICAL: Skip if message is from self
          // Compare as strings to handle any type mismatches
          if (String(senderId) === String(currentUserId)) {
            console.log('📨 RealtimeProvider: Skipping notification for own message (sender === current user)')
            return
          }
          
          // Check if user is currently viewing this channel
          const isViewingChannel = activeChannelIdRef.current === channelId
          
          // If viewing this channel, the message will come through the channel subscription
          // so we don't need to add it here to avoid duplicates
          if (isViewingChannel) {
            console.log('📨 Skipping notification - user is viewing this channel')
            return
          }
          
          console.log('📨 Processing new message notification for channel:', channelId)
          
          // Add the message to the channel's messages
          // The addMessage reducer will automatically:
          // 1. Add the message to the messages array
          // 2. Update the channel's last_message and last_message_at
          // 3. Increment unreadCount since the channel is not active
          // 4. Move the channel to the top of the list
          dispatch(addMessage({
            channelId,
            message: {
              ...message,
              // Ensure the message has the right structure
              sender: message.sender || {
                mongo_member_id: message.mongo_sender_id,
                name: message.sender_name || 'Unknown',
                email: message.sender_email || '',
                avatar: message.sender_avatar || '',
                role: message.sender_role || 'User',
                userType: 'User' as const,
                isOnline: false
              }
            }
          }))
          
          // Check if user is on the communications page
          const currentPath = window.location.pathname
          const isOnCommunicationsPage = currentPath.includes('/communications')

          if (!isOnCommunicationsPage) {
            // Show browser notification
            if ('Notification' in window && Notification.permission === 'granted') {
              const senderName = message.sender_name || message.sender?.name || 'Someone'
              new Notification(`New message from ${senderName}`, {
                body: message.content?.slice(0, 100) || 'New message',
                icon: message.sender_avatar || message.sender?.avatar || '/favicon.ico'
              })
            }

            // Show toast notification
            toast({
              title: "New Message",
              description: message.content?.slice(0, 50) || 'You have a new message',
            })
          }

          // Add to Redux notifications
          dispatch(addNotification({
            id: `message_${message.id}`,
            type: 'message',
            title: `New message from ${message.sender_name || 'Unknown'}`,
            channelId: message.channel_id,
            messageId: message.id,
            preview: message.content?.slice(0, 100) || 'New message',
            read: false
          }))
        },

        onMentionNotification: (data: any) => {
          // Show mention notification
          if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(`@${data.sender_name} mentioned you`, {
              body: data.content_preview,
              icon: data.sender_avatar || '/favicon.ico'
            })
          }

          // Add to Redux notifications
          dispatch(addNotification({
            id: `mention_${data.message_id}`,
            type: 'mention',
            title: `${data.sender_name} mentioned you`,
            channelId: data.channel_id,
            messageId: data.message_id,
            preview: data.content_preview,
            read: false
          }))

          // Show toast
          toast({
            title: `@${data.sender_name} mentioned you`,
            description: data.content_preview.slice(0, 60) + (data.content_preview.length > 60 ? '...' : ''),
          })
        }
      }

      console.log('🔧 RealtimeProvider: Setting up handlers for user:', userId)
      const realtimeManager = getRealtimeManager(eventHandlers)

      // Initialize presence and notifications
      const initRealtime = async () => {
        try {
          console.log('🔧 RealtimeProvider: Initializing presence for user:', userId)
          await realtimeManager.initializePresence(userId, userName, userAvatar)
          console.log('🔧 RealtimeProvider: Subscribing to notifications for user:', userId)
          await realtimeManager.subscribeToNotifications(userId)
          console.log('✅ RealtimeProvider: Global realtime initialized for user:', userId)
        } catch (error) {
          console.error('❌ RealtimeProvider: Failed to initialize global realtime:', error)
          // Reset initialization state so it can retry
          initializedUserIdRef.current = null
        }
      }

      initRealtime()

      // Request notification permission
      if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission()
      }
    // No cleanup - notification subscriptions should persist for the entire session
    // The RealtimeManager handles reconnection automatically
  }, [session, toast, dispatch])

  return <>{children}</>
}