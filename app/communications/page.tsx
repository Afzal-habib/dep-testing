"use client"

import { useState, useEffect, useRef, useCallback, useMemo } from "react"
import { useAppDispatch } from "@/hooks/redux"
import { addChannel } from "@/store/slices/communicationSlice"
import { Button } from "@/components/ui/button"
import { ChatWindow } from "@/components/communication/chat-window"
import { CommunicationSidebar } from "@/components/communication/communication-sidebar"
import { OnlineIndicator } from "@/components/communication/online-indicator"
import {
  MessageSquare,
  Plus,
} from "lucide-react"
import { useCommunications } from "@/hooks/use-communications"
import { usePermissions } from "@/hooks/use-permissions"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import { CreateChannelModal } from "@/components/communication/create-channel-modal"
import { ResizableSidebar } from "@/components/communication/resizable-sidebar"
import { FullscreenToggleRef } from '@/components/shared/FullscreenToggle';

export default function CommunicationsPage() {
  const dispatch = useAppDispatch()
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  const [isCreateChannelOpen, setIsCreateChannelOpen] = useState(false)
  const hasInitializedChannel = useRef(false)


  const {
    channels,
    activeChannelId,
    loading,
    error,
    onlineUsers,
    onlineUserIds,
    unreadCount,
    hasChannels,
    refreshChannels,
    selectChannel,
    setError,
    setFilters,
    filters,
    mockCurrentUser,
    pinChannel
  } = useCommunications()

  // Update URL when channel changes
  useEffect(() => {
    if (activeChannelId && typeof window !== 'undefined') {
      const url = new URL(window.location.href)
      const currentChannelParam = url.searchParams.get('channel')
      if (currentChannelParam !== activeChannelId) {
        url.searchParams.set('channel', activeChannelId)
        window.history.replaceState({}, '', url.toString())
        // Also store in localStorage as backup
        localStorage.setItem('lastActiveChannel', activeChannelId)
      }
    }
  }, [activeChannelId])

  // Handle URL params and localStorage for channel persistence
  useEffect(() => {
    if (typeof window === 'undefined' || hasInitializedChannel.current) return
    // Wait until channels are loaded before selecting from URL/localStorage
    if (loading || channels.length === 0) return

    const url = new URL(window.location.href)
    const channelParam = url.searchParams.get('channel')
    const storedChannel = localStorage.getItem('lastActiveChannel')

    // Priority: URL param > localStorage > none
    const channelToSelect = channelParam || storedChannel

    if (channelToSelect && channelToSelect !== activeChannelId) {
      // Verify the channel exists in the user's channel list
      const channelExists = channels.some(c => c.id === channelToSelect)
      
      if (channelExists) {
        hasInitializedChannel.current = true
        selectChannel(channelToSelect)
      } else {
        // Channel doesn't exist - clear the invalid reference
        console.log('Channel not found, clearing stored reference:', channelToSelect)
        localStorage.removeItem('lastActiveChannel')
        url.searchParams.delete('channel')
        window.history.replaceState({}, '', url.toString())
        hasInitializedChannel.current = true
        
        // Optionally select first available channel
        if (channels.length > 0) {
          selectChannel(channels[0].id)
        }
      }
    } else if (!channelToSelect && channels.length > 0 && !activeChannelId) {
      // No stored channel, select the first one automatically
      hasInitializedChannel.current = true
      selectChannel(channels[0].id)
    }
  }, [loading, channels, activeChannelId, selectChannel]) // Include channels to check existence
  const fullscreenRef = useRef<FullscreenToggleRef>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);

  // Handle responsive behavior
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth < 1024) {
        setIsMobileMenuOpen(false)
      }
    }

    handleResize() // Initial check
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [])


  const handleChannelSelect = useCallback((channelId: string) => {
    selectChannel(channelId)
    setIsMobileMenuOpen(false) // Close mobile menu after selection
  }, [selectChannel])

  const handleCreateChannel = useCallback(() => {
    setIsCreateChannelOpen(true)
    // TODO: Implement create channel functionality
    console.log('Create new channel')
  }, [])


  // Memoize maxWidth to prevent unnecessary re-renders
  const maxSidebarWidth = useMemo(() => {
    return typeof window !== "undefined" ? Math.floor(window.innerWidth * 0.5) : 500
  }, [])

  // Memoize current user ID to prevent unnecessary re-renders
  const currentUserId = useMemo(() => mockCurrentUser?._id || '', [mockCurrentUser?._id])

  // Memoize sidebar props to prevent unnecessary re-renders
  const sidebarProps = useMemo(() => ({
    channels,
    activeChannelId,
    onChannelSelect: handleChannelSelect,
    currentUserId,
    onlineUserIds,
    onCreateChannel: handleCreateChannel,
    onPinChannel: pinChannel,
    loading
  }), [
    channels,
    activeChannelId,
    handleChannelSelect,
    currentUserId,
    onlineUserIds,
    handleCreateChannel,
    pinChannel,
    loading
  ])
  return (
    <div className={`${isFullscreen ? 'h-[100vh]' : 'h-[calc(100vh-64px)]'}  flex flex-col bg-background`}>
      {/* <div className={`h-[calc(100vh-64px)]  flex flex-col bg-background`}> */}
      {/* Mobile header */}
      <div className="lg:hidden border-b bg-gradient-to-r from-card via-card to-card/95 p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sheet open={isMobileMenuOpen} onOpenChange={setIsMobileMenuOpen}>
              <SheetTrigger asChild>
                <button className="h-10 w-10 border-0 shadow-sm hover:text-primary transition-all duration-300 flex items-center justify-center hover:scale-110 hover:bg-accent rounded-lg">
                  {/* <AlignLeft className="h-6 w-6" /> */}
                  <svg
                    width={24}
                    height={24}
                    viewBox="0 0 24 24"
                    fill="currentColor"
                  >
                    <rect x="3" y="5" width="18" height="3" rx="1.5" />
                    <rect x="11" y="10.5" width="10" height="3" rx="1.5" />
                    <rect x="3" y="16" width="18" height="3" rx="1.5" />
                  </svg>
                </button>
              </SheetTrigger>
              <SheetContent side="left" className="w-80 p-0">
                <SheetHeader className="sr-only">
                  <SheetTitle>Messages Navigation</SheetTitle>
                  <SheetDescription>Navigate through your channels and conversations</SheetDescription>
                </SheetHeader>
                <CommunicationSidebar
                  {...sidebarProps}
                />
              </SheetContent>
            </Sheet>

            <h1 className="font-bold text-xl">Messages</h1>

            {unreadCount > 0 && (
              <Badge variant="default" className="ml-2 px-2 py-1 text-xs font-semibold shadow-sm animate-pulse">
                {unreadCount > 99 ? '99+' : unreadCount}
              </Badge>
            )}
          </div>

          <div className="flex items-center gap-2">
            {onlineUsers.length > 0 && (
              <OnlineIndicator users={onlineUsers} maxVisible={2} size="sm" />
            )}

            {/* {canCreate('communications', 'create') && ( */}
            <Button variant="default" size="sm" onClick={handleCreateChannel} className="h-9 w-9 p-0 shadow-sm hover:scale-110 transition-all duration-200">
              <Plus className="h-4 w-4" />
            </Button>
            {/* )} */}
          </div>
        </div>
      </div>

      {/* Error display */}
      {error && (
        <Alert className="m-4 mb-0">
          <AlertDescription className="flex items-center justify-between">
            {error}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setError('')}
            >
              Dismiss
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {/* Main content */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* Desktop sidebar - Resizable */}
        <ResizableSidebar
          defaultWidth={300}
          minWidth={200}
          maxWidth={maxSidebarWidth}
          storageKey="communication-sidebar"
          className="hidden lg:flex border-r"
        >
          <CommunicationSidebar
            {...sidebarProps}
          />
        </ResizableSidebar>



        {/* Chat area */}
        <div className="flex-1 min-w-0 overflow-hidden">
          {activeChannelId ? (
            <ChatWindow
              channelId={activeChannelId}
              fullscreenRef={fullscreenRef}
              onFullscreenChange={setIsFullscreen}
            />
          ) : (
            <div className="h-full flex items-center justify-center bg-gradient-to-br from-muted/5 via-muted/10 to-muted/5">
              <div className="text-center space-y-6 max-w-md mx-auto p-8 animate-in fade-in duration-500">
                <div className="h-24 w-24 bg-gradient-to-br from-primary/10 to-accent/20 rounded-2xl flex items-center justify-center mx-auto shadow-lg border border-primary/10 animate-in zoom-in duration-300">
                  <MessageSquare className="h-12 w-12 text-primary" />
                </div>

                <div className="space-y-3">
                  <h2 className="font-bold text-2xl bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text">Welcome to Communications</h2>
                  <p className="text-muted-foreground text-base leading-relaxed">
                    Stay connected with your team and clients through real-time messaging
                  </p>
                </div>

                {hasChannels ? (
                  <div className="space-y-3">
                    <p className="text-sm text-muted-foreground">
                      Select a conversation from the sidebar to get started
                    </p>

                    <div className="lg:hidden">
                      <Button
                        variant="default"
                        onClick={() => setIsMobileMenuOpen(true)}
                        className="shadow-sm hover:shadow-md transition-all duration-200"
                      >
                        <MessageSquare className="h-4 w-4 mr-2" />
                        View Conversations
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <p className="text-sm text-muted-foreground leading-relaxed">
                      No conversations yet. Create a new channel to start messaging.
                    </p>

                    {/* {canCreate('communications', 'create') && ( */}
                    <Button onClick={handleCreateChannel} className="shadow-sm hover:shadow-md transition-all duration-200">
                      <Plus className="h-4 w-4 mr-2" />
                      Create New Channel
                    </Button>
                    {/* )} */}
                  </div>
                )}

                {/* Quick stats */}
                <div className="flex justify-center gap-8 pt-6 border-t text-sm">
                  <div className="text-center">
                    <div className="font-bold text-2xl text-primary mb-1">{channels.length}</div>
                    <div className="text-muted-foreground text-xs">Channels</div>
                  </div>
                  <div className="text-center">
                    <div className="font-bold text-2xl text-green-600 dark:text-green-400 mb-1">{onlineUsers.length}</div>
                    <div className="text-muted-foreground text-xs">Online</div>
                  </div>
                  <div className="text-center">
                    <div className="font-bold text-2xl text-orange-600 dark:text-orange-400 mb-1">{unreadCount}</div>
                    <div className="text-muted-foreground text-xs">Unread</div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Create Channel Modal */}
      <CreateChannelModal
        isOpen={isCreateChannelOpen}
        onClose={() => setIsCreateChannelOpen(false)}
        onChannelCreatedRaw={async (channel) => {
          // Optimistic update: Add channel to Redux store immediately
          // This ensures the channel appears in the list instantly without waiting for realtime
          console.log('🔄 Adding channel to Redux store immediately:', channel.id)
          dispatch(addChannel(channel))
        }}
        onChannelCreated={(channel) => {
          if (channel) {
            console.log('📢 Channel created, selecting channel:', channel.id)
            selectChannel(channel.id)
            // Update URL
            const url = new URL(window.location.href)
            url.searchParams.set('channel', channel.id)
            window.history.replaceState({}, '', url.toString())
          }
        }}
      />
    </div>
  )
}