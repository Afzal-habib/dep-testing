// Communication Types - Updated for Supabase integration
import { FullscreenToggleRef } from '@/components/shared/FullscreenToggle'

// Messages table interface
export interface ICommunication {
  id: string // Supabase UUID
  channel_id: string // Supabase channel UUID reference
  mongo_sender_id: string // MongoDB user ID of sender
  content: string // Message content
  content_type: 'text' | 'file' | 'audio' | 'system' // Content type
  thread_id?: string // For threading (optional)
  reply_count: number // Number of replies
  mongo_mentioned_user_ids?: string[] // Array of mentioned user IDs
  is_edited: boolean // Edit status
  edited_at?: string // Edit timestamp
  created_at: string // Creation timestamp
  parent_message_id?: string // For replies
  attachments?: IAttachment[]
  read_receipts?: IReadReceipt[]
  reactions?: IReaction[] // Message reactions
  
  // Denormalized sender fields (stored in Supabase for real-time performance)
  sender_name: string
  sender_email: string
  sender_avatar?: string
  sender_role: string
  
  // Enriched sender object (computed from denormalized fields)
  sender?: IParticipant
  
  // UI helper fields (not in schema)
  isOptimistic?: boolean // For optimistic updates
  isFailed?: boolean // For failed message sends
}

// Channels table interface
export interface IChannel {
  id: string // Supabase UUID
  type: 'dm' | 'group' | 'department' | 'department-category' | 'multi-category' | 'project' | 'client-support' // Channel type
  name?: string // Channel name (optional for DMs)
  avatar_url?: string // Channel avatar URL
  mongo_department_id?: string // MongoDB department reference
  mongo_project_id?: string // MongoDB project reference
  mongo_creator_id: string // MongoDB user ID of creator
  is_private: boolean // Privacy setting
  member_count: number // Number of members
  last_message_at?: string // Last message timestamp
  created_at: string // Creation timestamp
  updated_at: string // Update timestamp
  // Advanced Channel Settings (Phase 2)
  auto_sync_enabled: boolean // Auto-add new dept members/assignees
  allow_external_members: boolean // Allow members outside dept/project
  admin_only_post: boolean // Only admins can send messages
  admin_only_add: boolean // Only admins can add new members
  // Archive fields (Phase 2)
  is_archived?: boolean // Whether the channel is archived
  archived_at?: string // Archive timestamp
  archived_by?: string // MongoDB user ID who archived
  // Pin fields (per-user, added from channel_members)
  is_pinned?: boolean // Whether the current user has pinned this channel
  pinned_at?: string | null // When the current user pinned this channel
  // UI helper fields (not in schema)
  last_message?: ICommunication
  unreadCount?: number
  channel_members: IChannelMember[] // Enriched channel members with user data
}

// Channel members table interface
export interface IChannelMember {
  role: string
  // Prisma fields
  id: string // Supabase UUID
  channel_id: string // Supabase channel UUID
  mongo_member_id: string // MongoDB user ID
  channelRole: 'owner' | 'admin' | 'member' // Channel role (owner = creator)
  joined_at: string // Join timestamp
  last_seen_at?: string // Last seen timestamp
  notifications_enabled: boolean // Notification preference
  added_by?: string // MongoDB user ID who added this member
  added_via?: 'creation' | 'auto_sync' | 'manual_add' | 'invitation' // How the member was added
  
  // Enriched user fields
  userRole: string // User role from MongoDB
  name: string // User name
  email: string // User email
  avatar?: string // User avatar
  userType: 'User' | 'Client' // User type
  isOnline: boolean // Online status (enriched from presence or is_online db field)
}

export interface IParticipant {
  mongo_member_id: string // Changed from 'mongoUserId'
  name: string
  email: string
  avatar?: string
  isOnline: boolean
  userType: 'User' | 'Client'
  role?: string
}

export interface ITypingIndicator {
  channelId: string
  userId: string
  userName: string
  timestamp: string // ISO string for Redux serialization
}

// Filter and Query Types
export interface CommunicationFilters {
  channelId?: string
  is_private?: boolean // Changed from 'isInternal'
  mongoDepartmentId?: string
  mongo_project_id?: string
  search?: string
  dateFrom?: string
  dateTo?: string
}

export interface CommunicationSort {
  field: keyof ICommunication
  direction: 'asc' | 'desc'
}

export interface FetchMessagesParams {
  channel_id: string
  page?: number
  limit?: number
  filters?: CommunicationFilters
  sort?: CommunicationSort
}

// Form Data Types
export interface CreateMessageData {
  channel_id: string
  content: string // Changed from 'message'
  content_type?: 'text' | 'file' | 'audio' | 'system' // Changed from 'messageType'
  attachments?: string[] // array of attachment URLs or attachment ids (depends on upload flow)
  attachment_ids?: string[] // IDs of pre-uploaded attachments
  // Audio attachment data for voice messages
  audio_attachment?: {
    file_url: string
    file_name?: string
    file_size?: number
    file_type?: string
    duration_seconds?: number
  }
  thread_id?: string // Changed from 'parentMessageId'
  parent_message_id?: string // For replies
  mongo_mentioned_user_ids?: string[] // Mentioned users
}

export interface CreateChannelData {
  name?: string
  type: 'dm' | 'group' | 'department' | 'project' | 'client-support' // Updated to match schema
  channel_members: string[] // MongoDB User IDs
  mongo_project_id?: string
  mongo_department_id?: string
  is_private?: boolean // Changed from 'isInternal'
}

export interface UpdateMessageData {
  content?: string // Changed from 'message'
}

// Component Props Types
export interface ChatWindowProps {
  channelId: string
  className?: string
  onToggleSidebar?: () => void
  isSidebarExpanded?: boolean
  fullscreenRef?: React.RefObject<FullscreenToggleRef | null>
  onFullscreenChange?: (isFullscreen: boolean) => void
}

export interface MessageListProps {
  messages: ICommunication[]
  typingUsers: ITypingIndicator[]
  currentUserId: string
  onMessageRead?: (messageId: string) => void
}

export interface MessageInputProps {
  channelId: string
  onSend: (data: CreateMessageData) => void
  disabled?: boolean
  placeholder?: string
  allowAttachments?: boolean
}

export interface ChannelListProps {
  channels: IChannel[]
  activeChannelId?: string
  onChannelSelect: (channelId: string) => void
  currentUserId: string
  showSearch?: boolean
}

export interface OnlineIndicatorProps {
  users: IParticipant[]
  maxVisible?: number
}

export interface ContextPanelProps {
  channel?: IChannel
  isVisible: boolean
  onToggle: () => void
}

// API Response Types
export interface CommunicationApiResponse {
  success: boolean
  data?: ICommunication | ICommunication[]
  pagination?: {
    page: number
    limit: number
    total: number
    pages: number
  }
  error?: string
  message?: string
}

export interface ChannelApiResponse {
  success: boolean
  data?: IChannel | IChannel[]
  pagination?: {
    page: number
    limit: number
    total: number
    pages: number
  }
  error?: string
  message?: string
}

// New interfaces for additional features
export interface IReaction {
  id: string
  message_id: string
  channel_id: string
  mongo_user_id: string
  user_name?: string
  emoji: string
  created_at: string
}

// Grouped reactions for display
export interface IGroupedReaction {
  emoji: string
  count: number
  users: { id: string; mongo_user_id: string; name?: string }[]
  hasCurrentUserReacted: boolean
}

export interface IAttachment {
  id: string
  message_id: string
  file_name: string
  file_url?: string
  s3_key?: string
  s3_bucket?: string
  file_size?: number
  file_type?: string
  uploaded_by?: string
  created_at: string
  width?: number
  height?: number
  durationSeconds?: number
}

export interface IReadReceipt {
  message_id: string
  mongo_user_id: string
  read_at: string
}