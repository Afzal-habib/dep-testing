# Communication Module Documentation (v8 - Enterprise Ready)

**Last Updated:** January 5, 2026  
**Status:** ✅ Production Ready - Enterprise Grade

## Overview

The Communication Module is a comprehensive real-time messaging system built for the DepLLC CRM application. It provides multi-channel communication capabilities including direct messages, group chats, department channels, project channels, and client support channels. The module uses a **hybrid database architecture** where **MongoDB serves as the primary database** for user profiles, business data, and authentication, while **Supabase (PostgreSQL) handles real-time communication data** including channels, messages, members, reactions, and read receipts.

### 🚀 Optimization Highlights (v8 - Enterprise Ready)

This version includes significant optimizations and enterprise-grade improvements:

| Improvement | Before | After |
|-------------|--------|-------|
| **API Routes** | 20+ separate route files | 8 consolidated routes with `?action=` parameters |
| **Database Ops** | Scattered Prisma calls | Centralized `operations.ts` service |
| **Real-time** | Direct Supabase calls | Unified `broadcast.ts` service |
| **Caching** | None | In-memory TTL cache via `cache.ts` |
| **Prisma Version** | 5.x | 7.x with driver adapters |
| **Code Reduction** | ~3,500 lines | ~2,100 lines (40% reduction) |
| **Logging** | `console.log` statements | Centralized `communicationLogger` |
| **Error Handling** | Inconsistent | Standardized logger + toast pattern |
| **Database Indexes** | Basic | Optimized with GIN indexes for arrays |

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              FRONTEND (Next.js 16)                               │
│  ┌─────────────────┐  ┌────────────────┐  ┌──────────────────────────────────┐ │
│  │  React Components│  │ useCommunications│  │ Redux Store (communicationSlice)│ │
│  │  - ChatWindow    │◄─┤     Hook        │◄─┤ - channels, messages            │ │
│  │  - MessageList   │  │                  │  │ - onlineUserIds, typingUsers   │ │
│  │  - MessageInput  │  │                  │  │ - loading states               │ │
│  │  - ChannelList   │  │                  │  │ - notifications                │ │
│  └─────────────────┘  └───────┬────────┘  └──────────────────────────────────┘ │
│                                │                                                 │
└────────────────────────────────┼─────────────────────────────────────────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
          ▼                      ▼                      ▼
┌─────────────────────┐ ┌───────────────────┐ ┌─────────────────────┐
│  RealtimeManager    │ │   API Routes      │ │   Supabase Client   │
│  (Singleton)        │ │   /api/comm/...   │ │   (Realtime Sub)    │
│  - Presence         │ │   - messages      │ │   - Broadcasting    │
│  - Typing           │ │   - channels      │ │   - Presence        │
│  - Broadcasting     │ │   - reactions     │ │   - Subscriptions   │
└─────────────────────┘ └─────────┬─────────┘ └─────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              BACKEND LAYER                                       │
│  ┌─────────────────────────┐  ┌──────────────────────────────────────────────┐ │
│  │  Supabase (PostgreSQL)   │  │  MongoDB (via Mongoose)                      │ │
│  │  - channels              │  │  - Users (primary user data)                 │ │
│  │  - messages              │  │  - Roles                                     │ │
│  │  - channel_members       │  │  - Projects, Departments                     │ │
│  │  - reactions             │  │  - Business entities                         │ │
│  │  - read_receipts         │  │                                              │ │
│  │  - attachments           │  │  * Used only for user lookup/enrichment      │ │
│  └─────────────────────────┘  └──────────────────────────────────────────────┘  │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │  AWS S3 (File Storage)                                                       ││
│  │  - chat-attachments/ (message files)                                         ││
│  └─────────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Why Hybrid Database Approach?

| Database | Purpose | Rationale |
|----------|---------|-----------|
| **MongoDB** | Primary database for business logic | Single source of truth for users, roles, projects, departments, and all business entities. Maintains referential integrity and complex relationships. |
| **Supabase (PostgreSQL)** | Real-time communication data | Optimized for chat workloads, built-in real-time features, fast message queries, presence tracking, and broadcasting. No MongoDB joins required for chat operations. |
| **AWS S3** | File attachments | Scalable blob storage with presigned URLs for secure file access. |

### Key Benefits of This Architecture:
- **Performance**: Chat operations don't require MongoDB lookups for every message
- **Real-time**: Supabase's built-in real-time features for instant messaging
- **Scalability**: Separate databases can scale independently
- **Data Integrity**: MongoDB maintains business data consistency
- **Developer Experience**: Prisma ORM for type-safe database operations
- **Enterprise Logging**: Centralized logging with proper log levels
- **User Feedback**: Consistent toast notifications for all operations
- **Maintainability**: Standardized patterns across all files

## Database Architecture

### Supabase PostgreSQL Schema (Communication Data)

```prisma
// channels - Chat rooms/conversations
model channels {
  id                     String            @id @default(uuid())
  type                   String            // 'dm', 'group', 'department', 'project', 'client-support'
  name                   String?
  avatar_url             String?
  mongo_department_id    String?           // Reference to MongoDB Department
  mongo_project_id       String?           // Reference to MongoDB Project
  mongo_creator_id       String            // Reference to MongoDB User
  is_private             Boolean           @default(false)
  member_count           Int               @default(0)
  last_message_at        DateTime?
  categories             String[]          @default([])  // For department categories
  created_at             DateTime          @default(now())
  updated_at             DateTime          @default(now())

  // Archive fields
  is_archived            Boolean           @default(false)
  archived_at            DateTime?
  archived_by            String?

  // Advanced settings
  auto_sync_enabled      Boolean           @default(true)
  allow_external_members Boolean           @default(false)
  admin_only_post        Boolean           @default(false)
  admin_only_add         Boolean           @default(false)

  // Relations
  channel_members        channel_members[]
  messages               messages[]
  attachments            attachments[]
  reactions              reactions[]
}

// channel_members - Channel membership with roles and permissions
model channel_members {
  id                    String    @id @default(uuid())
  channel_id            String
  mongo_member_id       String    // Reference to MongoDB User._id
  role                  String    @default("member")  // 'owner', 'admin', 'member'
  joined_at             DateTime  @default(now())
  last_seen_at          DateTime?
  is_online             Boolean   @default(false)
  notifications_enabled Boolean   @default(true)

  // Pinning feature
  is_pinned             Boolean   @default(false)
  pinned_at             DateTime?

  // Tracking how member was added
  added_by              String?
  added_via             String?   // 'creation', 'auto_sync', 'manual_add', 'invitation'

  channels              channels  @relation(fields: [channel_id], references: [id], onDelete: Cascade)

  @@unique([channel_id, mongo_member_id])
  @@index([mongo_member_id])
  @@index([channel_id, role])
  @@index([mongo_member_id, is_pinned])
}

// messages - Chat messages with denormalized sender data
model messages {
  id                       String          @id @default(uuid())
  channel_id               String
  mongo_sender_id          String
  content                  String          // HTML content from TipTap editor
  content_type             String          @default("text")
  thread_id                String?         // For message threading
  parent_message_id        String?         // For replies
  reply_count              Int             @default(0)
  mongo_mentioned_user_ids String[]        // @mentions
  is_edited                Boolean         @default(false)
  edited_at                DateTime?
  created_at               DateTime        @default(now())

  // Denormalized sender fields for performance (no MongoDB lookups needed)
  sender_name              String          @default("Unknown User")
  sender_email             String          @default("")
  sender_avatar            String?
  sender_role              String          @default("User")

  // Trash/Delete management
  is_trashed               Boolean         @default(false)
  trashed_at               DateTime?
  trashed_by               String?
  trash_reason             String?
  hidden_by_users          String[]        @default([])  // "Hide for Me" feature
  original_content         String?

  // Relations
  attachments              attachments[]
  channels                 channels        @relation(fields: [channel_id], references: [id], onDelete: Cascade)
  messages                 messages?       @relation("messagesTomessages", fields: [parent_message_id], references: [id])
  other_messages           messages[]      @relation("messagesTomessages")
  reactions                reactions[]
  read_receipts            read_receipts[]

  @@index([parent_message_id])
  @@index([channel_id, is_trashed, created_at(sort: Desc)])
  @@index([mongo_sender_id, is_trashed])
  @@index([is_trashed, trashed_at])
}

// reactions - Message reactions (emoji)
model reactions {
  id            String   @id @default(uuid())
  message_id    String
  channel_id    String
  mongo_user_id String
  user_name     String   @default("Unknown")  // Denormalized for display
  emoji         String
  created_at    DateTime @default(now())

  channels      channels @relation(fields: [channel_id], references: [id], onDelete: Cascade)
  messages      messages @relation(fields: [message_id], references: [id], onDelete: Cascade)

  @@unique([message_id, mongo_user_id, emoji])
}

// read_receipts - Message read status tracking
model read_receipts {
  id            String   @id @default(uuid())
  message_id    String
  mongo_user_id String
  read_at       DateTime @default(now())

  messages      messages @relation(fields: [message_id], references: [id], onDelete: Cascade)

  @@unique([message_id, mongo_user_id])
}

// attachments - File attachments metadata
model attachments {
  id                String   @id @default(uuid())
  message_id        String
  channel_id        String
  mongo_uploader_id String
  file_name         String
  file_url          String?
  s3_key            String?
  s3_bucket         String?
  file_size         Int?
  file_type         String?
  created_at        DateTime @default(now())

  channels          channels @relation(fields: [channel_id], references: [id], onDelete: Cascade)
  messages          messages @relation(fields: [message_id], references: [id], onDelete: Cascade)
}
```

### Denormalization Strategy

Messages store sender data directly in Supabase to avoid MongoDB lookups on every message read:

```typescript
// When creating a message, fetch sender once from MongoDB and store inline
const senderData = await User.findById(session.user.id)

const message = await prisma.messages.create({
  data: {
    content: data.content,
    mongo_sender_id: session.user.id,
    // Denormalized sender fields for instant loading
    sender_name: senderData.name,
    sender_email: senderData.email,
    sender_avatar: senderData.avatar,
    sender_role: extractRoleName(senderData.role),
  }
})
```

**Benefits:**
- ✅ No MongoDB joins on message fetch
- ✅ Instant message loading in real-time broadcasts
- ✅ Reduced database load and improved performance
- ⚠️ Trade-off: Must update denormalized data if user profile changes (handled via background sync)

## Features List

### Core Messaging Features
- **Real-time Messaging**: Instant message delivery with WebSocket connections via Supabase
- **Rich Text Editor**: HTML-based message composition with formatting, mentions, and emoji support (TipTap)
- **File Attachments**: Upload and share files with progress tracking and preview capabilities (AWS S3)
- **Voice Messages**: Record and send audio messages with duration tracking and playback
- **Message Reactions**: Add/remove emoji reactions to messages with real-time updates
- **Message Threading**: Reply to specific messages in threads with reply counts
- **Message Editing**: Edit sent messages with audit logging and change tracking
- **Read Receipts**: Track message read status across channel members with timestamps

### Channel Management
- **Multiple Channel Types**:
  - **Direct Messages (DM)**: One-on-one conversations with auto-creation
  - **Group Channels**: Custom group chats with flexible membership
  - **Department Channels**: Auto-synced based on user departments with role-based access
  - **Department Category Channels**: Sales, Support, IT, Management with cross-department communication
  - **Multi-Category Channels**: Combine multiple department categories for specialized teams
  - **Project Channels**: Auto-populated with project collaborators and task assignees
  - **Client Support Channels**: Dedicated support team channels with external member options
- **Channel Settings**: Configure privacy, member permissions, auto-sync, and notifications
- **Channel Pinning**: Pin frequently used channels for quick access (up to 5 per user)
- **Channel Archiving**: Archive inactive channels with restoration capability

### User Experience Features
- **Online Presence**: Real-time user online/offline status with Supabase presence tracking
- **Typing Indicators**: Show when users are typing in channels with throttling optimization
- **Unread Message Counts**: Badge notifications for unread messages with channel prioritization
- **Message Search**: Full-text search within channels with highlighting and pagination
- **Message History**: Load older messages with infinite scroll and pagination
- **Trash Management**: Soft delete messages with 30-day restore window and permanent deletion
- **Audit Logging**: Track message edits, deletions, and restorations with actor information

### Advanced Features
- **Mention System**: @mention users with autocomplete, notifications, and highlighting
- **Notification System**: Browser notifications for new messages and mentions with permission handling
- **Context Panel**: Channel information, member list, file attachments, and member management
- **Resizable Sidebar**: Adjustable communication panel width with persistent storage
- **Connection Status**: Monitor real-time WebSocket connection health with auto-reconnect
- **Emoji Picker**: Comprehensive emoji selection with categories and search
- **Voice Recorder**: High-quality audio recording with permission handling and visual feedback

## Real-time System (Supabase)

### RealtimeManager Class

The `RealtimeManager` is a **singleton** class that manages all Supabase real-time connections:

**Location:** `lib/realtime-manager.ts`

```typescript
class RealtimeManager {
  private rtChannels: Map<string, RealtimeChannel> = new Map()
  private subscriptionPromises: Map<string, Promise<void>> = new Map()
  private eventHandlers: RealtimeEventHandlers = {}
  private presenceChannel: RealtimeChannel | null = null
  private currentUserId: string | null = null
  private presenceInitialized: boolean = false

  // Typing indicator optimization
  private typingTimeouts: Map<string, NodeJS.Timeout> = new Map()
  private lastTypingSent: Map<string, number> = new Map()
  private isTyping: Map<string, boolean> = new Map()
  private remoteTypingTimeouts: Map<string, NodeJS.Timeout> = new Map()
}
```

### Supabase Channel Types Used

#### 1. Global Presence Channel (`global_presence`)

**Purpose:** Track which users are online across the entire application.

```typescript
async initializePresence(userId: string, userName: string, userAvatar?: string) {
  this.presenceChannel = supabase.channel('global_presence', {
    config: {
      presence: { key: userId }
    }
  })

  this.presenceChannel
    .on('presence', { event: 'sync' }, () => {
      const state = this.presenceChannel.presenceState()
      // Update online users list
      this.eventHandlers.onPresenceSync?.(state)
    })
    .on('presence', { event: 'join' }, ({ key }) => {
      this.eventHandlers.onUserOnline?.(key)
    })
    .on('presence', { event: 'leave' }, ({ key }) => {
      this.eventHandlers.onUserOffline?.(key)
    })
    .subscribe()

  // Track current user's presence
  await this.presenceChannel.track({
    userId,
    userName,
    userAvatar,
    online_at: new Date().toISOString()
  })
}
```

#### 2. Chat Channel Subscriptions (`rt_${channelId}`)

**Purpose:** Real-time updates for specific chat channels.

```typescript
subscribeToChannel(channelId: string, eventHandlers: RealtimeEventHandlers) {
  const rtChannel = supabase.channel(`rt_${channelId}`, {
    config: {
      broadcast: { self: false }  // Don't receive own broadcasts
    }
  })

  rtChannel
    .on('broadcast', { event: 'new_message' }, (payload) => {
      eventHandlers.onNewMessage?.(payload)
    })
    .on('broadcast', { event: 'message_update' }, (payload) => {
      eventHandlers.onMessageUpdate?.(payload)
    })
    .on('broadcast', { event: 'message_delete' }, (payload) => {
      eventHandlers.onMessageDelete?.(payload)
    })
    .on('broadcast', { event: 'typing_start' }, (payload) => {
      eventHandlers.onTypingStart?.(payload)
    })
    .on('broadcast', { event: 'typing_stop' }, (payload) => {
      eventHandlers.onTypingStop?.(payload)
    })
    .on('broadcast', { event: 'message_read' }, (payload) => {
      eventHandlers.onMessageRead?.(payload)
    })
    .on('broadcast', { event: 'reaction_added' }, (payload) => {
      eventHandlers.onReactionAdd?.(payload)
    })
    .on('broadcast', { event: 'reaction_removed' }, (payload) => {
      eventHandlers.onReactionRemove?.(payload)
    })
    .subscribe()
}
```

#### 3. User Notification Channel (`notifications_${userId}`)

**Purpose:** Personal notifications for @mentions and direct messages.

```typescript
async subscribeToNotifications(userId: string) {
  this.notificationChannel = supabase.channel(`notifications_${userId}`)

  this.notificationChannel
    .on('broadcast', { event: 'mention_notification' }, (payload) => {
      this.eventHandlers.onMentionNotification?.(payload)
    })
    .on('broadcast', { event: 'dm_notification' }, (payload) => {
      this.eventHandlers.onDMNotification?.(payload)
    })
    .subscribe()
}
```

### Broadcast Events Reference

| Event | Trigger | Payload | Real-time Update |
|-------|---------|---------|------------------|
| `new_message` | Message created | Full message object with denormalized sender data | Instant message display |
| `message_update` | Message edited | Updated message object | Live message editing |
| `message_delete` | Message deleted | `{ messageId, channelId }` | Message removal |
| `typing_start` | User starts typing | `{ userId, userName, channelId }` | Show typing indicator |
| `typing_stop` | User stops typing | `{ userId, channelId }` | Hide typing indicator |
| `message_read` | Message marked read | `{ messageId, userId, channelId, readAt }` | Update read receipts |
| `reaction_added` | Reaction added | Full reaction object | Add reaction badge |
| `reaction_removed` | Reaction removed | `{ messageId, userId, emoji }` | Remove reaction badge |
| `mention_notification` | User @mentioned | Notification data | Browser notification |
| `channel_updated` | Channel metadata changed | Updated channel object | Update channel info |
| `member_joined/left` | Membership changed | Member data | Update member list |

### Typing Indicator Optimization

The typing system uses sophisticated throttling to prevent network flooding:

```typescript
private readonly TYPING_THROTTLE_MS = 2000  // Send max every 2 seconds
private readonly TYPING_TIMEOUT_MS = 3500   // Auto-stop after 3.5 seconds
private readonly REMOTE_TYPING_TIMEOUT_MS = 4000  // Remove stale indicators

async sendTypingStart(channelId: string, userId: string) {
  const now = Date.now()
  const lastSent = this.lastTypingSent.get(channelId) || 0

  // Throttle: skip if sent recently
  if (this.isTyping.get(channelId) && now - lastSent < TYPING_THROTTLE_MS) {
    return
  }

  // Set auto-stop timeout
  const timeout = setTimeout(() => {
    this.sendTypingStop(channelId, userId)
  }, TYPING_TIMEOUT_MS)
  this.typingTimeouts.set(channelId, timeout)

  // Broadcast typing start
  this.isTyping.set(channelId, true)
  this.lastTypingSent.set(channelId, now)

  const rtChannel = this.rtChannels.get(channelId)
  rtChannel?.send({
    type: 'broadcast',
    event: 'typing_start',
    payload: { userId, userName: this.currentUserName, channelId }
  })
}
```



## Real-time Methods in RealtimeManager

The `RealtimeManager` class handles all real-time communication using Supabase's real-time features. It manages channel subscriptions, presence, typing indicators, and event broadcasting.

### Core Methods

#### `initializePresence(userId: string, userName: string, userAvatar?: string)`
- Initializes user presence tracking
- Joins global presence channel
- Broadcasts user's online status
- Sets up presence state change listeners

#### `subscribeToChannel(channelId: string, eventHandlers: RealtimeEventHandlers)`
- Creates or reuses Supabase real-time channel subscription
- Subscribes to channel-specific events (messages, reactions, member updates)
- Handles connection recovery and resubscription
- Prevents duplicate subscriptions per channel

#### `unsubscribeFromChannel(channelId: string)`
- Removes channel subscription
- Cleans up event listeners
- Updates subscription tracking

#### `sendMessage(channelId: string, messageData: any)`
- Broadcasts new message to channel subscribers
- Includes message content, sender info, and metadata
- Triggers real-time updates for all channel members

#### `sendTypingIndicator(channelId: string, userId: string, userName: string)`
- Sends typing start event with debouncing (300ms)
- Automatically clears typing after 3 seconds of inactivity
- Updates typing indicators for other channel members

#### `sendReaction(channelId: string, messageId: string, emoji: string, userId: string)`
- Broadcasts reaction addition/removal
- Updates message reaction counts in real-time
- Handles reaction toggling (add/remove)

#### `updatePresence(state: 'online' | 'away' | 'offline')`
- Updates user's presence state
- Broadcasts presence changes to all connected users
- Maintains presence heartbeat

#### `handleRealtimeEvent(eventType: string, payload: any)`
- Central event handler for all real-time events
- Routes events to appropriate handlers (new messages, typing, presence, etc.)
- Updates Redux store state accordingly

### Event Types Handled
- `new_message`: New message in channel
- `message_updated`: Message edit
- `message_deleted`: Message deletion
- `reaction_added/removed`: Reaction changes
- `user_typing`: Typing indicators
- `presence_changed`: User online/offline status
- `channel_updated`: Channel metadata changes
- `member_joined/left`: Channel membership changes



## Phase 1 Infrastructure (Centralized Services)

The Communication Module uses a layered architecture with centralized services to reduce code duplication and improve maintainability.

### operations.ts - Centralized Database Operations

**Location:** `lib/communication/operations.ts`

All database operations are centralized through typed service objects:

```typescript
// Channel Operations
export const channelOps = {
  // Get channel by ID with optional member inclusion
  getById: async (channelId: string, options?: { includeMembers?: boolean }): Promise<Channel | null>
  
  // Get user's role in a channel
  getMemberRole: async (channelId: string, userId: string): Promise<'owner' | 'admin' | 'member' | null>
  
  // Check if user is a member
  isMember: async (channelId: string, userId: string): Promise<boolean>
  
  // Get member record
  getMember: async (channelId: string, userId: string): Promise<ChannelMember | null>
  
  // Create channel
  create: async (data: CreateChannelInput): Promise<Channel>
  
  // Update channel
  update: async (channelId: string, data: UpdateChannelInput): Promise<Channel>
  
  // Delete channel
  delete: async (channelId: string): Promise<void>
  
  // Add member
  addMember: async (channelId: string, userId: string, role?: string): Promise<ChannelMember>
  
  // Remove member
  removeMember: async (channelId: string, userId: string): Promise<void>
  
  // Update member role
  updateMemberRole: async (channelId: string, userId: string, role: string): Promise<ChannelMember>
}

// Message Operations
export const messageOps = {
  // Get messages for channel with pagination
  getByChannel: async (channelId: string, options: { limit?: number; offset?: number; currentUserId?: string })
  
  // Search messages
  search: async (channelId: string, query: string, options?: { limit?: number; offset?: number })
  
  // Create message
  create: async (data: CreateMessageInput): Promise<Message>
  
  // Update message content
  update: async (messageId: string, content: string): Promise<Message>
  
  // Soft delete (trash)
  trash: async (messageId: string, userId: string, reason?: string): Promise<void>
  
  // Restore from trash
  restore: async (messageId: string): Promise<Message>
  
  // Permanent delete
  delete: async (messageId: string): Promise<void>
}

// Attachment Operations
export const attachmentOps = {
  // Get attachments for channel
  getByChannel: async (channelId: string, options?: { limit?: number; offset?: number })
  
  // Get attachment by ID
  getById: async (attachmentId: string): Promise<Attachment | null>
  
  // Create attachment record
  create: async (data: CreateAttachmentInput): Promise<Attachment>
  
  // Delete attachment
  delete: async (attachmentId: string): Promise<void>
}
```

**Benefits of Centralized Operations:**
- ✅ Type-safe database operations
- ✅ Consistent error handling
- ✅ Single point for query optimization
- ✅ Easy to add caching layer
- ✅ Testable in isolation

### broadcast.ts - Unified Real-time Broadcasting

**Location:** `lib/communication/broadcast.ts`

All Supabase real-time broadcasts go through unified functions:

```typescript
// Core broadcast functions
export async function broadcastToChannel(params: {
  channelId: string
  event: BroadcastEvent
  payload: Record<string, unknown>
}): Promise<boolean>

export async function broadcastToUser(params: {
  userId: string
  event: NotificationEvent
  payload: Record<string, unknown>
}): Promise<boolean>

// Convenience functions for common broadcasts
export async function broadcastNewMessage(
  channelId: string, 
  message: MessageWithSender
): Promise<boolean>

export async function broadcastMessageUpdate(
  channelId: string,
  messageId: string,
  updates: { content?: string; attachmentsAdded?: number; attachmentsRemoved?: number }
): Promise<boolean>

export async function broadcastMessageDelete(
  channelId: string,
  messageId: string,
  deletedBy: string
): Promise<boolean>

export async function broadcastMemberChange(
  channelId: string,
  action: 'joined' | 'left' | 'role_updated',
  member: ChannelMember
): Promise<boolean>

export async function broadcastChannelUpdate(
  channelId: string,
  updates: Partial<Channel>
): Promise<boolean>

export async function sendMentionNotification(
  userId: string,
  data: {
    channelId: string
    channelName: string
    messageId: string
    mentionedBy: string
    mentionedByName: string
    preview: string
  }
): Promise<boolean>
```

**Usage in Route Handlers:**

```typescript
// In POST /api/communication/messages
const message = await messageOps.create(messageData)

// Broadcast asynchronously (fire-and-forget for performance)
setImmediate(async () => {
  await broadcastNewMessage(channelId, messageWithSender)
  
  if (mentionedUserIds.length > 0) {
    for (const userId of mentionedUserIds) {
      await sendMentionNotification(userId, notificationData)
    }
  }
})

return NextResponse.json({ success: true, data: message })
```

### cache.ts - In-Memory TTL Caching

**Location:** `lib/communication/cache.ts`

Performance optimization with in-memory caching:

```typescript
class CommunicationCache {
  private channelCache: Map<string, { data: Channel; expiresAt: number }>
  private messagesCache: Map<string, { data: Message[]; expiresAt: number }>
  
  private readonly DEFAULT_TTL = 60 * 1000 // 1 minute
  private readonly CHANNEL_TTL = 5 * 60 * 1000 // 5 minutes
  private readonly MESSAGES_TTL = 30 * 1000 // 30 seconds
  
  // Channel caching
  getChannel(channelId: string): Channel | null
  setChannel(channelId: string, channel: Channel): void
  invalidateChannel(channelId: string): void
  
  // Messages caching (keyed by channel + pagination)
  getMessages(channelId: string, offset: number, limit: number): Message[] | null
  setMessages(channelId: string, offset: number, limit: number, messages: Message[]): void
  invalidateMessages(channelId: string): void
  
  // Bulk invalidation
  invalidateAll(): void
}

export const communicationCache = new CommunicationCache()
```

**Cache Invalidation Strategy:**
- Channel updates → Invalidate specific channel
- New message → Invalidate channel's message cache
- Member changes → Invalidate channel cache
- Message edit/delete → Invalidate channel's message cache

## Tech Stack & Integration

### Core Technologies

| Layer | Technology | Version | Purpose |
|-------|------------|---------|---------|
| **Frontend** | Next.js (App Router) | 16.x | React framework with SSR, API routes |
| **State Management** | Redux Toolkit | 2.x | Centralized state with slices |
| **UI Components** | Tailwind CSS + shadcn/ui | Latest | Responsive design system |
| **Rich Editor** | TipTap | 2.x | WYSIWYG message editor |
| **Real-time** | Supabase Realtime | 2.x | WebSocket connections and broadcasting |
| **Primary Database** | MongoDB | 7.x | User profiles, business data, auth |
| **Communication Database** | PostgreSQL (Supabase) | Latest | Chat data, real-time optimized |
| **File Storage** | AWS S3 | Latest | Attachments with presigned URLs |
| **Authentication** | NextAuth.js | 5.x | Session management |
| **ORM** | Prisma (with pg adapter) | 7.x | Type-safe database operations with driver adapters |
| **ODM** | Mongoose | 8.x | MongoDB object modeling |

### Key Dependencies

```json
{
  "@supabase/supabase-js": "^2.x",
  "@prisma/client": "^7.x",
  "@prisma/adapter-pg": "^7.x",
  "pg": "^8.x",
  "@reduxjs/toolkit": "^2.x",
  "@tiptap/react": "^2.x",
  "@tiptap/extension-mention": "^2.x",
  "@tiptap/extension-link": "^2.x",
  "mongoose": "^8.x",
  "@aws-sdk/client-s3": "^3.x",
  "@aws-sdk/s3-request-presigner": "^3.x",
  "date-fns": "^3.x",
  "lucide-react": "^0.294.x",
  "react-intersection-observer": "^9.x"
}
```

## API Routes Reference (Consolidated)

### Base Path: `/api/communication`

All routes use the `genericApiRoutesMiddleware` for authentication, authorization, and rate limiting.

> **💡 Route Consolidation Pattern**: Instead of separate route folders for each action, we use query parameters (`?action=`) to consolidate related operations into single route files. This reduces code duplication and improves maintainability.

#### Channels API

| Method | Endpoint | Description | Middleware Permissions |
|--------|----------|-------------|-------------------------|
| `GET` | `/channels` | Get user's channels with filters | `communication:read` |
| `POST` | `/channels` | Create new channel | `communication:create` |
| `GET` | `/channels/[channelId]` | Get channel details | `communication:read` |
| `GET` | `/channels/[channelId]?action=pin` | Get pin status | `communication:read` |
| `GET` | `/channels/[channelId]?action=settings` | Get channel settings | `communication:read` |
| `GET` | `/channels/[channelId]?action=members` | List channel members | `communication:read` |
| `PUT` | `/channels/[channelId]` | Update channel basic info | `communication:update` |
| `PUT` | `/channels/[channelId]?action=settings` | Update channel settings | `communication:update` |
| `PUT` | `/channels/[channelId]?action=member-role` | Update member role | `communication:update` |
| `PUT` | `/channels/[channelId]?action=archive` | Archive/unarchive channel | `communication:update` |
| `POST` | `/channels/[channelId]?action=pin` | Toggle pin status | `communication:update` |
| `POST` | `/channels/[channelId]?action=leave` | Leave channel | `communication:update` |
| `POST` | `/channels/[channelId]?action=members` | Add members to channel | `communication:update` |
| `DELETE` | `/channels/[channelId]` | Delete channel | `communication:delete` |
| `DELETE` | `/channels/[channelId]?action=remove-member` | Remove member | `communication:delete` |

**GET /channels Query Parameters:**
- `type` - Filter by channel type (`dm`, `project`, `department`, etc.)
- `department_id` - MongoDB department ID
- `project_id` - MongoDB project ID

**POST /channels Request Body:**
```typescript
{
  type: 'dm' | 'group' | 'department' | 'project' | 'client-support',
  name?: string,
  mongo_department_id?: string,
  mongo_project_id?: string,
  channel_members?: string[],  // MongoDB user IDs
  is_private?: boolean,
  auto_sync_enabled?: boolean,
  allow_external_members?: boolean
}
```

#### Messages API (Consolidated)

| Method | Endpoint | Description | Middleware Permissions |
|--------|----------|-------------|-------------------------|
| `GET` | `/messages?channel_id=` | Get channel messages (paginated) | `communication:read` |
| `GET` | `/messages?channel_id=&search=` | Search messages in channel | `communication:read` |
| `GET` | `/messages?trash=true` | Get user's trashed messages | `communication:read` |
| `POST` | `/messages` | Send message (JSON or FormData with files) | `communication:create` |
| `PUT` | `/messages/[messageId]` | Edit message | `communication:update` |
| `DELETE` | `/messages/[messageId]?deleteType=trash` | Move to trash (default) | `communication:delete` |
| `DELETE` | `/messages/[messageId]?deleteType=self` | Hide for me only | `communication:delete` |
| `DELETE` | `/messages/[messageId]?deleteType=permanent` | Permanently delete | `communication:delete` |
| `POST` | `/messages/[messageId]?action=restore` | Restore from trash | `communication:update` |

**GET /messages Query Parameters:**
- `channel_id` (required for channel messages) - Supabase channel UUID
- `search` - Search query for message content (ILIKE)
- `trash=true` - Get trashed messages for current user
- `limit` - Default 50, max 100
- `offset` - Default 0

**POST /messages Request Body (JSON):**
```typescript
{
  channel_id: string,
  content: string,           // HTML from TipTap editor
  content_type?: 'text' | 'file' | 'audio',
  parent_message_id?: string,  // For replies
  mongo_mentioned_user_ids?: string[]
}
```

**POST /messages with Files (FormData):**
```typescript
FormData {
  channel_id: string,
  content?: string,
  content_type?: 'text' | 'file',
  files: File[],             // Multiple files supported
  mongo_mentioned_user_ids?: string  // JSON array string
}
```

#### Attachments API (Consolidated)

| Method | Endpoint | Description | Middleware Permissions |
|--------|----------|-------------|-------------------------|
| `POST` | `/attachments` | Upload files to channel | `communication:create` |
| `GET` | `/attachments?channel_id=` | Get channel attachments | `communication:read` |
| `GET` | `/attachments?download=id` | Get presigned download URL | `communication:read` |

#### Reactions API

| Method | Endpoint | Description | Middleware Permissions |
|--------|----------|-------------|-------------------------|
| `POST` | `/reactions` | Add reaction to message | `communication:create` |
| `DELETE` | `/reactions` | Remove reaction from message | `communication:delete` |

**POST /reactions Request Body:**
```typescript
{
  message_id: string,
  channel_id: string,
  emoji: string  // Unicode emoji or shortcode
}
```

#### Read Receipts API

| Method | Endpoint | Description | Middleware Permissions |
|--------|----------|-------------|-------------------------|
| `POST` | `/read-receipts` | Mark message as read | `communication:update` |
| `GET` | `/read-receipts` | Get read receipts for message | `communication:read` |

## State Management (Redux)

### communicationSlice Structure

**Location:** `store/slices/communicationSlice.ts`

```typescript
interface CommunicationState {
  // Channel Management
  channels: IChannel[]
  activeChannelId: string | null
  selectedChannel: IChannel | null
  channelsInitialized: boolean

  // Messages (keyed by channelId for efficient access)
  messages: Record<string, ICommunication[]>
  messagesLoading: boolean
  hasMoreMessages: Record<string, boolean>

  // Real-time Features
  onlineUserIds: string[]        // Fast lookup array
  onlineUsers: IParticipant[]
  typingUsers: Record<string, ITypingIndicator[]>

  // UI State
  isChannelListExpanded: boolean
  isContextPanelVisible: boolean
  showSearch: boolean
  searchQuery: string

  // Loading & Error States
  loading: boolean
  actionLoading: boolean
  error: string | null

  // User Context
  currentUser: IParticipant | null
  currentUserId: string | null

  // Notifications
  unreadCount: number
  notifications: Notification[]

  // Trash Management
  trashedMessages: ITrashedMessage[]
  trashedMessagesLoading: boolean
  trashedMessagesPagination: PaginationState
}
```

### Key Reducers and Actions

| Action | Purpose | Optimistic Update |
|--------|---------|-------------------|
| `setActiveChannel` | Select channel, clear unread count | No |
| `addMessage` | Add new message to channel | Yes (temporary ID) |
| `updateMessage` | Update message content | Yes |
| `prependMessages` | Add older messages (pagination) | No |
| `addMessageReadReceipt` | Add read receipt | No |
| `addReactionToMessage` | Add emoji reaction | Yes |
| `removeReactionFromMessage` | Remove emoji reaction | Yes |
| `setTyping` | Add typing indicator | No |
| `removeTyping` | Remove typing indicator | No |
| `setOnlineUserIds` | Sync online users from presence | No |
| `addOnlineUser` | User came online | No |
| `removeOnlineUser` | User went offline | No |
| `moveMessageToTrash` | Soft delete message | Yes |
| `restoreMessageFromTrash` | Restore from trash | Yes |

### Optimistic Updates Pattern

```typescript
// Example: Sending a message with optimistic update
const sendMessage = async (messageData: CreateMessageData) => {
  const tempId = crypto.randomUUID()

  // 1. Create optimistic message
  const optimisticMessage: ICommunication = {
    id: tempId,
    ...messageData,
    isOptimistic: true,
    created_at: new Date().toISOString(),
    sender: currentUser
  }

  // 2. Add to store immediately for instant UI feedback
  dispatch(addMessage({
    channelId: messageData.channel_id,
    message: optimisticMessage
  }))

  try {
    // 3. Send to API
    const response = await api.post('/messages', messageData)

    // 4. Replace optimistic message with real data
    dispatch(updateMessage({
      channelId: messageData.channel_id,
      messageId: tempId,
      updates: {
        ...response.data,
        isOptimistic: false
      }
    }))
  } catch (error) {
    // 5. Remove optimistic message on failure
    dispatch(removeMessage({
      channelId: messageData.channel_id,
      messageId: tempId
    }))
    throw error
  }
}
```

## Custom Hooks

### useCommunications (Main Hook)

**Location:** `hooks/use-communications.ts`

This is the primary hook that orchestrates all communication functionality.

#### Initialization Flow

```typescript
export function useCommunications() {
  const dispatch = useAppDispatch()
  const { data: session } = useSession()

  // 1. Set current user ID in Redux store
  useEffect(() => {
    if (session?.user?.id) {
      dispatch(setCurrentUserId(session.user.id))
    }
  }, [session?.user?.id])

  // 2. Initialize presence tracking (once per session)
  useEffect(() => {
    if (session?.user?.id && !presenceInitializedRef.current) {
      presenceInitializedRef.current = true
      realtimeManager.initializePresence(
        session.user.id,
        session.user.name,
        session.user.image
      )
    }
  }, [session?.user?.id])

  // 3. Fetch channels (once per session)
  useEffect(() => {
    if (session?.user?.id && !globalFetchedChannels.get(session.user.id)) {
      globalFetchedChannels.set(session.user.id, true)
      fetchChannels()
    }
  }, [session?.user?.id])

  // 4. Subscribe to active channel real-time updates
  useEffect(() => {
    if (activeChannelId) {
      subscribeToChannel(activeChannelId)
    }
    return () => {
      if (activeChannelId) {
        realtimeManager.unsubscribeFromChannel(activeChannelId)
      }
    }
  }, [activeChannelId])

  // ... rest of hook implementation
}
```

#### Returned Interface

```typescript
return {
  // State
  channels,
  activeChannelId,
  selectedChannel,
  messages,
  onlineUserIds,
  typingUsers,
  loading,
  actionLoading,
  error,

  // Actions
  selectChannel,
  sendMessage,
  sendMessageWithFiles,
  updateMessage,
  deleteMessage,
  toggleReaction,
  markAsRead,
  createChannel,
  pinChannel,

  // Real-time
  setTyping,
  removeTyping,

  // UI
  toggleChannelList,
  toggleContextPanel,

  // Search & History
  searchMessages,
  fetchOlderMessages,

  // Trash
  moveToTrash,
  restoreFromTrash,
  permanentlyDelete,

  // Users
  users,
  usersLoading
}
```

### useChatAttachments

**Location:** `hooks/use-chat-attachments.ts`

Handles file upload/download operations with AWS S3 integration.

```typescript
export function useChatAttachments() {
  const [isUploading, setIsUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)

  const uploadAttachments = useCallback(async (
    files: File[],
    options: UploadAttachmentOptions
  ): Promise<UploadedAttachment[]> => {
    setIsUploading(true)
    setError(null)

    try {
      const formData = new FormData()
      files.forEach(file => formData.append('files', file))
      formData.append('channelId', options.channelId)
      formData.append('messageId', options.messageId)

      const response = await api.post('/attachments', formData, {
        onUploadProgress: (progressEvent) => {
          const progress = Math.round(
            (progressEvent.loaded * 100) / progressEvent.total
          )
          setUploadProgress(progress)
          options.onProgress?.(progress)
        }
      })

      return response.data.attachments
    } catch (err) {
      const errorMessage = err.response?.data?.message || 'Upload failed'
      setError(errorMessage)
      throw new Error(errorMessage)
    } finally {
      setIsUploading(false)
      setUploadProgress(0)
    }
  }, [])

  const downloadAttachment = useCallback(async (attachment: IAttachment) => {
    try {
      // Use consolidated attachments endpoint with download query param
      const response = await api.get(`/attachments`, {
        params: { download: attachment.id }
      })

      // Open download link
      window.open(response.data.downloadUrl, '_blank')
    } catch (err) {
      setError('Download failed')
      throw err
    }
  }, [])

  return {
    uploadAttachments,
    downloadAttachment,
    previewAttachment,
    fetchChannelAttachments,
    isUploading,
    uploadProgress,
    error
  }
}
```

## Frontend Components

### Component Hierarchy

```
CommunicationPage (app/communications/page.tsx)
├── CommunicationSidebar
│   ├── ChannelList (channels + search + filters)
│   │   ├── ChannelItem (with unread badges, online indicators)
│   │   └── CreateChannelModal
│   └── UserDirectory (start DMs + pinned users)
│       └── UserItem (with online status)
│
└── ChatWindow
    ├── Header (channel info + actions)
    │   ├── ChannelAvatar
    │   ├── ChannelName
    │   └── ChannelActions (settings, members, etc.)
    │
    ├── MessageList (virtualized)
    │   ├── MessageGroup (by date)
    │   ├── MessageItem
    │   │   ├── MessageContent (rich text)
    │   │   ├── MessageReactions
    │   │   ├── MessageActions (reply, edit, delete)
    │   │   └── ReadReceipts
    │   └── TypingIndicator
    │
    ├── MessageInput (RichMessageEditor)
    │   ├── TipTap Editor
    │   ├── FileUpload
    │   ├── VoiceRecorder
    │   ├── EmojiPicker
    │   └── MentionPicker
    │
    └── ContextPanel (optional)
        ├── ChannelInfo
        ├── MemberList
        └── FileAttachments
```

### Core Components

#### ChatWindow (`components/communication/chat-window.tsx`)

The main chat interface that coordinates all chat functionality:

```typescript
export function ChatWindow({
  channelId,
  className,
  onToggleSidebar,
  isSidebarExpanded,
  fullscreenRef,
  onFullscreenChange
}: ChatWindowProps) {
  // Integration with useCommunications hook
  const {
    selectedChannel,
    messages,
    sendMessage,
    updateMessage,
    markAsRead,
    // ... other props
  } = useCommunications()

  // Local state for UI
  const [isSearchVisible, setIsSearchVisible] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [showChannelSettings, setShowChannelSettings] = useState(false)

  // Auto-select channel if channelId provided
  useEffect(() => {
    if (channelId && channelId !== selectedChannel?.id) {
      selectChannel(channelId)
    }
  }, [channelId, selectedChannel?.id])

  // Handle search
  const handleSearch = useCallback(async (query: string) => {
    if (!selectedChannel) return

    const results = await searchMessages(selectedChannel.id, query)
    setSearchResults(results)
  }, [selectedChannel, searchMessages])

  return (
    <div className={cn("flex flex-col h-full", className)}>
      {/* Header */}
      <ChatHeader
        channel={selectedChannel}
        onToggleSidebar={onToggleSidebar}
        onOpenSettings={() => setShowChannelSettings(true)}
      />

      {/* Message List */}
      <MessageList
        messages={messages[selectedChannel?.id || ''] || []}
        currentUserId={currentUserId}
        onMessageRead={markAsRead}
        onReply={setReplyTo}
        onEdit={setEditMessage}
        onDelete={handleDeleteMessage}
        onReaction={handleReaction}
        hasMoreMessages={hasMoreMessages}
        isLoadingMore={isLoadingMore}
        readReceipts={readReceipts}
        channel_members={selectedChannel?.channel_members}
      />

      {/* Message Input */}
      <MessageInput
        channelId={selectedChannel?.id}
        onSend={handleSendMessage}
        onSendWithFiles={handleSendWithFiles}
        onEdit={handleEditMessage}
        disabled={!selectedChannel || actionLoading}
        channelMembers={selectedChannel?.channel_members}
        replyTo={replyTo}
        editMessage={editMessage}
        onCancelReply={() => setReplyTo(null)}
        onCancelEdit={() => setEditMessage(null)}
      />

      {/* Modals */}
      {showChannelSettings && (
        <ChannelSettingsModal
          isOpen={showChannelSettings}
          onClose={() => setShowChannelSettings(false)}
          channel={selectedChannel}
        />
      )}
    </div>
  )
}
```

#### MessageList (`components/communication/message-list.tsx`)

Virtualized message list with infinite scroll and real-time updates:

```typescript
export function MessageList({
  messages,
  typingUsers,
  currentUserId,
  onMessageRead,
  onReply,
  onEdit,
  onDelete,
  onLoadMore,
  hasMoreMessages,
  isLoadingMore,
  readReceipts,
  channel_members
}: MessageListProps) {
  // Intersection Observer for read receipts
  const observerRef = useRef<IntersectionObserver>()
  const messageRefs = useRef<Map<string, HTMLDivElement>>(new Map())

  useEffect(() => {
    observerRef.current = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const messageId = entry.target.getAttribute('data-message-id')
            if (messageId) {
              onMessageRead?.(messageId)
            }
          }
        })
      },
      { threshold: 0.5 }
    )

    return () => observerRef.current?.disconnect()
  }, [onMessageRead])

  // Group messages by date
  const groupedMessages = useMemo(() => {
    const groups: { date: string; messages: ICommunication[] }[] = []
    let currentGroup: ICommunication[] = []
    let currentDate = ''

    messages.forEach((message) => {
      const messageDate = format(new Date(message.created_at), 'yyyy-MM-dd')

      if (messageDate !== currentDate) {
        if (currentGroup.length > 0) {
          groups.push({ date: currentDate, messages: currentGroup })
        }
        currentGroup = [message]
        currentDate = messageDate
      } else {
        currentGroup.push(message)
      }
    })

    if (currentGroup.length > 0) {
      groups.push({ date: currentDate, messages: currentGroup })
    }

    return groups
  }, [messages])

  return (
    <div className="flex-1 overflow-y-auto">
      {groupedMessages.map((group) => (
        <MessageGroup
          key={group.date}
          date={group.date}
          messages={group.messages}
          currentUserId={currentUserId}
          onReply={onReply}
          onEdit={onEdit}
          onDelete={onDelete}
          messageRefs={messageRefs}
          observer={observerRef.current}
        />
      ))}

      {/* Load More */}
      {hasMoreMessages && (
        <LoadMoreButton
          onClick={onLoadMore}
          loading={isLoadingMore}
        />
      )}

      {/* Typing Indicator */}
      <TypingIndicator
        typingUsers={typingUsers}
        currentUserId={currentUserId}
      />
    </div>
  )
}
```

#### RichMessageEditor (`components/communication/rich-message-editor.tsx`)

TipTap-based rich text editor with mentions, emoji, and file handling:

```typescript
export const RichMessageEditor = forwardRef<RichMessageEditorRef, RichMessageEditorProps>(
  ({ value = "", placeholder, disabled, onChange, onSend, className, channelMembers }, ref) => {
    const editor = useEditor({
      extensions: [
        StarterKit,
        Mention.configure({
          HTMLAttributes: { class: 'mention' },
          suggestion: mentionSuggestion(channelMembers)
        }),
        Link,
        Placeholder.configure({ placeholder }),
        // Custom extensions for formatting
      ],
      content: value,
      onUpdate: ({ editor }) => {
        const html = editor.getHTML()
        const text = editor.getText()
        onChange?.(html, text)
      },
      editable: !disabled
    })

    // Handle send
    const handleSend = useCallback(() => {
      if (!editor) return

      const html = editor.getHTML()
      const text = editor.getText()
      const mentionedUsers = extractMentions(html)

      onSend?.(html, text, [], mentionedUsers)
      editor.commands.clearContent()
    }, [editor, onSend])

    return (
      <div className={cn("border rounded-lg", className)}>
        <EditorContent editor={editor} />
        <MessageToolbar editor={editor} onSend={handleSend} />
      </div>
    )
  }
)
```

## Data Flow Diagrams

### Complete Message Sending Flow

```
User Types Message in RichMessageEditor
       │
       ▼
TipTap Editor → onChange → RichMessageEditor state
       │
       ▼
User clicks Send or presses Enter
       │
       ▼
MessageInput.handleSendFromEditor()
       │
       ▼
Extract mentions, files, content
       │
       ▼
useCommunications.sendMessage()
       │
       ▼
Optimistic Update: Add to Redux store
       │
       ▼
API Call: POST /api/communication/messages
       │
       ▼
genericApiRoutesMiddleware validation
       │
       ▼
Database: Create message in Supabase
       │
       ▼
Fetch sender data from MongoDB (once)
       │
       ▼
Denormalize sender data in message
       │
       ▼
Real-time Broadcast: new_message event
       │
       ▼
RealtimeManager → All channel subscribers
       │
       ▼
Redux: Replace optimistic message with real data
       │
       ▼
React: Re-render MessageList instantly
```

### Real-time Presence Flow

```
User Opens App
       │
       ▼
useCommunications initializes
       │
       ▼
realtimeManager.initializePresence()
       │
       ▼
Supabase: Join 'global_presence' channel
       │
       ▼
presence.track() - Announce online status
       │
       ▼
Other users receive 'join' event
       │
       ▼
RealtimeManager event handler
       │
       ▼
dispatch(addOnlineUser(userId))
       │
       ▼
OnlineIndicator shows green dot
       │
       ▼
UI updates instantly across all tabs
```

## Backend Flow and API Structure

### Middleware Explanation

The core middleware `genericApiRoutesMiddleware` provides comprehensive request preprocessing:

```typescript
const { session, user, userEmail, isSuperAdmin } = await genericApiRoutesMiddleware(request, 'communication', 'read')
```

**What it does:**
1. **Rate Limiting**: Prevents API abuse by limiting requests per user/IP address
2. **Authentication**: Validates user session via NextAuth.js
   - Checks for valid JWT token in cookies
   - Extracts user information from session
   - Returns 401 if unauthenticated
3. **Authorization**: Enforces role-based access control
   - Checks if user has required permission ('communication:read')
   - Supports module-specific permissions
   - Returns 403 if unauthorized
4. **User Enrichment**: Fetches additional user data from MongoDB
   - Retrieves full user profile (name, email, avatar, role, department)
   - Includes department and project associations
   - Provides `isSuperAdmin` flag for elevated permissions
5. **Request Validation**: Sanitizes and validates request data
6. **Audit Logging**: Logs API access for security monitoring

**Return Values:**
- `session`: NextAuth session object
- `user`: Full user data from MongoDB
- `userEmail`: User's email address
- `isSuperAdmin`: Boolean indicating super admin status

This middleware ensures all communication API endpoints are secure, rate-limited, and properly authenticated before executing business logic.

### Database Operations

#### Message Creation with Denormalization

```typescript
// POST /api/communication/messages
export async function POST(request: NextRequest) {
  const { session, user } = await genericApiRoutesMiddleware(request, 'communication', 'create')

  const body = await request.json()
  const { channel_id, content, mentioned_user_ids } = body

  // 1. Create message in Supabase with denormalized sender data
  const message = await prisma.messages.create({
    data: {
      channel_id,
      mongo_sender_id: session.user.id,
      content,
      mongo_mentioned_user_ids: mentioned_user_ids || [],
      // Denormalized fields for instant loading
      sender_name: user.name,
      sender_email: user.email,
      sender_avatar: user.avatar,
      sender_role: user.role?.name || 'User'
    }
  })

  // 2. Broadcast to real-time subscribers
  await realtimeManager.sendMessage(channel_id, message)

  // 3. Send notifications for mentions
  if (mentioned_user_ids?.length > 0) {
    await sendMentionNotifications(message, mentioned_user_ids)
  }

  return NextResponse.json(message)
}
```

#### Channel Auto-sync Logic

```typescript
// When user department changes in MongoDB
export async function syncUserChannels(userId: string, newDepartmentId: string) {
  // 1. Find all department channels for new department
  const departmentChannels = await prisma.channels.findMany({
    where: {
      type: 'department',
      mongo_department_id: newDepartmentId,
      auto_sync_enabled: true
    }
  })

  // 2. Add user to these channels
  for (const channel of departmentChannels) {
    await prisma.channel_members.upsert({
      where: {
        channel_id_mongo_member_id: {
          channel_id: channel.id,
          mongo_member_id: userId
        }
      },
      update: { added_via: 'auto_sync' },
      create: {
        channel_id: channel.id,
        mongo_member_id: userId,
        role: 'member',
        added_via: 'auto_sync'
      }
    })
  }

  // 3. Remove from old department channels
  const oldDepartmentChannels = await prisma.channels.findMany({
    where: {
      type: 'department',
      mongo_department_id: { not: newDepartmentId },
      auto_sync_enabled: true
    }
  })

  for (const channel of oldDepartmentChannels) {
    await prisma.channel_members.deleteMany({
      where: {
        channel_id: channel.id,
        mongo_member_id: userId,
        added_via: 'auto_sync'  // Only remove auto-added memberships
      }
    })
  }
}
```

## Backend Folder Structure (Optimized)

The Communication Module's backend implementation is organized across multiple directories, following Next.js App Router conventions and separation of concerns. Here's the complete folder structure with explanations:

### API Routes Structure (`app/api/communication/`) - CONSOLIDATED

```
app/api/communication/
├── channels/
│   ├── route.ts                    # GET: List user's channels, POST: Create channel
│   └── [channelId]/
│       └── route.ts                # CONSOLIDATED: All channel operations via ?action=
│                                   # GET: details, ?action=pin|settings|members
│                                   # PUT: update, ?action=settings|member-role|archive
│                                   # POST: ?action=pin|leave|members
│                                   # DELETE: delete, ?action=remove-member
├── messages/
│   ├── route.ts                    # CONSOLIDATED: All message listing operations
│   │                               # GET: ?channel_id= messages, ?search= search, ?trash=true
│   │                               # POST: Send message (JSON or FormData with files)
│   ├── [messageId]/
│   │   └── route.ts                # PUT: Edit, DELETE: trash/hide/permanent
│   │                               # POST: ?action=restore
│   └── audit-logs/
│       └── route.ts                # GET: Message audit logs (admin only)
├── reactions/
│   └── route.ts                    # POST/DELETE: Add/remove reactions
├── read-receipts/
│   └── route.ts                    # POST: Mark as read, GET: Get read receipts
├── attachments/
│   └── route.ts                    # CONSOLIDATED: POST upload, GET list, ?download=id
└── users/
    └── [userId]/
        └── pin/
            └── route.ts            # User pinning endpoints
```

**Route Consolidation Benefits:**
- ✅ 40% reduction in route files (from 20+ to 9)
- ✅ Centralized action handling per resource
- ✅ Easier maintenance and testing
- ✅ Consistent error handling patterns
- ✅ Reduced code duplication

### Centralized Services (`lib/communication/`) - Phase 1 Infrastructure

```
lib/communication/
├── operations.ts                   # 📦 Centralized database operations
│   ├── channelOps                  # Channel CRUD, membership, settings
│   ├── messageOps                  # Message CRUD, search, trash
│   └── attachmentOps               # Attachment CRUD, S3 operations
├── broadcast.ts                    # 📡 Unified real-time broadcasting
│   ├── broadcastToChannel()        # Send event to channel subscribers
│   ├── broadcastToUser()           # Send personal notification
│   ├── broadcastNewMessage()       # Convenience: new message broadcast
│   ├── broadcastMessageUpdate()    # Convenience: message edit broadcast
│   ├── broadcastMessageDelete()    # Convenience: message delete broadcast
│   ├── broadcastMemberChange()     # Member join/leave notifications
│   ├── broadcastChannelUpdate()    # Channel metadata changes
│   └── sendMentionNotification()   # @mention notifications
├── cache.ts                        # 🗄️ In-memory TTL caching
│   ├── CommunicationCache class    # Singleton cache manager
│   ├── getChannel() / setChannel() # Channel caching
│   ├── getMessages() / setMessages()# Message list caching
│   └── invalidate()                # Cache invalidation
├── channel-helpers.ts              # Channel creation and member management utilities
├── channel-sync-manager.ts         # Auto-sync users to department/project channels
└── utils.ts                        # Message transformation and enrichment utilities
```

**Phase 1 Infrastructure Usage in Routes:**

```typescript
// Example: Using centralized services in route handlers
import { channelOps, messageOps } from '@/lib/communication/operations'
import { broadcastNewMessage, sendMentionNotification } from '@/lib/communication/broadcast'

// Database operation via channelOps
const channel = await channelOps.getById(channelId, { includeMembers: true })
const memberRole = await channelOps.getMemberRole(channelId, userId)

// Broadcasting via unified broadcast.ts
await broadcastNewMessage(channelId, messageWithSender)
await sendMentionNotification(mentionedUserId, notificationData)
```

### Library Files (`lib/`)

```
lib/
├── communication/                  # Communication-specific utilities (see above)
├── prisma.ts                       # Prisma client with PG driver adapter
├── realtime-manager.ts             # Supabase real-time management singleton
├── supabase.ts                     # Supabase client configuration
├── mongodb.ts                      # MongoDB connection and utilities
├── db-utils.ts                     # Database operation helpers
└── logger.ts                       # Logging utilities
```

**Prisma Configuration (v7 with Driver Adapter):**

```typescript
// lib/prisma.ts
import { PrismaClient } from '.prisma/client'
import { Pool } from 'pg'
import { PrismaPg } from '@prisma/adapter-pg'

const connectionString = process.env.DATABASE_URL 
const pool = new Pool({ connectionString })
const adapter = new PrismaPg(pool)

export const prisma = new PrismaClient({
  adapter,
  log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
})
```

### Database Schema (`prisma/`)

```
prisma/
├── schema.prisma                  # Complete database schema
└── migrations/                    # Database migration files
    └── YYYYMMDDHHMMSS_*.sql       # Migration scripts
```

**Schema Organization:**
- **channels**: Channel metadata and settings
- **channel_members**: Membership with roles and permissions
- **messages**: Messages with denormalized sender data
- **reactions**: Emoji reactions on messages
- **read_receipts**: Message read status tracking
- **attachments**: File attachment metadata

### Hooks (`hooks/`)

```
hooks/
├── use-communications.ts          # Main communication hook (channels, messages, real-time)
├── use-chat-attachments.ts        # File upload/download functionality
└── use-voice-recorder.ts          # Voice message recording
```

**Hooks Purpose:**
- **useCommunications**: Central hook managing all communication state and actions
- **useChatAttachments**: AWS S3 integration for file operations
- **useVoiceRecorder**: Web Audio API for voice message recording

### Redux Store (`store/slices/`)

```
store/
├── slices/
│   └── communicationSlice.ts      # Redux slice for communication state
└── index.ts                       # Store configuration
```

**State Management:**
- Centralized state for channels, messages, presence, and UI state
- Optimistic updates for instant UI feedback
- Real-time state synchronization

### Components (`components/communication/`)

```
components/
└── communication/
    ├── chat-window.tsx             # Main chat interface container
    ├── message-list.tsx            # Virtualized message list with reactions
    ├── message-input.tsx           # Message input with rich editor
    ├── rich-message-editor.tsx     # TipTap-based rich text editor
    ├── channel-list.tsx            # Channel sidebar with filtering
    ├── channel-settings-modal.tsx  # Channel configuration modal
    ├── create-channel-modal.tsx    # New channel creation modal
    ├── context-panel.tsx           # Channel info, members, files panel
    ├── resizable-sidebar.tsx       # Adjustable sidebar component
    ├── communication-sidebar.tsx   # Main sidebar container
    ├── user-directory.tsx          # User list for DM creation
    ├── online-indicator.tsx        # Online user status display
    ├── typing-indicator.tsx        # Typing status animation
    ├── emoji-picker.tsx            # Emoji selection interface
    ├── reaction-picker.tsx         # Quick reaction bar
    ├── mention-picker.tsx          # @mention autocomplete
    ├── voice-recorder.tsx          # Voice message recording UI
    ├── attachment-preview.tsx      # File attachment preview
    ├── audit-log-view.tsx          # Message modification history
    ├── trash-view.tsx              # Soft-deleted messages management
    ├── message-notification.tsx    # Notification center
    └── connection-status.tsx       # Real-time connection health
```

**Component Categories:**
- **Core Chat**: Chat window, message list, input components
- **Channel Management**: Channel list, creation, settings modals
- **User Interface**: Sidebar, context panel, online indicators
- **Interactive Elements**: Emoji picker, mention picker, voice recorder
- **Utility Components**: Connection status, notifications, audit logs

### Types (`types/`)

```
types/
├── communication.ts               # Core communication interfaces
└── index.ts                       # Type exports
```

**Type Definitions:**
- **ICommunication**: Message interface with reactions and attachments
- **IChannel**: Channel data structure with members and settings
- **IChannelMember**: Channel membership with roles
- **IAttachment**: File attachment metadata
- **IReaction**: Emoji reaction data
- **ITypingIndicator**: Typing status information

### Configuration Files

```
├── next.config.mjs                # Next.js configuration
├── tailwind.config.js             # Tailwind CSS configuration
├── tsconfig.json                  # TypeScript configuration
├── prisma.config.ts               # Prisma configuration
├── components.json                # shadcn/ui configuration
└── postcss.config.js              # PostCSS configuration
```

## Performance Optimizations

### Message Loading Strategy

- **Pagination**: Load messages in chunks (50 at a time) to reduce initial load
- **Virtual Scrolling**: Only render visible messages using `react-window`
- **Infinite Scroll**: Load older messages on demand with intersection observer
- **Optimistic Updates**: Instant UI feedback for user actions
- **Debounced Typing**: Prevent excessive typing indicator broadcasts (2s throttle)

### Real-time Optimizations

- **Channel-specific Subscriptions**: Only subscribe to active channels
- **Broadcast Filtering**: Don't receive own broadcasts (`self: false`)
- **Typing Throttling**: Send typing indicators max every 2 seconds
- **Presence Batching**: Batch presence updates to reduce network calls
- **Connection Pooling**: Reuse WebSocket connections

### Database Optimizations

- **Denormalized Sender Data**: No MongoDB joins for message display
- **Indexed Queries**: Optimized indexes on frequently queried fields
- **Connection Pooling**: Reuse database connections
- **Query Caching**: Cache frequently accessed data (channels, users)
- **Background Sync**: Async operations for non-critical updates

## Security Considerations

### Authentication & Authorization

- **Session Validation**: All API routes require valid NextAuth sessions
- **Permission Checks**: Module and action-specific permissions
- **Rate Limiting**: Prevent API abuse with configurable limits
- **Input Sanitization**: All user inputs are sanitized and validated
- **SQL Injection Prevention**: Parameterized queries with Prisma

### Data Protection

- **Audit Logging**: All message modifications are logged with actor info
- **Soft Deletes**: Messages are soft-deleted with restore capability
- **File Security**: S3 presigned URLs with expiration
- **Access Control**: Channel membership controls message access
- **Encryption**: Sensitive data encrypted at rest and in transit

### Real-time Security

- **Channel Isolation**: Users only receive messages from joined channels
- **Broadcast Validation**: Server-side validation of broadcast payloads
- **Rate Limiting**: Real-time events are rate-limited per user
- **Connection Limits**: Maximum concurrent connections per user

## Usage Examples

### Basic Message Sending

```typescript
import { useCommunications } from '@/hooks/use-communications'

function ChatComponent() {
  const { sendMessage, selectedChannel } = useCommunications()

  const handleSend = async (content: string) => {
    await sendMessage({
      channel_id: selectedChannel.id,
      content: content,
      mongo_mentioned_user_ids: extractMentions(content)
    })
  }

  return (
    <MessageInput onSend={handleSend} />
  )
}
```

### Real-time Channel Subscription

```typescript
import { getRealtimeManager } from '@/lib/realtime-manager'

const realtimeManager = getRealtimeManager({
  onNewMessage: (message) => {
    console.log('New message:', message)
    // Update UI
  },
  onUserOnline: (userId) => {
    console.log('User came online:', userId)
    // Update online status
  }
})

// Subscribe to channel
realtimeManager.subscribeToChannel(channelId, {
  onNewMessage: handleNewMessage,
  onTypingStart: handleTypingStart,
  onPresenceChange: handlePresenceChange
})
```

### File Upload with Progress

```typescript
import { useChatAttachments } from '@/hooks/use-chat-attachments'

function FileUploadComponent() {
  const { uploadAttachments, uploadProgress, isUploading } = useChatAttachments()

  const handleFileUpload = async (files: File[]) => {
    const attachments = await uploadAttachments(files, {
      channelId: selectedChannel.id,
      messageId: message.id,
      onProgress: (progress) => {
        console.log(`Upload progress: ${progress}%`)
      }
    })

    console.log('Uploaded attachments:', attachments)
  }

  return (
    <input
      type="file"
      multiple
      onChange={(e) => handleFileUpload(Array.from(e.target.files))}
      disabled={isUploading}
    />
  )
}
```

## Future Enhancements

### Completed in v7 ✅
- ✅ **Route Consolidation**: Reduced from 20+ routes to 9 consolidated routes
- ✅ **Centralized Services**: operations.ts, broadcast.ts, cache.ts
- ✅ **In-Memory Caching**: TTL-based caching for channels and messages
- ✅ **Prisma v7 Upgrade**: Driver adapters for improved connection pooling
- ✅ **Code Reduction**: 40% reduction in codebase size

### Completed in v8 ✅ (Enterprise Ready)
- ✅ **Enterprise Logging**: Replaced all console.* with communicationLogger
- ✅ **Error Handling**: Standardized logger + toast pattern across all components
- ✅ **Toast Notifications**: User-friendly feedback for all operations
- ✅ **Database Indexes**: GIN indexes for arrays, composite indexes for queries
- ✅ **Mute Toggle**: Channel mute/unmute with real-time sync
- ✅ **Last Message Display**: Preview in channel lists
- ✅ **Pin Sync**: Unified pinning between user directory and channel list
- ✅ **TypeScript Clean**: Zero compilation errors

### Performance Improvements (Phase 3 - Planned)
- **Hook Optimization**: Optimize useCallback dependencies in use-communications.ts
- **Cache Warming**: Pre-fetch next page of messages on channel selection
- **Memoization**: Improve memoization patterns for expensive computations

### Advanced Features (Planned)
- **End-to-end Encryption**: Message encryption for sensitive communications
- **Message Scheduling**: Send messages at specific times
- **Advanced Search**: Full-text search with filters and operators
- **Integration APIs**: Connect with external messaging platforms
- **Analytics Dashboard**: Communication metrics and insights
- **Mobile App**: Native mobile application support

### Performance Improvements (Planned)
- **Message Compression**: Reduce bandwidth for large message histories
- **Offline Support**: Queue messages when offline
- **Push Notifications**: Native push notifications for mobile
- **Voice/Video Calls**: Real-time voice and video communication
- **Screen Sharing**: Share screens during calls

### Scalability Enhancements (Planned)
- **Message Archiving**: Archive old messages to separate storage
- **Shard Management**: Database sharding for large deployments
- **CDN Integration**: Global CDN for file attachments
- **Load Balancing**: Distribute load across multiple servers

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| **v8** | **January 5, 2026** | **Enterprise-grade logging, error handling standardization, toast notifications, Prisma GIN indexes, mute toggle, last message display** |
| v7 | January 2026 | Route consolidation, centralized services, Prisma v7, 40% code reduction |
| v6 | December 2025 | Trash management, audit logging, advanced channel settings |
| v5 | November 2025 | Voice messages, file attachments, S3 integration |
| v4 | October 2025 | Real-time presence, typing indicators, reactions |
| v3 | September 2025 | Channel types, department/project integration |
| v2 | August 2025 | Basic messaging, DM support |
| v1 | July 2025 | Initial implementation |

### v8 Detailed Changelog

#### Enterprise Logging System
- Replaced all `console.log/error/warn` with `communicationLogger`
- Added proper log levels (info, warn, error, debug)
- Integrated with centralized logging infrastructure

**Files Updated:**
- `lib/communication/utils.ts` - 4 console.error → logger.error
- `lib/communication/channel-sync-manager.ts` - 4 console calls → logger
- `app/api/communication/messages/audit-logs/route.ts` - logger integration
- All 12 component files with proper logger imports

#### Error Handling Standardization
- All error handlers now use consistent pattern: `logger.error()` + `toast()`
- User-friendly error messages via toast notifications
- Proper error logging for debugging

**Components with Toast Notifications:**
- `whatsapp-attachment-grid.tsx` - Download failure toast
- `attachment-preview.tsx` - Download failure toast
- `attachment-gallery.tsx` - Gallery load failure toast
- `connection-status.tsx` - Reconnect failure logging
- All channel management components

#### Database Optimizations
- Added GIN index for `mongo_mentioned_user_ids` (fast @mention queries)
- Added composite indexes for attachments, reactions, read_receipts
- Optimized query patterns for channel listing

#### New Features
- **Mute Toggle**: Mute/unmute channels with real-time sync
- **Last Message Display**: Show last message preview in channel list
- **Pin Sync**: User pins synced between directory and channel list

---

---

## Enterprise Standards Compliance

### Logging Standards

```typescript
// Standard logger import pattern
import { communicationLogger as logger } from '@/lib/logger'

// Usage patterns
logger.info('Operation completed successfully')
logger.warn('Potential issue detected')
logger.error('Operation failed:', error)
logger.debug('Debug information for development')
```

### Error Handling Pattern

```typescript
// Standard error handling in components
const handleOperation = async () => {
  try {
    await apiCall()
    toast({
      title: "Success",
      description: "Operation completed successfully"
    })
  } catch (error) {
    logger.error('Operation failed:', error)
    toast({
      title: "Error",
      description: "Failed to complete operation. Please try again.",
      variant: "destructive"
    })
  }
}
```

### Files Following Enterprise Standards

| Category | Files | Pattern Applied |
|----------|-------|----------------|
| **Components** | 12 files | Logger + Toast |
| **Lib Files** | 3 files | Logger only |
| **API Routes** | 9 routes | Logger + Error responses |
| **Hooks** | 1 file | Logger for debug |

### Quality Checklist

- ✅ No `console.log` statements in production code
- ✅ All errors logged with proper context
- ✅ All user-facing errors show toast notifications
- ✅ TypeScript compilation clean (no errors)
- ✅ Consistent import patterns across files
- ✅ Proper error boundaries implemented
- ✅ Loading states for all async operations

---

This comprehensive documentation covers the complete Communication Module implementation with MongoDB as the primary database and Supabase for real-time communication features. The v8 release brings enterprise-grade logging, standardized error handling, and production-ready code quality. The module is now ready for long-term maintainability and scalability.