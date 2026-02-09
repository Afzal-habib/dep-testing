# Communication Module Optimization Plan

## Executive Summary

This document outlines a comprehensive phased approach to optimize the Communication Module of the Digi Era Pro CRM application. The optimization aims to:

1. **Consolidate Backend Routes**: Reduce 20+ route files to a centralized, generic API structure
2. **Follow App Patterns**: Align with the generic CRUD patterns documented in `COMPLETE-CRUD-IMPLEMENTATION-FINAL-VERSIONE.md`
3. **Maintain Full Functionality**: Ensure 100% feature parity with current implementation
4. **Preserve Real-time Capabilities**: Keep all Supabase real-time features working identically
5. **Enterprise-grade Optimization**: Follow WhatsApp-level architecture best practices

---

## ⚠️ Pre-Implementation Fixes Required

Before starting the optimization, these inconsistencies in the current codebase MUST be fixed:

### 1. Environment Variable Inconsistency

**Issue**: Some API routes use `SUPABASE_SECRET_KEY`, others use `SUPABASE_SERVICE_ROLE_KEY`.

| File | Current Usage | Should Be |
|------|---------------|-----------|
| `messages/route.ts` | `SUPABASE_SECRET_KEY` | `SUPABASE_SERVICE_ROLE_KEY` |
| `messages/with-files/route.ts` | `SUPABASE_SECRET_KEY` | `SUPABASE_SERVICE_ROLE_KEY` |
| `read-receipts/route.ts` | `SUPABASE_SECRET_KEY` | `SUPABASE_SERVICE_ROLE_KEY` |
| `attachments/route.ts` | `SUPABASE_SECRET_KEY` | `SUPABASE_SERVICE_ROLE_KEY` |
| `reactions/route.ts` | `SUPABASE_SERVICE_ROLE_KEY` | ✅ Correct |
| `messages/restore/route.ts` | `SUPABASE_SERVICE_ROLE_KEY` | ✅ Correct |
| `messages/[messageId]/route.ts` | `SUPABASE_SERVICE_ROLE_KEY` | ✅ Correct |

**Action**: Standardize to `SUPABASE_SERVICE_ROLE_KEY` (the JWT token for server-side admin access). The `SUPABASE_SECRET_KEY` is a different format and may cause issues.

### 2. Existing Validation Schemas

**Status**: `lib/validations/channel.ts` already exists with comprehensive schemas.

**Decision**: 
- ✅ Keep existing `lib/validations/channel.ts` 
- ✅ Add missing schemas (audit logs, trash queries) to it
- ❌ Do NOT create separate `lib/validations/communication.ts` - consolidate into existing file

### 3. Missing Broadcast Events in Plan

The following broadcast events exist in `realtime-manager.ts` but were not documented in original plan:

| Event | Purpose | Must Preserve |
|-------|---------|---------------|
| `new_channel` | Notify user of new channel they were added to | ✅ Yes |
| `user_pin_update` | Notify user when their pin status changes | ✅ Yes |
| `new_message` (on notification channel) | DM/mention notification to specific user | ✅ Yes |

---

## Current State Analysis

### Current Backend Structure (20+ Route Files)
```
app/api/communication/
├── channels/
│   ├── route.ts                    # GET: List channels, POST: Create
│   └── [channelId]/
│       ├── route.ts                # GET/PUT/DELETE: Channel CRUD
│       ├── archive/route.ts        # POST: Archive/unarchive
│       ├── leave/route.ts          # POST: Leave channel
│       ├── pin/route.ts            # POST/GET: Pin status
│       ├── members/route.ts        # GET/POST/PUT/DELETE: Members
│       └── settings/route.ts       # GET/PUT: Settings
├── messages/
│   ├── route.ts                    # GET: List, POST: Send
│   ├── [messageId]/route.ts        # PUT/DELETE: Edit/delete
│   ├── audit-logs/route.ts         # GET: Audit logs
│   ├── restore/route.ts            # POST: Restore from trash
│   ├── search/route.ts             # GET: Search messages
│   ├── trash/route.ts              # GET: List trashed
│   └── with-files/route.ts         # POST: Send with attachments
├── reactions/route.ts              # POST/DELETE/GET: Reactions
├── read-receipts/route.ts          # POST/GET: Read receipts
├── attachments/
│   ├── route.ts                    # POST/GET: Upload/list
│   └── download/route.ts           # GET: Download URL
├── members/route.ts                # GET/POST/DELETE: Members
└── users/[userId]/pin/route.ts     # POST/GET: Pin user
```

### Current Issues Identified

1. **Route Proliferation**: 20+ separate route files with duplicated code
2. **Inconsistent Patterns**: Not following the generic CRUD approach used in Departments
3. **Duplicate Helper Functions**: Same helper functions repeated across files
4. **No Centralized Validation**: Validation schemas scattered or inline
5. **Broadcasting Logic Duplicated**: Supabase broadcast code repeated in multiple routes
6. **Missing Caching Strategy**: No consistent caching like `executeGenericDbQuery`
7. **Error Handling Inconsistency**: Different error response formats across routes

### What's Working Well (Must Preserve)

1. ✅ Real-time messaging via Supabase broadcasts
2. ✅ Presence tracking via global_presence channel
3. ✅ Typing indicators with throttling
4. ✅ Denormalized sender data for performance
5. ✅ Rich text editor with TipTap
6. ✅ File attachments with S3 presigned URLs
7. ✅ Voice messages recording/playback
8. ✅ Emoji reactions with real-time updates
9. ✅ Read receipts tracking
10. ✅ Message editing with audit logs
11. ✅ Trash/restore functionality
12. ✅ Channel pinning/archiving
13. ✅ Multiple channel types (DM, group, department, project, client-support)
14. ✅ @mention system with notifications

---

## 🔑 Critical Architecture Clarification

### Client-Side vs Server-Side Real-time Architecture

**IMPORTANT**: The communication module uses a two-layer real-time architecture. Understanding this distinction is critical before implementation.

#### Layer 1: CLIENT-SIDE - `lib/realtime-manager.ts` (EXISTING - DO NOT MODIFY)

**Purpose**: Handles **receiving** broadcasts, presence tracking, and typing indicators in the browser.

**Key Characteristics**:
- Uses `supabase` from `@/lib/supabase` (anon key - client-side only)
- Singleton pattern via `getRealtimeManager()`
- Runs in the browser (React components)
- **Responsibilities**:
  - Subscribe to channel broadcasts (`subscribeToChannel`)
  - Subscribe to user notifications (`subscribeToNotifications`)
  - Track presence (`initializePresence`, `updatePresence`)
  - Send/receive typing indicators (`startTyping`, `stopTyping`)
  - Handle connection recovery and reconnection
  - Dispatch events to React Query cache via handlers

**Example Usage in Components**:
```typescript
// components/communication/message-list.tsx
const realtimeManager = getRealtimeManager()
realtimeManager.subscribeToChannel(channelId)
realtimeManager.setEventHandler('onNewMessage', (msg) => {
  queryClient.setQueryData(['messages', channelId], ...)
})
```

#### Layer 2: SERVER-SIDE - `lib/communication/broadcast.ts` (NEW - TO BE CREATED)

**Purpose**: Handles **sending** broadcasts from API routes using the admin client.

**Key Characteristics**:
- Uses `createClient` with `SUPABASE_SERVICE_ROLE_KEY` (admin key - server-side only)
- Runs in Node.js API routes only
- **Responsibilities**:
  - Broadcast new messages to channel subscribers
  - Broadcast message updates/deletes
  - Broadcast reactions, read receipts
  - Send user-specific notifications (@mentions)

**Example Usage in API Routes**:
```typescript
// app/api/communication/messages/route.ts
import { broadcastToChannel } from '@/lib/communication/broadcast'

// After creating message in DB:
await broadcastToChannel({
  channelId: message.channel_id,
  event: 'new_message',
  payload: messageWithSender
})
```

#### Architecture Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ARCHITECTURE FLOW                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  BROWSER (Client-Side)                    SERVER (API Routes)               │
│  ─────────────────────                    ──────────────────                │
│                                                                              │
│  ┌─────────────────────┐                  ┌─────────────────────┐           │
│  │   React Component   │ ──HTTP POST──▶   │   POST /messages    │           │
│  │   (MessageInput)    │                  │   route.ts          │           │
│  └─────────────────────┘                  └──────────┬──────────┘           │
│                                                      │                       │
│                                                      ▼                       │
│                                           ┌─────────────────────┐           │
│                                           │   prisma.messages   │           │
│                                           │   .create(...)      │           │
│                                           └──────────┬──────────┘           │
│                                                      │                       │
│                                                      ▼                       │
│                                           ┌─────────────────────┐           │
│                                           │  broadcast.ts       │           │
│                                           │  broadcastToChannel │           │
│                                           │  (SERVICE_ROLE_KEY) │           │
│                                           └──────────┬──────────┘           │
│                                                      │                       │
│               ┌──────────────────────────────────────┘                       │
│               │ Supabase Realtime                                           │
│               ▼                                                              │
│  ┌─────────────────────┐                                                    │
│  │  realtime-manager   │ ◀── Receives broadcast via subscription           │
│  │  (ANON_KEY)         │                                                    │
│  └──────────┬──────────┘                                                    │
│             │                                                                │
│             ▼                                                                │
│  ┌─────────────────────┐                                                    │
│  │  onNewMessage       │ ──▶ Updates React Query cache                      │
│  │  event handler      │ ──▶ UI re-renders with new message                 │
│  └─────────────────────┘                                                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Why Two Separate Services?

| Aspect | CLIENT (realtime-manager.ts) | SERVER (broadcast.ts) |
|--------|------------------------------|----------------------|
| **Environment** | Browser (React) | Node.js (API Routes) |
| **Supabase Key** | `ANON_KEY` (public) | `SERVICE_ROLE_KEY` (secret) |
| **Purpose** | Receive broadcasts, presence | Send broadcasts |
| **Security** | User authenticated via session | Admin privileges |
| **Lifecycle** | Per-user singleton | Per-request |

> ⚠️ **NEVER import `realtime-manager.ts` in API routes** - it uses the client-side Supabase client.
> ⚠️ **NEVER import `broadcast.ts` in React components** - it would expose the service role key.

---

## Middleware Architecture: `genericApiRoutesMiddleware`

### Overview

The `genericApiRoutesMiddleware` from `lib/middleware/route-middleware.ts` is the standardized middleware for all API routes. It provides:

1. **Rate Limiting** - Configurable by action type
2. **Authentication** - Via NextAuth session validation
3. **Authorization** - Permission checking against resource/action
4. **User Enrichment** - Returns full user context and filter functions

### Function Signature

```typescript
export async function genericApiRoutesMiddleware(
  request: NextRequest,
  resource: string,     // e.g., 'communication', 'departments', 'users'
  action: string,       // e.g., 'read', 'create', 'update', 'delete'
  options?: RouteMiddlewareOptions
): Promise<RouteMiddlewareResult>
```

### Rate Limit Types (Auto-detected)

| Action | Rate Limit Type | Limit |
|--------|----------------|-------|
| `read` | `api` | Higher limit |
| `create`, `update`, `delete`, `manage` | `sensitive` | Lower limit |
| `login`, `register`, `logout` | `auth` | Strict limit |

### Return Type

```typescript
interface RouteMiddlewareResult {
  session: any            // NextAuth session object
  user: any               // Full user document from MongoDB (with role, department, etc.)
  userEmail: string       // Convenience field for logging
  isSuperAdmin: boolean   // Whether user has superAdmin flag
  filterContext: {        // Context for permission-based filtering
    userId: string
    userEmail: string
    userDepartment?: string
    userRole: any
    subordinateIds: string[]
    isSuperAdmin: boolean
  }
  applyFilters: (baseQuery: any) => Promise<any>  // Function to apply permission filters
}
```

### Usage Pattern in API Routes

```typescript
// app/api/communication/channels/route.ts
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'

export async function GET(request: NextRequest) {
  try {
    // 1. Run middleware - handles auth, rate limiting, permissions
    const { user, userEmail, isSuperAdmin, applyFilters } = 
      await genericApiRoutesMiddleware(request, 'communication', 'read')

    // 2. Build base query
    let query = { is_archived: false }

    // 3. Apply permission-based filters (skipped for superAdmin)
    query = await applyFilters(query)

    // 4. Execute query with user context
    const channels = await getChannelsForUser(user._id, query)

    return NextResponse.json({ data: channels })
  } catch (error) {
    return handleAPIError(error)
  }
}

export async function POST(request: NextRequest) {
  try {
    // For create/update/delete - uses 'sensitive' rate limiting
    const { user, userEmail } = 
      await genericApiRoutesMiddleware(request, 'communication', 'create')

    // ... create channel logic
  } catch (error) {
    return handleAPIError(error)
  }
}
```

### Important Behavior

1. **Caching**: Read operations are cached for 30 seconds (per user)
2. **Error Handling**: Throws structured errors that should be caught with `handleAPIError`
3. **Rate Limiting**: Automatically applied based on action type
4. **SuperAdmin Bypass**: `isSuperAdmin` users skip permission filters

---

## Architecture Goals

### Target Backend Structure (Optimized)
```
app/api/communication/
├── route.ts                        # GET: Stats/Overview (optional)
├── channels/
│   ├── route.ts                    # GET: List, POST: Create
│   └── [channelId]/
│       └── route.ts                # GET/PUT/DELETE + actions via query params
├── messages/
│   ├── route.ts                    # GET: List, POST: Send (handles files too)
│   └── [messageId]/
│       └── route.ts                # GET/PUT/DELETE + actions
├── reactions/
│   └── route.ts                    # POST: Toggle, GET: List
└── read-receipts/
    └── route.ts                    # POST: Mark read, GET: List

lib/communication/
├── operations.ts                   # Unified database operations (like db-utils.ts)
├── broadcast.ts                    # Centralized Supabase broadcasting
├── helpers.ts                      # Consolidated helper functions
├── cache.ts                        # Enhanced caching strategy
├── channel-helpers.ts              # Channel-specific logic (existing)
├── channel-sync-manager.ts         # Auto-sync logic (existing)
└── utils.ts                        # Utilities (existing)

lib/validations/
└── communication.ts                # All communication validation schemas
```

### Key Design Principles

1. **Generic Operations**: Use action-based routing (e.g., `?action=archive`, `?action=pin`)
2. **Centralized Broadcasting**: Single broadcast service for all real-time events
3. **Unified Error Handling**: Consistent error responses across all routes
4. **Smart Caching**: Implement caching for frequently accessed data
5. **Type Safety**: Full TypeScript coverage with Prisma types
6. **Audit Logging**: Centralized audit for all modifications

---

## Phase 1: Foundation Layer (Prerequisites)

### 1.1 Schema Review (No Changes Expected)

Current Prisma schema is well-designed. Verify indexes are optimal:

```prisma
// Existing indexes to verify are present:
@@index([channel_id, is_trashed, created_at(sort: Desc)])  // messages
@@index([mongo_sender_id, is_trashed])                     // messages
@@index([channel_id, mongo_member_id])                     // channel_members
@@index([mongo_member_id, is_pinned])                      // channel_members
@@unique([message_id, mongo_user_id, emoji])               // reactions
@@unique([message_id, mongo_user_id])                      // read_receipts
```

**Action**: Run `npx prisma db push` to ensure schema is current. No schema changes needed.

### 1.2 Create Centralized Broadcast Service

> 📌 **Architecture Note**: This `broadcast.ts` is a **SERVER-SIDE** service that runs in API routes only. It is **NOT** a replacement for `lib/realtime-manager.ts` (which is CLIENT-SIDE). 
> 
> - **`broadcast.ts`** → SENDS broadcasts from API routes using `SERVICE_ROLE_KEY`
> - **`realtime-manager.ts`** → RECEIVES broadcasts in browser using `ANON_KEY`
> 
> See "Critical Architecture Clarification" section above for the full explanation.

**File**: `lib/communication/broadcast.ts`

```typescript
/**
 * Centralized Supabase Broadcast Service
 * Handles all real-time event broadcasting for the communication module
 */
import { createClient, SupabaseClient } from '@supabase/supabase-js'
import { apiLogger as logger } from '@/lib/logger'

// Singleton admin client
let supabaseAdminClient: SupabaseClient | null = null

function getSupabaseAdmin(): SupabaseClient {
  if (!supabaseAdminClient) {
    supabaseAdminClient = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.SUPABASE_SERVICE_ROLE_KEY!,
      {
        realtime: {
          params: { eventsPerSecond: 100 }
        }
      }
    )
  }
  return supabaseAdminClient
}

// Event types for type safety
export type BroadcastEvent = 
  // Message events
  | 'new_message'
  | 'message_update'
  | 'message_delete'
  | 'message_trash'
  | 'message_restore'
  | 'message_hidden'
  // Reaction events
  | 'reaction_added'
  | 'reaction_removed'
  // Read receipt events
  | 'message_read'
  // Typing events (NOTE: These are CLIENT-SIDE via realtime-manager.ts, NOT server broadcast)
  // | 'typing_start'  // DO NOT include - handled by client
  // | 'typing_stop'   // DO NOT include - handled by client
  // Channel events
  | 'channel_updated'
  | 'channel_archived'
  | 'new_channel'           // Broadcast to user when added to a channel
  | 'user_pin_update'       // Broadcast to user when channel pin status changes
  // Member events
  | 'member_joined'
  | 'member_left'
  | 'member_updated'
  | 'member_role_changed'

// Notification-specific events (sent to user notification channel)
export type NotificationEvent = 
  | 'mention_notification'
  | 'dm_notification'
  | 'new_message'           // For DM notifications

export interface BroadcastOptions {
  channelId: string
  event: BroadcastEvent
  payload: Record<string, unknown>
  timeout?: number
}

/**
 * Broadcast a message to a Supabase channel with proper connection handling
 */
export async function broadcastToChannel({
  channelId,
  event,
  payload,
  timeout = 5000
}: BroadcastOptions): Promise<boolean> {
  const supabase = getSupabaseAdmin()
  const channelName = `rt_${channelId}`

  return new Promise((resolve) => {
    const channel = supabase.channel(channelName, {
      config: { broadcast: { self: false, ack: true } }
    })

    let resolved = false
    const timeoutId = setTimeout(() => {
      if (!resolved) {
        resolved = true
        supabase.removeChannel(channel)
        logger.warn(`Broadcast to ${channelName}/${event} timed out`)
        resolve(false)
      }
    }, timeout)

    channel.subscribe(async (status) => {
      if (status === 'SUBSCRIBED') {
        try {
          const result = await channel.send({
            type: 'broadcast',
            event,
            payload
          })

          if (!resolved) {
            resolved = true
            clearTimeout(timeoutId)
            supabase.removeChannel(channel)
            resolve(result === 'ok')
          }
        } catch (error) {
          if (!resolved) {
            resolved = true
            clearTimeout(timeoutId)
            supabase.removeChannel(channel)
            logger.error(`Broadcast error to ${channelName}:`, error)
            resolve(false)
          }
        }
      } else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
        if (!resolved) {
          resolved = true
          clearTimeout(timeoutId)
          supabase.removeChannel(channel)
          resolve(false)
        }
      }
    })
  })
}

/**
 * Broadcast to user-specific notification channel
 */
export async function broadcastToUser(
  userId: string,
  event: 'mention_notification' | 'dm_notification',
  payload: Record<string, unknown>
): Promise<boolean> {
  const supabase = getSupabaseAdmin()
  const channelName = `notifications_${userId}`

  return new Promise((resolve) => {
    const channel = supabase.channel(channelName)

    channel.subscribe(async (status) => {
      if (status === 'SUBSCRIBED') {
        try {
          const result = await channel.send({
            type: 'broadcast',
            event,
            payload
          })
          supabase.removeChannel(channel)
          resolve(result === 'ok')
        } catch {
          supabase.removeChannel(channel)
          resolve(false)
        }
      }
    })
  })
}

/**
 * Batch broadcast to multiple channels (for group operations)
 */
export async function broadcastToMultipleChannels(
  broadcasts: BroadcastOptions[]
): Promise<Map<string, boolean>> {
  const results = new Map<string, boolean>()
  
  await Promise.all(
    broadcasts.map(async (broadcast) => {
      const success = await broadcastToChannel(broadcast)
      results.set(broadcast.channelId, success)
    })
  )

  return results
}
```

### 1.3 Create Unified Database Operations

**File**: `lib/communication/operations.ts`

```typescript
/**
 * Unified Communication Database Operations
 * Following the db-utils.ts pattern with caching support
 */
import { prisma } from '@/lib/prisma'
import { communicationCache } from './cache'

// Re-export existing operations for backward compatibility
export { channelOperations, messageOperations } from '@/lib/db-utils'

/**
 * Channel-related database operations
 */
export const channelOps = {
  /**
   * Get channel by ID with members
   */
  async getById(channelId: string, includeLast?: number) {
    const cacheKey = `channel:${channelId}`
    const cached = communicationCache.get(cacheKey)
    if (cached) return cached

    const channel = await prisma.channels.findUnique({
      where: { id: channelId },
      include: {
        channel_members: true,
        ...(includeLast && {
          messages: {
            where: { is_trashed: false },
            orderBy: { created_at: 'desc' },
            take: includeLast
          }
        })
      }
    })

    if (channel) {
      communicationCache.set(cacheKey, channel, 60000) // 1 min cache
    }
    return channel
  },

  /**
   * Get user's channels with unread counts
   */
  async getUserChannels(userId: string, filters?: {
    type?: string
    departmentId?: string
    projectId?: string
  }) {
    return prisma.channels.findMany({
      where: {
        channel_members: {
          some: { mongo_member_id: userId }
        },
        ...(filters?.type && { type: filters.type }),
        ...(filters?.departmentId && { mongo_department_id: filters.departmentId }),
        ...(filters?.projectId && { mongo_project_id: filters.projectId }),
      },
      include: {
        channel_members: true,
        messages: {
          where: { is_trashed: false },
          orderBy: { created_at: 'desc' },
          take: 1
        }
      },
      orderBy: { updated_at: 'desc' }
    })
  },

  /**
   * Check if user is member of channel
   */
  async isMember(channelId: string, userId: string): Promise<boolean> {
    const membership = await prisma.channel_members.findFirst({
      where: {
        channel_id: channelId,
        mongo_member_id: userId
      }
    })
    return !!membership
  },

  /**
   * Get member role in channel
   */
  async getMemberRole(channelId: string, userId: string): Promise<string | null> {
    const membership = await prisma.channel_members.findFirst({
      where: {
        channel_id: channelId,
        mongo_member_id: userId
      },
      select: { role: true }
    })
    return membership?.role ?? null
  },

  /**
   * Toggle channel pin status
   */
  async togglePin(channelId: string, userId: string, maxPins: number = 5) {
    const member = await prisma.channel_members.findFirst({
      where: { channel_id: channelId, mongo_member_id: userId }
    })

    if (!member) throw new Error('Not a member of this channel')

    if (member.is_pinned) {
      // Unpin
      return prisma.channel_members.update({
        where: { id: member.id },
        data: { is_pinned: false, pinned_at: null }
      })
    } else {
      // Check pin limit
      const pinnedCount = await prisma.channel_members.count({
        where: { mongo_member_id: userId, is_pinned: true }
      })

      if (pinnedCount >= maxPins) {
        throw new Error(`Maximum ${maxPins} pinned channels allowed`)
      }

      return prisma.channel_members.update({
        where: { id: member.id },
        data: { is_pinned: true, pinned_at: new Date() }
      })
    }
  },

  /**
   * Archive/unarchive channel
   */
  async toggleArchive(channelId: string, userId: string, action: 'archive' | 'unarchive') {
    communicationCache.invalidate(`channel:${channelId}`)
    
    return prisma.channels.update({
      where: { id: channelId },
      data: {
        is_archived: action === 'archive',
        archived_at: action === 'archive' ? new Date() : null,
        archived_by: action === 'archive' ? userId : null
      }
    })
  }
}

/**
 * Message-related database operations
 */
export const messageOps = {
  /**
   * Get messages for a channel with pagination
   */
  async getByChannel(
    channelId: string,
    options: { limit?: number; offset?: number; includeAttachments?: boolean } = {}
  ) {
    const { limit = 50, offset = 0, includeAttachments = true } = options

    return prisma.messages.findMany({
      where: {
        channel_id: channelId,
        is_trashed: false
      },
      orderBy: { created_at: 'desc' },
      take: limit,
      skip: offset,
      include: {
        ...(includeAttachments && { attachments: true }),
        reactions: true
      }
    })
  },

  /**
   * Create message with sender denormalization
   */
  async create(data: {
    channel_id: string
    mongo_sender_id: string
    content: string
    content_type?: string
    parent_message_id?: string
    mongo_mentioned_user_ids?: string[]
    sender_name: string
    sender_email: string
    sender_avatar?: string
    sender_role?: string
  }) {
    const message = await prisma.messages.create({
      data: {
        channel_id: data.channel_id,
        mongo_sender_id: data.mongo_sender_id,
        content: data.content,
        content_type: data.content_type ?? 'text',
        parent_message_id: data.parent_message_id,
        mongo_mentioned_user_ids: data.mongo_mentioned_user_ids ?? [],
        sender_name: data.sender_name,
        sender_email: data.sender_email,
        sender_avatar: data.sender_avatar,
        sender_role: data.sender_role ?? 'User'
      },
      include: { attachments: true }
    })

    // Update reply count if this is a reply
    if (data.parent_message_id) {
      await prisma.messages.update({
        where: { id: data.parent_message_id },
        data: { reply_count: { increment: 1 } }
      })
    }

    // Update channel's last_message_at
    await prisma.channels.update({
      where: { id: data.channel_id },
      data: { last_message_at: new Date(), updated_at: new Date() }
    })

    return message
  },

  /**
   * Search messages in channel
   */
  async search(channelId: string, query: string, options?: { limit?: number; offset?: number }) {
    const { limit = 20, offset = 0 } = options ?? {}

    return prisma.messages.findMany({
      where: {
        channel_id: channelId,
        is_trashed: false,
        content: { contains: query, mode: 'insensitive' }
      },
      orderBy: { created_at: 'desc' },
      take: limit,
      skip: offset,
      include: { attachments: true }
    })
  },

  /**
   * Move message to trash (soft delete)
   */
  async trash(messageId: string, userId: string, reason?: string) {
    return prisma.messages.update({
      where: { id: messageId },
      data: {
        is_trashed: true,
        trashed_at: new Date(),
        trashed_by: userId,
        trash_reason: reason
      }
    })
  },

  /**
   * Restore message from trash
   */
  async restore(messageId: string) {
    return prisma.messages.update({
      where: { id: messageId },
      data: {
        is_trashed: false,
        trashed_at: null,
        trashed_by: null,
        trash_reason: null
      }
    })
  },

  /**
   * Get trashed messages for user
   */
  async getTrashed(userId: string, options?: { channelId?: string; limit?: number; offset?: number }) {
    const { channelId, limit = 20, offset = 0 } = options ?? {}

    return prisma.messages.findMany({
      where: {
        is_trashed: true,
        trashed_by: userId,
        ...(channelId && { channel_id: channelId })
      },
      orderBy: { trashed_at: 'desc' },
      take: limit,
      skip: offset
    })
  }
}

/**
 * Reaction operations
 */
export const reactionOps = {
  /**
   * Toggle reaction (add if not exists, remove if exists)
   */
  async toggle(data: {
    messageId: string
    channelId: string
    userId: string
    userName: string
    emoji: string
  }) {
    const existing = await prisma.reactions.findFirst({
      where: {
        message_id: data.messageId,
        mongo_user_id: data.userId,
        emoji: data.emoji
      }
    })

    if (existing) {
      await prisma.reactions.delete({ where: { id: existing.id } })
      return { action: 'removed' as const, reaction: existing }
    } else {
      const reaction = await prisma.reactions.create({
        data: {
          message_id: data.messageId,
          channel_id: data.channelId,
          mongo_user_id: data.userId,
          user_name: data.userName,
          emoji: data.emoji
        }
      })
      return { action: 'added' as const, reaction }
    }
  },

  /**
   * Get reactions for a message
   */
  async getByMessage(messageId: string) {
    return prisma.reactions.findMany({
      where: { message_id: messageId },
      orderBy: { created_at: 'asc' }
    })
  }
}

/**
 * Read receipt operations
 */
export const readReceiptOps = {
  /**
   * Mark message as read
   */
  async mark(messageId: string, userId: string) {
    return prisma.read_receipts.upsert({
      where: {
        message_id_mongo_user_id: {
          message_id: messageId,
          mongo_user_id: userId
        }
      },
      create: {
        message_id: messageId,
        mongo_user_id: userId,
        read_at: new Date()
      },
      update: {
        read_at: new Date()
      }
    })
  },

  /**
   * Mark all messages in channel as read
   */
  async markAllInChannel(channelId: string, userId: string) {
    const unreadMessages = await prisma.messages.findMany({
      where: {
        channel_id: channelId,
        is_trashed: false,
        mongo_sender_id: { not: userId },
        read_receipts: {
          none: { mongo_user_id: userId }
        }
      },
      select: { id: true }
    })

    if (unreadMessages.length === 0) return { markedCount: 0 }

    await prisma.read_receipts.createMany({
      data: unreadMessages.map(msg => ({
        message_id: msg.id,
        mongo_user_id: userId
      })),
      skipDuplicates: true
    })

    return { markedCount: unreadMessages.length }
  },

  /**
   * Get read receipts for a message
   */
  async getByMessage(messageId: string) {
    return prisma.read_receipts.findMany({
      where: { message_id: messageId }
    })
  }
}

/**
 * Attachment operations
 */
export const attachmentOps = {
  /**
   * Create attachment record
   */
  async create(data: {
    messageId: string
    channelId: string
    uploaderId: string
    fileName: string
    fileUrl?: string
    s3Key?: string
    s3Bucket?: string
    fileSize?: number
    fileType?: string
  }) {
    return prisma.attachments.create({
      data: {
        message_id: data.messageId,
        channel_id: data.channelId,
        mongo_uploader_id: data.uploaderId,
        file_name: data.fileName,
        file_url: data.fileUrl,
        s3_key: data.s3Key,
        s3_bucket: data.s3Bucket,
        file_size: data.fileSize,
        file_type: data.fileType
      }
    })
  },

  /**
   * Get attachments for a channel
   */
  async getByChannel(channelId: string) {
    return prisma.attachments.findMany({
      where: { channel_id: channelId },
      orderBy: { created_at: 'desc' }
    })
  }
}

/**
 * Audit log operations
 */
export const auditOps = {
  /**
   * Create audit log entry
   */
  async log(data: {
    messageId: string
    channelId: string
    actorId: string
    actorName: string
    actorEmail: string
    action: 'created' | 'edited' | 'trashed' | 'restored' | 'permanently_deleted'
    previousContent?: string
    newContent?: string
    metadata?: Record<string, unknown>
  }) {
    return prisma.message_audit_logs.create({
      data: {
        message_id: data.messageId,
        channel_id: data.channelId,
        actor_id: data.actorId,
        actor_name: data.actorName,
        actor_email: data.actorEmail,
        action: data.action,
        previous_content: data.previousContent,
        new_content: data.newContent,
        metadata: data.metadata as any
      }
    })
  },

  /**
   * Get audit logs with filters
   */
  async get(filters: {
    channelId?: string
    messageId?: string
    actorId?: string
    action?: string
    startDate?: Date
    endDate?: Date
    limit?: number
    offset?: number
  }) {
    const { limit = 50, offset = 0, ...where } = filters

    return prisma.message_audit_logs.findMany({
      where: {
        ...(where.channelId && { channel_id: where.channelId }),
        ...(where.messageId && { message_id: where.messageId }),
        ...(where.actorId && { actor_id: where.actorId }),
        ...(where.action && { action: where.action }),
        ...(where.startDate || where.endDate) && {
          created_at: {
            ...(where.startDate && { gte: where.startDate }),
            ...(where.endDate && { lte: where.endDate })
          }
        }
      },
      orderBy: { created_at: 'desc' },
      take: limit,
      skip: offset
    })
  }
}
```

### 1.4 Enhanced Caching System

**File**: `lib/communication/cache.ts` (Update existing)

```typescript
/**
 * Enhanced Communication Cache with TTL and pattern invalidation
 */

interface CacheEntry<T> {
  data: T
  timestamp: number
  ttl: number
}

class CommunicationCache {
  private cache: Map<string, CacheEntry<unknown>> = new Map()
  private cleanupInterval: NodeJS.Timeout | null = null

  constructor() {
    // Run cleanup every 30 seconds
    if (typeof window === 'undefined') {
      this.cleanupInterval = setInterval(() => this.cleanup(), 30000)
    }
  }

  /**
   * Get cached value if not expired
   */
  get<T>(key: string): T | null {
    const entry = this.cache.get(key) as CacheEntry<T> | undefined
    if (!entry) return null

    if (Date.now() - entry.timestamp > entry.ttl) {
      this.cache.delete(key)
      return null
    }

    return entry.data
  }

  /**
   * Set value with TTL (default 60 seconds)
   */
  set<T>(key: string, data: T, ttl: number = 60000): void {
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl
    })
  }

  /**
   * Invalidate single key
   */
  delete(key: string): void {
    this.cache.delete(key)
  }

  /**
   * Invalidate by pattern (e.g., 'channel:*' invalidates all channel caches)
   */
  invalidate(pattern: string): void {
    const regex = new RegExp(pattern.replace('*', '.*'))
    for (const key of this.cache.keys()) {
      if (regex.test(key)) {
        this.cache.delete(key)
      }
    }
  }

  /**
   * Clear all cache
   */
  clear(): void {
    this.cache.clear()
  }

  /**
   * Remove expired entries
   */
  private cleanup(): void {
    const now = Date.now()
    for (const [key, entry] of this.cache.entries()) {
      if (now - entry.timestamp > entry.ttl) {
        this.cache.delete(key)
      }
    }
  }

  /**
   * Get cache stats (for debugging)
   */
  stats(): { size: number; keys: string[] } {
    return {
      size: this.cache.size,
      keys: Array.from(this.cache.keys())
    }
  }
}

export const communicationCache = new CommunicationCache()
```

### 1.5 Update Existing Validation Schemas

> ⚠️ **IMPORTANT**: The file `lib/validations/channel.ts` already exists with comprehensive schemas. 
> DO NOT create a new `lib/validations/communication.ts` file - instead, add missing schemas to the existing file.

**File**: `lib/validations/channel.ts` (UPDATE EXISTING - Add missing schemas)

**Schemas that already exist** (no changes needed):
- ✅ `createChannelSchema`
- ✅ `updateChannelSchema`
- ✅ `channelQuerySchema`
- ✅ `createMessageSchema`
- ✅ `updateMessageSchema`
- ✅ `messageQuerySchema`
- ✅ `addMemberSchema`
- ✅ `createReactionSchema`
- ✅ `markAsReadSchema`

**Schemas to ADD to existing file**:

```typescript
// ============================================
// ADD THESE TO lib/validations/channel.ts
// ============================================

// Trash query schema
export const trashQuerySchema = z.object({
  channelId: z.string().uuid().optional(),
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(20)
})

// Message action schema (for trash/restore/hide operations)
export const messageActionSchema = z.object({
  action: z.enum(['trash', 'restore', 'permanent_delete', 'hide_for_self']),
  reason: z.string().optional(),
})

// Channel action schema (for archive/pin/leave operations)
export const channelActionSchema = z.object({
  action: z.enum(['archive', 'unarchive', 'pin', 'unpin', 'leave']),
})

// Audit log query schema
export const auditLogQuerySchema = z.object({
  channel_id: z.string().uuid().optional(),
  message_id: z.string().uuid().optional(),
  action: z.enum(['created', 'edited', 'trashed', 'restored', 'permanently_deleted']).optional(),
  actor_id: z.string().optional(),
  start_date: z.string().datetime().optional(),
  end_date: z.string().datetime().optional(),
  limit: z.coerce.number().min(1).max(100).default(50),
  offset: z.coerce.number().min(0).default(0),
})

// Message search schema
export const messageSearchSchema = z.object({
  channel_id: z.string().uuid(),
  query: z.string().min(1).max(500),
  limit: z.coerce.number().min(1).max(100).default(20),
  offset: z.coerce.number().min(0).default(0),
})

// Mark read schema (supports bulk and single)
export const markReadBulkSchema = z.object({
  message_id: z.string().uuid().optional(),
  channel_id: z.string().uuid().optional(),
  mark_all: z.boolean().optional(),
}).refine(
  data => data.message_id || (data.mark_all && data.channel_id),
  { message: 'Either message_id or (mark_all with channel_id) is required' }
)

// Type exports for new schemas
export type TrashQueryParams = z.infer<typeof trashQuerySchema>
export type MessageActionData = z.infer<typeof messageActionSchema>
export type ChannelActionData = z.infer<typeof channelActionSchema>
export type AuditLogQueryParams = z.infer<typeof auditLogQuerySchema>
export type MessageSearchParams = z.infer<typeof messageSearchSchema>
export type MarkReadBulkData = z.infer<typeof markReadBulkSchema>
```

> 📝 **Note**: The constants `CHANNEL_CONSTANTS` already exist in `lib/validations/channel.ts`. 
> Update them if needed rather than creating new ones.

---

## Phase 2: Consolidated API Routes

### 2.1 Channels API (Consolidated)

**File**: `app/api/communication/channels/route.ts` (Consolidated)

This route handles:
- GET: List user's channels
- POST: Create new channel

**File**: `app/api/communication/channels/[channelId]/route.ts` (Consolidated)

This single file handles ALL channel operations via HTTP method + optional action query param:
- GET: Channel details
- PUT: Update channel / Execute action (archive, unarchive)
- DELETE: Delete channel
- POST: Execute action (pin, leave, add members)

```typescript
// Example consolidated approach
export async function PUT(request: NextRequest, { params }) {
  const { channelId } = await params
  const searchParams = request.nextUrl.searchParams
  const action = searchParams.get('action')

  // Handle action-based operations
  if (action === 'archive') {
    return handleArchive(channelId, session.user.id, true)
  }
  if (action === 'unarchive') {
    return handleArchive(channelId, session.user.id, false)
  }

  // Handle regular update
  const body = await request.json()
  return handleUpdate(channelId, body)
}

export async function POST(request: NextRequest, { params }) {
  const { channelId } = await params
  const searchParams = request.nextUrl.searchParams
  const action = searchParams.get('action')

  if (action === 'pin') {
    return handlePin(channelId, session.user.id)
  }
  if (action === 'leave') {
    return handleLeave(channelId, session.user.id)
  }
  if (action === 'members') {
    return handleAddMembers(channelId, body)
  }
}
```

### 2.2 Messages API (Consolidated)

**File**: `app/api/communication/messages/route.ts`

Handles:
- GET: List messages with pagination (combines search via query param)
- POST: Send message (handles text, files, voice in one endpoint)

**File**: `app/api/communication/messages/[messageId]/route.ts`

Handles ALL message operations:
- GET: Get single message
- PUT: Edit message
- DELETE: Trash/permanent delete message
- POST: Execute action (restore, hide for self)

### 2.3 Route Consolidation Map

| Current Route | Consolidated Route | Action/Method |
|---------------|-------------------|---------------|
| `channels/route.ts` | `channels/route.ts` | GET, POST |
| `channels/[channelId]/route.ts` | `channels/[channelId]/route.ts` | GET, PUT, DELETE |
| `channels/[channelId]/archive/route.ts` | `channels/[channelId]/route.ts` | PUT?action=archive |
| `channels/[channelId]/leave/route.ts` | `channels/[channelId]/route.ts` | POST?action=leave |
| `channels/[channelId]/pin/route.ts` | `channels/[channelId]/route.ts` | POST?action=pin |
| `channels/[channelId]/members/route.ts` | `channels/[channelId]/route.ts` | POST?action=members / DELETE?action=remove-member |
| `channels/[channelId]/settings/route.ts` | `channels/[channelId]/route.ts` | PUT (settings in body) |
| `messages/route.ts` | `messages/route.ts` | GET, POST |
| `messages/with-files/route.ts` | `messages/route.ts` | POST (files in FormData) |
| `messages/[messageId]/route.ts` | `messages/[messageId]/route.ts` | GET, PUT, DELETE |
| `messages/restore/route.ts` | `messages/[messageId]/route.ts` | POST?action=restore |
| `messages/search/route.ts` | `messages/route.ts` | GET?search=query |
| `messages/trash/route.ts` | `messages/route.ts` | GET?trash=true |
| `messages/audit-logs/route.ts` | `messages/audit-logs/route.ts` | GET (keep separate for admin) |
| `reactions/route.ts` | `reactions/route.ts` | POST (toggle), GET |
| `read-receipts/route.ts` | `read-receipts/route.ts` | POST, GET |
| `attachments/route.ts` | `attachments/route.ts` | POST, GET |
| `attachments/download/route.ts` | `attachments/route.ts` | GET?download=id |
| `members/route.ts` | (removed - merged into channel) | - |
| `users/[userId]/pin/route.ts` | `users/[userId]/pin/route.ts` | POST, GET (keep for user pinning) |

---

## Phase 3: Frontend Hook Optimization

### 3.1 Update useCommunications Hook

The frontend hook needs updates to:
1. Use new consolidated API endpoints
2. Support action query parameters
3. Maintain backward compatibility with component interfaces

Key changes:
```typescript
// Example: Pin channel action
const pinChannel = async (channelId: string) => {
  const response = await apiRequest.post(
    `/api/communication/channels/${channelId}?action=pin`
  )
  // ... rest of logic unchanged
}

// Example: Archive channel action
const archiveChannel = async (channelId: string, archive: boolean) => {
  const response = await apiRequest.put(
    `/api/communication/channels/${channelId}?action=${archive ? 'archive' : 'unarchive'}`
  )
  // ... rest of logic unchanged
}
```

### 3.2 Component Impact Analysis

| Component | Changes Required | Risk Level |
|-----------|------------------|------------|
| `chat-window.tsx` | API URL updates | Low |
| `channel-list.tsx` | API URL updates | Low |
| `channel-settings-modal.tsx` | API URL updates for actions | Low |
| `message-list.tsx` | No changes | None |
| `message-input.tsx` | No changes | None |
| `rich-message-editor.tsx` | No changes | None |
| `context-panel.tsx` | API URL updates | Low |
| `trash-view.tsx` | API URL updates | Low |
| `audit-log-view.tsx` | No changes | None |

---

## Phase 4: Testing & Validation

### 4.1 Test Checklist

#### Channels
- [ ] List user's channels (all types)
- [ ] Create DM channel
- [ ] Create group channel
- [ ] Create department channel (auto-sync)
- [ ] Create project channel (auto-sync)
- [ ] Update channel name/settings
- [ ] Archive/unarchive channel
- [ ] Pin/unpin channel
- [ ] Leave channel
- [ ] Add/remove members
- [ ] Delete channel

#### Messages
- [ ] Send text message
- [ ] Send message with files
- [ ] Send voice message
- [ ] Edit message (with audit log)
- [ ] Reply to message
- [ ] Move to trash
- [ ] Restore from trash
- [ ] Permanently delete
- [ ] Hide for self
- [ ] Search messages
- [ ] Load older messages (pagination)

#### Real-time
- [ ] New message broadcast
- [ ] Message edit broadcast
- [ ] Message delete broadcast
- [ ] Typing indicator
- [ ] Presence tracking (online/offline)
- [ ] Reaction broadcast
- [ ] Read receipt broadcast

#### Reactions
- [ ] Add reaction
- [ ] Remove reaction
- [ ] Toggle reaction
- [ ] Multiple users reacting

#### Read Receipts
- [ ] Mark single message read
- [ ] Mark all in channel read
- [ ] Get read receipts

#### Attachments
- [ ] Upload single file
- [ ] Upload multiple files
- [ ] Download attachment (presigned URL)
- [ ] Voice message upload

#### UI Functionality
- [ ] Channel list rendering
- [ ] Message list rendering
- [ ] Context panel functionality
- [ ] Trash view
- [ ] Audit log view
- [ ] Connection status indicator
- [ ] Notification system

---

## Phase 5: Migration Strategy

### 5.1 Migration Steps

1. **Phase 1 (Foundation)**: Create new lib files without touching existing routes
   - Create `lib/communication/broadcast.ts`
   - Create `lib/communication/operations.ts`
   - Update `lib/communication/cache.ts`
   - Create `lib/validations/communication.ts`
   - Test these files independently

2. **Phase 2 (Route Consolidation)**: Replace routes one at a time
   - Start with least critical routes (reactions, read-receipts)
   - Move to messages routes
   - Finally update channel routes
   - Keep old routes as backup until verified

3. **Phase 3 (Frontend)**: Update hook and test
   - Update useCommunications hook
   - Test all functionality
   - Update any component API calls

4. **Phase 4 (Cleanup)**: Remove deprecated files
   - Delete old route files
   - Remove unused helper functions
   - Update imports throughout codebase

### 5.2 Rollback Plan

- Keep old routes in a `_deprecated` folder during migration
- Feature flag for new vs old API paths (if needed)
- Git tags at each phase completion for easy rollback

---

## Phase 6: Performance Optimization

### 6.1 Backend Optimizations

1. **Connection Pooling**: Already using Prisma with PG adapter
2. **Query Optimization**: Ensure indexes are utilized
3. **Caching**: Implement caching for frequently accessed data
4. **Broadcast Optimization**: Single broadcast service, proper cleanup

### 6.2 Frontend Optimizations

1. **Message Virtualization**: Already using react-window (keep)
2. **Debounced Operations**: Typing, search already debounced
3. **Memoization**: Ensure proper React.memo usage
4. **State Management**: Redux for UI state, TanStack Query consideration

---

## Implementation Timeline

| Phase | Duration | Deliverables |
|-------|----------|--------------|
| Phase 1 | 2-3 days | Foundation layer (lib files) |
| Phase 2 | 3-4 days | Consolidated API routes |
| Phase 3 | 1-2 days | Frontend hook updates |
| Phase 4 | 1-2 days | Testing & validation |
| Phase 5 | 1 day | Migration completion & cleanup |
| Phase 6 | 1 day | Performance optimization |

**Total Estimated Time**: 9-13 days

---

## Success Criteria

1. ✅ All existing features work identically
2. ✅ Real-time functionality preserved
3. ✅ No TypeScript errors
4. ✅ All tests pass
5. ✅ Route files reduced from 20+ to ~8
6. ✅ Code duplication eliminated
7. ✅ Consistent error handling
8. ✅ Consistent response formats
9. ✅ Proper caching implemented
10. ✅ Audit logging maintained

---

## Appendix A: File Structure After Optimization

```
app/api/communication/
├── channels/
│   ├── route.ts                    # GET: List, POST: Create
│   └── [channelId]/
│       └── route.ts                # All channel operations
├── messages/
│   ├── route.ts                    # GET: List/Search/Trash, POST: Send
│   ├── [messageId]/
│   │   └── route.ts                # All message operations
│   └── audit-logs/
│       └── route.ts                # GET: Audit logs (admin)
├── reactions/
│   └── route.ts                    # POST: Toggle, GET: List
├── read-receipts/
│   └── route.ts                    # POST: Mark, GET: List
├── attachments/
│   └── route.ts                    # POST: Upload, GET: List/Download
└── users/
    └── [userId]/
        └── pin/
            └── route.ts            # POST/GET: User pinning

lib/communication/
├── broadcast.ts                    # Centralized broadcasting
├── operations.ts                   # Unified DB operations
├── cache.ts                        # Enhanced caching
├── helpers.ts                      # Consolidated helpers (new)
├── channel-helpers.ts              # Channel-specific logic
├── channel-sync-manager.ts         # Auto-sync logic
└── utils.ts                        # Utilities

lib/validations/
└── channel.ts                      # All validation schemas (EXISTING - update, don't create new)
```

---

## Appendix B: API Response Format Standards

All endpoints should follow this response format:

```typescript
// Success Response
{
  success: true,
  data: { ... },
  message?: string
}

// Error Response
{
  success: false,
  error: string,
  details?: { ... }
}

// Paginated Response
{
  success: true,
  data: {
    items: [...],
    pagination: {
      page: number,
      limit: number,
      total: number,
      hasMore: boolean
    }
  }
}
```

---

## Appendix C: Broadcast Event Reference

### Channel-Specific Broadcasts (via `rt_{channelId}`)

| Event | Payload | Triggered By |
|-------|---------|--------------|
| `new_message` | Full message with sender | POST /messages (via `broadcast.ts`) |
| `message_update` | Updated message | PUT /messages/[id] (via `broadcast.ts`) |
| `message_delete` | { messageId, channelId } | DELETE /messages/[id] (via `broadcast.ts`) |
| `message_trash` | { messageId, channelId } | DELETE /messages/[id]?action=trash (via `broadcast.ts`) |
| `message_restore` | Full message | POST /messages/[id]?action=restore (via `broadcast.ts`) |
| `message_hidden` | { messageId, userId } | DELETE /messages/[id]?action=hide (via `broadcast.ts`) |
| `reaction_added` | Full reaction | POST /reactions (via `broadcast.ts`) |
| `reaction_removed` | { messageId, emoji, userId } | POST /reactions toggle (via `broadcast.ts`) |
| `message_read` | { messageId, userId, readAt } | POST /read-receipts (via `broadcast.ts`) |
| `channel_updated` | Updated channel | PUT /channels/[id] (via `broadcast.ts`) |
| `channel_archived` | { channelId, archived } | PUT /channels/[id]?action=archive (via `broadcast.ts`) |
| `member_joined` | Member data | POST /channels/[id]?action=members (via `broadcast.ts`) |
| `member_left` | { channelId, userId } | POST /channels/[id]?action=leave (via `broadcast.ts`) |
| `member_role_changed` | { channelId, userId, newRole } | PUT /channels/[id]?action=member-role (via `broadcast.ts`) |
| `typing_start` | { channelId, userId, userName } | **CLIENT-SIDE** via `realtime-manager.ts` |
| `typing_stop` | { channelId, userId } | **CLIENT-SIDE** via `realtime-manager.ts` |

### User-Specific Broadcasts (via `notifications_{userId}`)

| Event | Payload | Triggered By |
|-------|---------|--------------|
| `mention_notification` | { channelId, messageId, mentionedBy, content } | POST /messages when @mention detected |
| `new_message` | { channelId, message, sender } | POST /messages for DM channels |

### User Channel Updates (via `user:{userId}:channels`)

| Event | Payload | Triggered By |
|-------|---------|--------------|
| `new_channel` | Full channel object | POST /channels when user added as member |
| `user_pin_update` | { channelId, isPinned } | POST /channels/[id]?action=pin |

### Presence (via `global_presence`)

| Event | Payload | Triggered By |
|-------|---------|--------------|
| (presence sync) | { userId, status, lastSeen } | **CLIENT-SIDE** via `realtime-manager.ts` |

---

## Notes

1. **Hybrid Database Architecture**: MongoDB for users/business data, Supabase for communication data - this remains unchanged
2. **Denormalization Strategy**: Sender data stored in messages - this remains unchanged
3. **Real-time via Supabase**: All real-time features use Supabase broadcasts - this remains unchanged
4. **File Storage**: AWS S3 for attachments with presigned URLs - this remains unchanged
5. **Two-Layer Real-time Architecture**:
   - **Server-side (`broadcast.ts`)**: Sends broadcasts from API routes using `SERVICE_ROLE_KEY`
   - **Client-side (`realtime-manager.ts`)**: Receives broadcasts in browser using `ANON_KEY`
   - These are complementary, NOT duplicates

This optimization focuses on code organization, consistency, and maintainability while preserving all existing functionality and architecture decisions.

---

## Quick Reference: Key Files

| File | Purpose | Environment |
|------|---------|-------------|
| `lib/communication/broadcast.ts` | Send broadcasts to Supabase channels | SERVER (API routes) |
| `lib/realtime-manager.ts` | Receive broadcasts, manage presence/typing | CLIENT (Browser) |
| `lib/middleware/route-middleware.ts` | Authentication, rate limiting, permissions | SERVER (API routes) |
| `lib/db-utils.ts` | Database operations for channels/messages | SERVER (API routes) |
| `lib/communication/operations.ts` | Enhanced cached database operations | SERVER (API routes) |
| `hooks/use-communications.ts` | React hook for communication state | CLIENT (Browser) |
| `lib/validations/channel.ts` | Zod validation schemas | SHARED |

---

## Appendix D: Pre-Implementation Checklist

Before starting implementation, verify these items:

### Environment Setup
- [ ] `SUPABASE_SERVICE_ROLE_KEY` is set in `.env` (not `SUPABASE_SECRET_KEY`)
- [ ] `NEXT_PUBLIC_SUPABASE_URL` is set
- [ ] `NEXT_PUBLIC_SUPABASE_ANON_KEY` is set
- [ ] Database migrations are up to date (`npx prisma db push`)

### Codebase Preparation
- [ ] All existing tests pass
- [ ] No TypeScript errors in `/app/api/communication/**`
- [ ] Back up existing route files before modification
- [ ] Create git branch for optimization work

### Dependencies Check
- [ ] `@supabase/supabase-js` is installed
- [ ] `zod` is installed
- [ ] `@prisma/client` is installed
- [ ] All peer dependencies are resolved

### Architecture Understanding Confirmed
- [ ] Understand `realtime-manager.ts` is CLIENT-SIDE only
- [ ] Understand `broadcast.ts` will be SERVER-SIDE only
- [ ] Understand `genericApiRoutesMiddleware` returns `{ session, user, userEmail, isSuperAdmin, filterContext, applyFilters }`
- [ ] Understand existing validation schemas in `lib/validations/channel.ts`

---

## Appendix E: Implementation Order

**Recommended order to minimize risk:**

1. **Phase 1.1**: Create `lib/communication/broadcast.ts` (new file, no breaking changes)
2. **Phase 1.2**: Create `lib/communication/operations.ts` (new file, no breaking changes)
3. **Phase 1.3**: Update `lib/communication/cache.ts` (enhance existing)
4. **Phase 1.4**: Add missing schemas to `lib/validations/channel.ts`
5. **Phase 2.1**: Consolidate `reactions/route.ts` (least complex)
6. **Phase 2.2**: Consolidate `read-receipts/route.ts` (least complex)
7. **Phase 2.3**: Consolidate `attachments/route.ts`
8. **Phase 2.4**: Consolidate `messages/route.ts` and `messages/[messageId]/route.ts`
9. **Phase 2.5**: Consolidate `channels/route.ts` and `channels/[channelId]/route.ts`
10. **Phase 3**: Update `hooks/use-communications.ts` to use new endpoints
11. **Phase 4**: Remove deprecated route files
12. **Phase 5**: Final testing and cleanup
