# Communication Module - Professional Improvements Roadmap v2

> **Last Updated:** December 2024  
> **Status:** Phase 1-5 Completed | Real-time & UI Enhancements Complete  
> **Target:** Enterprise-grade WhatsApp/Slack-style messaging

---

## Implementation Status

| Phase | Name | Status | Notes |
|-------|------|--------|-------|
| 1 | Critical Bug Fixes | ✅ Completed | Pagination, logging, cleanup |
| 2 | Message Lifecycle | ✅ Completed | Trash, restore, audit logs |
| 3 | Channel Management | ✅ Completed | Leave, archive, settings modal, realtime updates |
| 4 | Loading & Reliability | ✅ Completed | Skeletons, reconnection, connection status |
| 5 | Performance & Security | ✅ Completed | Cache layer, rate limiting, DOMPurify XSS protection |
| 6 | UI Enhancements | ✅ Completed | Resizable sidebar, archived channel indicators |

---

## Recent Additions (December 2024)

### Real-time Channel Updates
- **Redux Actions:** `addChannel`, `updateChannel`, `removeChannel` for instant UI updates
- **API Broadcasting:** Archive/unarchive/leave/create operations broadcast via Supabase
- **User Channel Subscription:** Automatic subscription to `user:${userId}:channels` for new channel notifications
- **Optimistic Updates:** Local state updates immediately, synced with server response

### Caching Layer (`lib/communication/cache.ts`)
- Channel caching with 2-minute TTL
- Message caching per channel (1-minute TTL)
- User data caching (5-minute TTL)
- Cache invalidation on channel updates

### Resizable Sidebar (`components/communication/resizable-sidebar.tsx`)
- Drag handle for horizontal resize
- Min: 280px, Max: 400px
- localStorage persistence
- Double-click to reset
- Mobile-friendly (100% width in Sheet)

### Security Enhancements
- DOMPurify integration for XSS protection in `html-text-renderer.tsx`
- Rate limiting verified (300 req/15min for API, 100 for sensitive, 5 for auth)

---

## Project Patterns Reference

### API Route Pattern
```typescript
// All routes MUST follow this pattern
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'

export async function GET(request: NextRequest) {
  const { session, user, isSuperAdmin } = await genericApiRoutesMiddleware(
    request, 
    'communication',  // module name
    'read'            // 'read' | 'create' | 'update' | 'delete'
  )
  // ... route logic
}
```

### Modal Pattern
```typescript
// Use CustomModal for all modal dialogs
import CustomModal from '@/components/shared/custom-modal'

<CustomModal
  isOpen={isOpen}
  onClose={onClose}
  title="Modal Title"
  size="md"  // 'sm' | 'md' | 'lg' | 'xl'
>
  {/* content */}
</CustomModal>
```

### Hook Pattern
```typescript
// Use apiRequest for API calls (automatically unwraps responses)
import { apiRequest } from '@/lib/utils/api-client'

const data = await apiRequest('/api/communication/endpoint', {
  method: 'POST',
  body: JSON.stringify(payload)
})
// data is already unwrapped (not { success, data })
```

---

## Phase 3: Channel Management (Priority: HIGH)

**Estimated Time:** 2-3 days  
**Dependencies:** Phase 1-2 completed

### 3.1 Leave Channel

**Schema Update (Prisma):**
```prisma
model channels {
  // Add to existing model
  is_archived   Boolean   @default(false)
  archived_at   DateTime?
  archived_by   String?   // mongo_user_id
}
```

**API:** `POST /api/communication/channels/[channelId]/leave`

| Validation | Rule |
|------------|------|
| Admin check | Channel admin/owner cannot leave (must transfer first) |
| Last member | Auto-archive channel if last member leaves |
| DM channels | Hide instead of leave |

**Implementation:**
```typescript
// app/api/communication/channels/[channelId]/leave/route.ts
export async function POST(request: NextRequest, { params }) {
  const { session } = await genericApiRoutesMiddleware(request, 'communication', 'update')
  
  const channelId = (await params).channelId
  const membership = await prisma.channel_members.findFirst({
    where: { channel_id: channelId, mongo_member_id: session.user.id }
  })
  
  // Prevent admin from leaving
  if (membership?.role === 'admin' || membership?.role === 'owner') {
    return NextResponse.json({ error: 'Transfer admin role before leaving' }, { status: 400 })
  }
  
  // Delete membership
  await prisma.channel_members.delete({ where: { id: membership.id } })
  
  // Check if last member - auto archive
  const remainingCount = await prisma.channel_members.count({ where: { channel_id: channelId } })
  if (remainingCount === 0) {
    await prisma.channels.update({
      where: { id: channelId },
      data: { is_archived: true, archived_at: new Date() }
    })
  }
  
  return NextResponse.json({ success: true })
}
```

### 3.2 Archive Channel

**API:** `POST /api/communication/channels/[channelId]/archive`

| Permission | Requirement |
|------------|-------------|
| Archive | Admin/owner only |
| Unarchive | Admin/owner only |
| View archived | Any previous member |

**Implementation:**
```typescript
// app/api/communication/channels/[channelId]/archive/route.ts
export async function POST(request: NextRequest, { params }) {
  const { session } = await genericApiRoutesMiddleware(request, 'communication', 'update')
  
  const { action } = await request.json() // 'archive' | 'unarchive'
  const channelId = (await params).channelId
  
  // Check admin role
  const membership = await prisma.channel_members.findFirst({
    where: { 
      channel_id: channelId, 
      mongo_member_id: session.user.id,
      role: { in: ['admin', 'owner'] }
    }
  })
  
  if (!membership) {
    return NextResponse.json({ error: 'Admin required' }, { status: 403 })
  }
  
  await prisma.channels.update({
    where: { id: channelId },
    data: {
      is_archived: action === 'archive',
      archived_at: action === 'archive' ? new Date() : null,
      archived_by: action === 'archive' ? session.user.id : null
    }
  })
  
  return NextResponse.json({ success: true })
}
```

### 3.3 Channel Settings Modal

**Component:** `components/communication/channel-settings-modal.tsx`

**Features:**
- Edit channel name/description
- Manage members (add/remove/role change)
- Archive/Unarchive toggle
- Leave channel button
- Transfer admin role

**UI Pattern:**
```tsx
<CustomModal isOpen={isOpen} onClose={onClose} title="Channel Settings" size="lg">
  <Tabs defaultValue="general">
    <TabsList>
      <TabsTrigger value="general">General</TabsTrigger>
      <TabsTrigger value="members">Members</TabsTrigger>
    </TabsList>
    <TabsContent value="general">{/* Name, description, archive */}</TabsContent>
    <TabsContent value="members">{/* Member list with role management */}</TabsContent>
  </Tabs>
</CustomModal>
```

### 3.4 Hook Updates

**Add to `use-communications.ts`:**
```typescript
const leaveChannel = useCallback(async (channelId: string) => {
  await apiRequest(`/api/communication/channels/${channelId}/leave`, { method: 'POST' })
  await fetchChannels()
  dispatch(clearActiveChannel())
  toast({ title: 'Left channel successfully' })
}, [dispatch, fetchChannels])

const archiveChannel = useCallback(async (channelId: string, action: 'archive' | 'unarchive') => {
  await apiRequest(`/api/communication/channels/${channelId}/archive`, {
    method: 'POST',
    body: JSON.stringify({ action })
  })
  await fetchChannels()
  toast({ title: action === 'archive' ? 'Channel archived' : 'Channel restored' })
}, [fetchChannels])
```

---

## Phase 4: Loading States & Reliability (Priority: HIGH)

**Estimated Time:** 2 days

### 4.1 Skeleton Components

**Create:** `components/communication/skeletons/`

| Component | Usage |
|-----------|-------|
| `MessageSkeleton` | Message bubble loading |
| `ChannelListSkeleton` | Sidebar loading |
| `ChatWindowSkeleton` | Full chat loading |

**Pattern:**
```tsx
export function MessageSkeleton({ count = 5 }: { count?: number }) {
  return (
    <div className="space-y-4 p-4">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="flex gap-3 animate-pulse">
          <Skeleton className="h-10 w-10 rounded-full" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-4 w-full" />
          </div>
        </div>
      ))}
    </div>
  )
}
```

### 4.2 Connection Recovery

**Update:** `lib/realtime-manager.ts`

```typescript
private reconnectAttempts = 0
private readonly maxReconnectAttempts = 5
private reconnectDelay = 1000

private handleDisconnect() {
  if (this.reconnectAttempts < this.maxReconnectAttempts) {
    setTimeout(() => {
      this.reconnect()
      this.reconnectAttempts++
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, 30000) // Max 30s
    }, this.reconnectDelay)
  }
}
```

### 4.3 Connection Status Banner

**Component:** `components/communication/connection-status.tsx`

```tsx
export function ConnectionStatus() {
  const { isConnected, isReconnecting } = useRealtimeStatus()
  
  if (isConnected) return null
  
  return (
    <div className="bg-yellow-500 text-white px-4 py-2 text-center text-sm">
      {isReconnecting ? 'Reconnecting...' : 'Connection lost'}
    </div>
  )
}
```

---

## Phase 5: Performance & Security (Priority: MEDIUM-HIGH)

**Estimated Time:** 2-3 days

### 5.1 React Query Migration (Optional)

**Benefit:** Automatic caching, background refetch, stale data handling

```typescript
// hooks/use-channel-messages.ts
export function useChannelMessages(channelId: string) {
  return useQuery({
    queryKey: ['messages', channelId],
    queryFn: () => apiRequest(`/api/communication/channels/${channelId}/messages`),
    staleTime: 30 * 1000,
    gcTime: 5 * 60 * 1000,
  })
}
```

### 5.2 Rate Limiting

**Already implemented** via `genericApiRoutesMiddleware`. Verify limits:

| Endpoint | Limit |
|----------|-------|
| Send message | 30/minute |
| Channel operations | 10/minute |
| Search | 20/minute |

### 5.3 Content Security

**Verify XSS protection:**
```typescript
import DOMPurify from 'dompurify'
const sanitizedContent = DOMPurify.sanitize(content)
```

---

## Implementation Sequence (Post Phase 2)

| Order | Task | Est. Time |
|-------|------|-----------|
| 1 | Prisma schema (is_archived) | 15 min |
| 2 | Run migration | 5 min |
| 3 | Leave channel API | 1 hour |
| 4 | Archive channel API | 1 hour |
| 5 | Hook updates (leaveChannel, archiveChannel) | 30 min |
| 6 | Channel settings modal (CustomModal) | 2 hours |
| 7 | Skeleton components | 1.5 hours |
| 8 | Connection recovery in RealtimeManager | 2 hours |
| 9 | Connection status banner | 30 min |

---

## Files Reference

### To Create (Phase 3-5)
```
app/api/communication/channels/[channelId]/leave/route.ts
app/api/communication/channels/[channelId]/archive/route.ts
components/communication/channel-settings-modal.tsx
components/communication/skeletons/message-skeleton.tsx
components/communication/skeletons/channel-skeleton.tsx
components/communication/connection-status.tsx
```

### To Update
```
prisma/schema.prisma                    # Add is_archived fields
hooks/use-communications.ts             # Add leaveChannel, archiveChannel
lib/realtime-manager.ts                 # Add reconnection logic
store/slices/communicationSlice.ts      # Add archived channels state
components/communication/chat-window.tsx # Add settings button
```

---

## Success Criteria

✅ **Phase 3:** Leave/archive channels work, admin restrictions enforced  
✅ **Phase 4:** Smooth loading states, automatic reconnection  
✅ **Phase 5:** Cached reads, rate limits verified

---

*Follow project patterns. Test each phase before moving to next.*
