# Realtime Notifications - Implementation Plan v2

> **Last Updated:** December 2024  
> **Priority:** MEDIUM (After Communication Phase 3-5)  
> **Architecture:** MongoDB (primary) + Supabase (realtime delivery)

---

## Overview

Generic realtime notification system for project/task lifecycle events. Uses Supabase for WebSocket delivery while keeping MongoDB as the primary database.

---

## Data Flow

```
Action (Create/Update) → MongoDB API → Success → Supabase Broadcast → User Notification
```

---

## Phase 1: Notification Infrastructure (2 days)

### 1.1 Prisma Schema

```prisma
model notifications {
  id              String    @id @default(uuid())
  mongo_user_id   String    // Recipient
  type            String    // project_created, task_assigned, etc.
  title           String
  message         String
  mongo_entity_id String    // Project/Task MongoDB ID
  entity_type     String    // 'project' | 'task'
  metadata        Json?
  is_read         Boolean   @default(false)
  read_at         DateTime?
  created_at      DateTime  @default(now())
  
  @@index([mongo_user_id, is_read, created_at])
}
```

### 1.2 Notification Manager

**Create:** `lib/notification-manager.ts`

```typescript
import { prisma } from '@/lib/prisma'
import { getRealtimeManager } from '@/lib/realtime-manager'

class NotificationManager {
  async send(params: {
    userIds: string[]
    type: NotificationType
    title: string
    message: string
    entityId: string
    entityType: 'project' | 'task'
    metadata?: Record<string, any>
  }) {
    // 1. Store in Supabase
    const notifications = await prisma.notifications.createMany({
      data: params.userIds.map(userId => ({
        mongo_user_id: userId,
        type: params.type,
        title: params.title,
        message: params.message,
        mongo_entity_id: params.entityId,
        entity_type: params.entityType,
        metadata: params.metadata || {}
      }))
    })
    
    // 2. Broadcast via Supabase Realtime
    const realtimeManager = getRealtimeManager()
    for (const userId of params.userIds) {
      await realtimeManager.broadcastToUser(userId, 'new_notification', {
        type: params.type,
        title: params.title,
        message: params.message
      })
    }
    
    return notifications
  }
  
  async markAsRead(notificationId: string, userId: string) {
    return prisma.notifications.updateMany({
      where: { id: notificationId, mongo_user_id: userId },
      data: { is_read: true, read_at: new Date() }
    })
  }
  
  async getUnreadCount(userId: string) {
    return prisma.notifications.count({
      where: { mongo_user_id: userId, is_read: false }
    })
  }
}

export const notificationManager = new NotificationManager()
```

### 1.3 Notification Types

```typescript
// types/notifications.ts
export type NotificationType = 
  | 'project_created'
  | 'project_approved'
  | 'task_assigned'
  | 'task_updated'
  | 'task_completed'
  | 'mention'
```

---

## Phase 2: API Integration (1-2 days)

### 2.1 Project Notifications

**Modify:** `app/api/projects/route.ts` (POST)

```typescript
import { notificationManager } from '@/lib/notification-manager'

// After project creation
await notificationManager.send({
  userIds: [departmentHeadId],
  type: 'project_created',
  title: 'New Project',
  message: `${project.name} requires review`,
  entityId: project._id.toString(),
  entityType: 'project',
  metadata: { projectName: project.name, priority: project.priority }
})
```

### 2.2 Task Notifications

**Modify:** `app/api/tasks/route.ts` (POST/PUT)

```typescript
// After task assignment
if (task.assigneeId) {
  await notificationManager.send({
    userIds: [task.assigneeId.toString()],
    type: 'task_assigned',
    title: 'New Task',
    message: `You have been assigned: ${task.title}`,
    entityId: task._id.toString(),
    entityType: 'task'
  })
}
```

---

## Phase 3: Frontend Components (1-2 days)

### 3.1 Notification Hook

**Create:** `hooks/use-notifications.ts`

```typescript
export function useNotifications() {
  const [notifications, setNotifications] = useState([])
  const [unreadCount, setUnreadCount] = useState(0)
  const { data: session } = useSession()
  
  // Fetch on mount
  useEffect(() => {
    if (session?.user?.id) fetchNotifications()
  }, [session])
  
  // Subscribe to realtime
  useEffect(() => {
    if (!session?.user?.id) return
    
    const realtimeManager = getRealtimeManager()
    const unsubscribe = realtimeManager.subscribeToUserChannel(
      session.user.id,
      (notification) => {
        setNotifications(prev => [notification, ...prev])
        setUnreadCount(c => c + 1)
        toast.info(notification.title)
      }
    )
    
    return unsubscribe
  }, [session])
  
  return { notifications, unreadCount, markAsRead }
}
```

### 3.2 Notification Bell

**Create:** `components/layout/notification-bell.tsx`

```tsx
import { useNotifications } from '@/hooks/use-notifications'
import { Bell } from 'lucide-react'

export function NotificationBell() {
  const { notifications, unreadCount, markAsRead } = useNotifications()
  
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" className="relative">
          <Bell className="h-5 w-5" />
          {unreadCount > 0 && (
            <Badge className="absolute -top-1 -right-1 h-5 w-5 flex items-center justify-center">
              {unreadCount > 99 ? '99+' : unreadCount}
            </Badge>
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="w-80">
        {notifications.length === 0 ? (
          <p className="p-4 text-sm text-muted-foreground">No notifications</p>
        ) : (
          notifications.slice(0, 10).map(notif => (
            <NotificationItem key={notif.id} notification={notif} onRead={markAsRead} />
          ))
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
```

---

## Phase 4: API Routes (1 day)

### 4.1 Notifications List

**Create:** `app/api/notifications/route.ts`

```typescript
export async function GET(request: NextRequest) {
  const { session } = await genericApiRoutesMiddleware(request, 'notifications', 'read')
  
  const notifications = await prisma.notifications.findMany({
    where: { mongo_user_id: session.user.id },
    orderBy: { created_at: 'desc' },
    take: 50
  })
  
  return NextResponse.json({ success: true, data: notifications })
}
```

### 4.2 Mark as Read

**Create:** `app/api/notifications/[id]/read/route.ts`

```typescript
export async function POST(request: NextRequest, { params }) {
  const { session } = await genericApiRoutesMiddleware(request, 'notifications', 'update')
  
  await notificationManager.markAsRead((await params).id, session.user.id)
  
  return NextResponse.json({ success: true })
}
```

---

## Implementation Sequence

| Order | Task | Est. Time |
|-------|------|-----------|
| 1 | Prisma schema for notifications | 15 min |
| 2 | NotificationManager class | 1.5 hours |
| 3 | API routes (list, mark read) | 1 hour |
| 4 | useNotifications hook | 1 hour |
| 5 | NotificationBell component | 1.5 hours |
| 6 | Integrate in Header | 30 min |
| 7 | Add triggers to project/task APIs | 2 hours |

**Total: ~8-10 hours**

---

## Files to Create

- `lib/notification-manager.ts`
- `types/notifications.ts`
- `hooks/use-notifications.ts`
- `components/layout/notification-bell.tsx`
- `app/api/notifications/route.ts`
- `app/api/notifications/[id]/read/route.ts`

## Files to Modify

- `prisma/schema.prisma` (add notifications table)
- `lib/realtime-manager.ts` (add user channel subscription)
- `app/api/projects/route.ts` (add notification trigger)
- `app/api/tasks/route.ts` (add notification trigger)
- `components/layout/header.tsx` (add NotificationBell)

---

## Success Criteria

- Users receive realtime notifications for projects/tasks
- Notification bell shows unread count
- Clicking notification navigates to entity
- Mark as read works correctly
- Offline users see notifications on next login

---

*Follow project patterns (genericApiRoutesMiddleware, CustomModal, apiRequest).*
