# Advanced Channel Management - Implementation Plan v2

> **Last Updated:** December 2024  
> **Priority:** LOW (Optional Enhancement)  
> **Dependencies:** Communication Phase 3-5 completed

---

## Overview

Advanced channel features including auto-sync membership, admin controls, and department/project integration. These are optional enhancements for enterprise deployments.

---

## Feature Summary

| Feature | Description | Priority |
|---------|-------------|----------|
| Auto-Sync Members | Auto-add users to dept/project channels | Medium |
| Admin Controls | Restrict who can post/add members | Medium |
| Channel Avatar | Custom channel images | Low |
| Voice Messages | Record and send audio | Low |

---

## Phase 1: Auto-Sync Infrastructure (Optional)

### 1.1 Schema Updates

```prisma
model channels {
  // Add to existing
  auto_sync_enabled      Boolean @default(false)
  allow_external_members Boolean @default(true)
  admin_only_post        Boolean @default(false)
  admin_only_add         Boolean @default(false)
}
```

### 1.2 Channel Sync Manager

**Create:** `lib/channel-sync-manager.ts`

```typescript
class ChannelSyncManager {
  // Auto-add user to department channels when user joins department
  async syncUserToDepartment(userId: string, departmentId: string) {
    const channels = await prisma.channels.findMany({
      where: {
        mongo_department_id: departmentId,
        auto_sync_enabled: true,
        is_archived: false
      }
    })
    
    const user = await User.findById(userId).select('name email avatar')
    
    await Promise.all(channels.map(channel =>
      prisma.channel_members.upsert({
        where: {
          channel_id_mongo_member_id: { channel_id: channel.id, mongo_member_id: userId }
        },
        create: {
          channel_id: channel.id,
          mongo_member_id: userId,
          member_name: user.name,
          member_email: user.email,
          role: 'member'
        },
        update: {}
      })
    ))
  }
  
  // Auto-add task assignee to project channel
  async syncAssigneeToProject(assigneeId: string, projectId: string) {
    const channel = await prisma.channels.findFirst({
      where: {
        mongo_project_id: projectId,
        type: 'project',
        auto_sync_enabled: true
      }
    })
    
    if (!channel) return
    
    const user = await User.findById(assigneeId).select('name email avatar')
    
    await prisma.channel_members.upsert({
      where: {
        channel_id_mongo_member_id: { channel_id: channel.id, mongo_member_id: assigneeId }
      },
      create: {
        channel_id: channel.id,
        mongo_member_id: assigneeId,
        member_name: user.name,
        member_email: user.email,
        role: 'member'
      },
      update: {}
    })
  }
}

export const channelSyncManager = new ChannelSyncManager()
```

### 1.3 Integration Points

**User Creation (optional):**
```typescript
// app/api/users/route.ts POST
if (user.departmentId) {
  await channelSyncManager.syncUserToDepartment(user._id.toString(), user.departmentId.toString())
}
```

**Task Assignment (optional):**
```typescript
// app/api/tasks/route.ts POST/PUT
if (task.assigneeId && task.projectId) {
  await channelSyncManager.syncAssigneeToProject(task.assigneeId.toString(), task.projectId.toString())
}
```

---

## Phase 2: Admin Controls (Optional)

### 2.1 Member Management API

**Create:** `app/api/communication/channels/[channelId]/members/route.ts`

```typescript
// POST - Add member
export async function POST(request: NextRequest, { params }) {
  const { session } = await genericApiRoutesMiddleware(request, 'communication', 'create')
  const { userId, role = 'member' } = await request.json()
  const channelId = (await params).channelId
  
  // Check if admin-only-add
  const channel = await prisma.channels.findUnique({ where: { id: channelId } })
  if (channel?.admin_only_add) {
    const requester = await prisma.channel_members.findFirst({
      where: { channel_id: channelId, mongo_member_id: session.user.id }
    })
    if (requester?.role !== 'admin' && requester?.role !== 'owner') {
      return NextResponse.json({ error: 'Admin required' }, { status: 403 })
    }
  }
  
  // Add member
  const user = await User.findById(userId).select('name email avatar')
  const member = await prisma.channel_members.create({
    data: {
      channel_id: channelId,
      mongo_member_id: userId,
      member_name: user.name,
      member_email: user.email,
      role
    }
  })
  
  return NextResponse.json({ success: true, data: member })
}

// DELETE - Remove member
export async function DELETE(request: NextRequest, { params }) {
  const { session } = await genericApiRoutesMiddleware(request, 'communication', 'delete')
  const { searchParams } = new URL(request.url)
  const memberId = searchParams.get('memberId')
  const channelId = (await params).channelId
  
  // Check admin role
  const requester = await prisma.channel_members.findFirst({
    where: { channel_id: channelId, mongo_member_id: session.user.id }
  })
  
  if (requester?.role !== 'admin' && requester?.role !== 'owner') {
    return NextResponse.json({ error: 'Admin required' }, { status: 403 })
  }
  
  await prisma.channel_members.deleteMany({
    where: { channel_id: channelId, mongo_member_id: memberId }
  })
  
  return NextResponse.json({ success: true })
}
```

### 2.2 Message Posting Restriction

**Update:** `app/api/communication/messages/route.ts` POST

```typescript
// Check admin-only-post restriction
const channel = await prisma.channels.findUnique({ where: { id: channelId } })
if (channel?.admin_only_post) {
  const membership = await prisma.channel_members.findFirst({
    where: { channel_id: channelId, mongo_member_id: session.user.id }
  })
  if (membership?.role !== 'admin' && membership?.role !== 'owner') {
    return NextResponse.json({ error: 'Only admins can post' }, { status: 403 })
  }
}
```

---

## Phase 3: Voice Messages (Future)

### Overview

Record and send audio messages directly in chat.

### Requirements

- Browser MediaRecorder API
- S3 storage for audio files
- Audio player component in message bubble

### Implementation Notes

```typescript
// Message content_type: 'audio'
// Store audio file URL in attachments
// Use HTML5 audio element for playback
```

*Voice messages are low priority - implement only if specifically requested.*

---

## Implementation Sequence

| Order | Task | Est. Time | Priority |
|-------|------|-----------|----------|
| 1 | Schema updates (optional fields) | 15 min | Medium |
| 2 | ChannelSyncManager class | 2 hours | Medium |
| 3 | Members API endpoint | 1.5 hours | Medium |
| 4 | Admin-only-post check | 30 min | Medium |
| 5 | Integrate sync in user/task APIs | 1 hour | Low |
| 6 | Voice messages | 4+ hours | Low |

---

## Files to Create

- `lib/channel-sync-manager.ts`
- `app/api/communication/channels/[channelId]/members/route.ts`

## Files to Modify

- `prisma/schema.prisma` (add optional fields)
- `app/api/communication/messages/route.ts` (admin-only check)
- `app/api/users/route.ts` (optional sync trigger)
- `app/api/tasks/route.ts` (optional sync trigger)

---

## Decision Points

| Feature | Implement Now? | Reason |
|---------|----------------|--------|
| Auto-sync | No | Nice-to-have, not critical |
| Admin controls | Maybe | Useful for announcements channels |
| Voice messages | No | Complex, low ROI |

---

## Success Criteria

If implemented:
- Users auto-added to relevant channels on dept/project assignment
- Admins can restrict posting/adding members
- No performance degradation from sync operations

---

*These are optional enhancements. Focus on core communication features first.*
