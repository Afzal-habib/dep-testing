# Real-Time Communication System Implementation with supabase

This document outlines the complete implementation of the real-time communication system for the Digi Era Pro CRM using supabase and there already mongoDb used as a main DB and all other implementation are completed with these modules  


## Existing implemented  project struture using the mongoDB as a main db 
In this ERP/CRM all the things are implemented for these modules :
1) Project Setup & Architecture and Role base permissions
    Next.js + Tailwind project setup
    Strict TypeScript config, Redux Toolkit store
    NextAuth with MongoDB adapter + bcryptjs
    Base layout, header, sidebar, notification bell
    Role-based middleware & environment variable scaffolding
    Role-based permission system with dynamic assignment
2) Authentication & Authorization Module
    Purpose: Multi-tier security with role-based access control
    Users are created by the admin department with credential setups and all important fields against the department and specific role
    Multi-Tier Authentication: Admin (2FA ), Employee (2FA), Client (Global)
    Dynamic Role Management: 10+ roles with hierarchical permissions
    Security Enforcement: Network validation, session management, audit logging
    Superadmin Protection: user with role super_admin(unrestricted)
    User registration/login with security tier validation
    Two-factor authentication for admins and Internal Employees on every login.
    Session management with timeout
3) Department Management Module 
    Key Features:
    Department creation/hierarchy
    Employee assignment
    Role management with dynamic permissions
    Inter-department workflow
    Performance tracking
    Workflow Process:
    Dynamic role creation per department
    Role assignment to users
    Access based on permissions

4) Lead Generation & Client Management Module
    Key Features:
    Client profile creation (details, requirements)
    Lead scoring/qualification tracking
    Quote/proposal management
    Client communication history
    Pipeline tracking/conversion metrics
5)  Onboarding & Project Validation Module
    Workflow Stages:
    Sales Manager(using dynamic role and permission): Project Basic info collection on the lead creation
    Support Manager (using dynamic role and permission): Info validation and Project Updation
    Support Agent (using dynamic role and permission): All Project information gathering
    Enhancement/documentation
    Key Features:
    Ticket management with status tracking
    Project categorization (Web, GMB, SEO, Graphics, Social)
    Client requirement validation/enhancement
    Document collection/verification
6) Approval & Task Creation Module
    Support Agent(using dynamic role and permission): Project Categorization (department-wise) 
    Department Manager (Stage 7): Approval/task creation
    Workflow Stages:
    Team Lead (using dynamic role and permission): Subtask creation/assignment
    Team Member (using dynamic role and permission): Execution/progress updates
    Key Features:
    Task assignment with priority levels
    Progress tracking (real-time)
    Time logging/productivity monitoring
    Internal collaboration (after real time chat implementation)


## Main Plan for real time communication:
`` Want to create the slack inspired realtime chat/communication using the supabase
`` Basically we are using the MongoDb as a main DB for this erp/crm and want to use the supabase for real time communication.
`` For all the users and client we are using the mongoDB and want to use the supabse just for the communication purpose only with these tables ( channel, messages, channelMember or other important tables but not the Profile/Users, for that use  the mongo_member_id,MongoDepartId in the channels, messages...)

`` There is no need for creating too many tables in the supabase , just create the important tables and other use the mongo collecion data using thier ids and manipulate on the run time in the  api end points but every things should be according to the best practices.

## 📋 Features Implemented

### ✅ Core Communication Features
- **Real-time messaging** 
- **Multiple channel types**: DM, Department, Project, General, Group
- **Message persistence** with supabase
- **Read receipts** and delivery status
- **Typing indicators** with auto-timeout
- **Online presence** with heartbeat tracking
- **Automatic channel creation** for departments and projects
- **Attachment** using the s3

### ✅ Channel Types
1. **User-to-User (DM)**: Direct messaging between any two users
1. **User-to-Cleint (DM)**: Direct messaging between support agent to client( client is a user with isClient :true)
2. **Department Channels**: Auto-created for each department with all department members and in future we can also add the user in this channel for new created user
3. **General Channel for more than one department**: Company-wide channel for all internal users for selected department  (excludes clients) and in future we can also add the user in this channel for new created user
4. **Project Channels**: Create the Channel on project based and all assinged user can participate for project related communication and in future we can also add the user in this channel for new created user
5. **Group Channels**: Manual creation for custom groups

### ✅ Real-Time Features
- **Live message delivery** with instant UI updates
- **Typing indicators** with 3-second timeout
- **Online/offline status** with heartbeat (25s intervals)
- **Channel switching** with automatic room joining/leaving
- **Unread message counts** and notifications
- **Presence tracking** across all connected clients

## Use Existing Component for UI for Chat System

The communication system has a complete UI component library that can be seamlessly integrated with Supabase. The existing components are designed to work with the `useCommunications` hook, which currently uses mock data but can be easily updated to use real Supabase calls.

#### Core Components:
- **`ChatWindow`** - Main chat interface with message list, input, and header
- **`MessageList`** - Displays messages with read receipts, typing indicators, and attachments
- **`ChannelList`** - Shows available channels with unread counts and search
- **`CommunicationSidebar`** - Collapsible sidebar for channel navigation
- **`MessageInput`** - Rich text input with file upload and emoji support
- **`OnlineIndicator`** - Shows online users with avatars and status
- **`ContextPanel`** - Channel information, members, and file sharing
- **`MessageNotification`** - Bell icon with notification dropdown
- **`UserDirectory`** - User search and DM initiation

#### Key Hook: `useCommunications`
Located at `hooks/use-communications.ts`, this hook provides:
- Channel management (create, select, fetch)
- Message handling (send, receive, mark as read)
- Real-time subscriptions (to be implemented with Supabase)
- Typing indicators and presence
- Error handling and loading states

### Integration Steps for Supabase

#### 1. Update `useCommunications` Hook
Replace mock data calls with real Supabase operations:

```typescript
// Before (Mock Data)
const { channels, sendMessage } = useCommunications()

// After (Supabase Integration)
const { channels, sendMessage } = useCommunications() // Same interface, different implementation
```

#### 2. Supabase Table Structure
Create these tables in Supabase (matching existing TypeScript interfaces):

```sql
-- Channels table
CREATE TABLE channels (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  type TEXT NOT NULL CHECK (type IN ('dm', 'group', 'department', 'project', 'client-support')),
  name TEXT,
  avatar_url TEXT,
  mongo_department_id TEXT,
  mongo_project_id TEXT,
  mongo_creator_id TEXT NOT NULL,
  is_private BOOLEAN DEFAULT FALSE,
  member_count INTEGER DEFAULT 0,
  last_message_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Messages table
CREATE TABLE messages (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  channel_id UUID REFERENCES channels(id) ON DELETE CASCADE,
  mongo_sender_id TEXT NOT NULL,
  content TEXT NOT NULL,
  content_type TEXT DEFAULT 'text' CHECK (content_type IN ('text', 'file', 'system')),
  thread_id UUID,
  reply_count INTEGER DEFAULT 0,
  mongo_mentioned_user_ids TEXT[],
  is_edited BOOLEAN DEFAULT FALSE,
  edited_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  attachments JSONB
);

-- Channel members table
CREATE TABLE channel_members (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  channel_id UUID REFERENCES channels(id) ON DELETE CASCADE,
  mongo_member_id TEXT NOT NULL,
  role TEXT DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
  joined_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(channel_id, mongo_member_id)
);

-- Read receipts table
CREATE TABLE read_receipts (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  message_id UUID REFERENCES messages(id) ON DELETE CASCADE,
  mongo_user_id TEXT NOT NULL,
  read_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(message_id, mongo_user_id)
);
```

#### 3. Real-time Subscriptions
Implement Supabase real-time subscriptions in the hook:

```typescript
// In useCommunications hook
useEffect(() => {
  if (!channelId) return;

  // Subscribe to new messages
  const messageSubscription = supabase
    .channel(`messages:${channelId}`)
    .on('postgres_changes', {
      event: 'INSERT',
      schema: 'public',
      table: 'messages',
      filter: `channel_id=eq.${channelId}`
    }, (payload) => {
      addMessage(payload.new);
    })
    .subscribe();

  // Subscribe to typing indicators
  const typingSubscription = supabase
    .channel(`typing:${channelId}`)
    .on('broadcast', { event: 'typing' }, (payload) => {
      setTyping(payload.payload);
    })
    .subscribe();

  return () => {
    messageSubscription.unsubscribe();
    typingSubscription.unsubscribe();
  };
}, [channelId]);
```

#### 4. API Integration Points
Update these functions in `useCommunications` to use Supabase:

- `fetchChannels()` - Query channels with member info
- `createChannel()` - Insert into channels and channel_members
- `sendMessage()` - Insert message and broadcast via real-time
- `markAsRead()` - Insert read receipt
- `setTyping()` - Broadcast typing status

#### 5. MongoDB Integration
For user data, join with MongoDB collections:

```typescript
// Example: Fetch channels with participant details
const fetchChannelsWithChannelMembers = async () => {
  const { data: channels } = await supabase
    .from('channels')
    .select(`
      *,
      channel_members (
        mongo_member_id,
        role
      )
    `);

  // Enrich with MongoDB user data
  const enrichedChannels = await Promise.all(
    channels.map(async (channel) => {
      const channel_members = await Promise.all(
        channel.channel_members.map(async (member) => {
          const user = await getUserFromMongo(member.mongo_member_id);
          return {
            mongo_member_id: member.mongo_member_id,
            name: user.name,
            email: user.email,
            role: user.role,
            isOnline: user.isOnline,
            avatar: user.avatar
          };
        })
      );
      return { ...channel, channel_members };
    })
  );

  return enrichedChannels;
};
```

#### 6. Permission Integration
Use existing role-based permissions from the CRUD system:

```typescript
// Check permissions before allowing actions
const canCreateChannel = usePermissions().canCreate('channels');
const canSendMessage = usePermissions().canCreate('messages', channelId);

// In components
if (canCreateChannel) {
  // Show create channel button
}
```

#### 7. Component Usage Examples

**Basic Chat Page:**
```tsx
// app/communications/page.tsx
export default function CommunicationsPage() {
  const { channels, selectChannel, currentUser } = useCommunications();

  return (
    <div className="flex h-screen">
      <CommunicationSidebar 
        channels={channels}
        onChannelSelect={selectChannel}
        currentUserId={currentUser?._id}
      />
      <ChatWindow />
    </div>
  );
}
```

**Channel-Specific Page:**
```tsx
// app/communications/[channelId]/page.tsx
export default function ChannelPage({ params }) {
  const { selectChannel } = useCommunications();

  useEffect(() => {
    selectChannel(params.channelId);
  }, [params.channelId]);

  return <ChatWindow channelId={params.channelId} />;
}
```

**Client Portal Chat:**
```tsx
// app/client-portal/chat/page.tsx
export default function ClientChatPage() {
  const { channels } = useCommunications();
  const supportChannel = channels.find(ch => ch.type === 'client-support');

  return (
    <div className="min-h-screen">
      <ChatWindow channelId={supportChannel?.id} />
    </div>
  );
}
```

### Migration Strategy

1. **Keep UI Components Intact** - Most of the  changes are not needed to React components
2. **Update Hook Implementation** - Replace mock data with Supabase calls
3. **Add Real-time Subscriptions** - Implement Supabase real-time features
4. **Test Incrementally** - Start with basic messaging, then add features
5. **Maintain Type Safety** - Ensure Supabase data matches existing TypeScript interfaces

### Benefits of This Approach

- **Zero UI Changes** - Existing components work without modification
- **Type Safety Maintained** - Same interfaces, different data source
- **Gradual Migration** - Can migrate features one by one
- **Consistent UX** - Users won't notice the backend change
- **Permission Integration** - Leverages existing role-based access control

The existing UI components are production-ready and designed to handle real-time updates, making this integration straightforward and reliable.

The communication system provides comprehensive real-time messaging capabilities with multiple channel types, presence tracking, and extensible architecture for real time chating system.
use these supase related env variables where need 

NEXT_PUBLIC_SUPABASE_URL=https://kkdcderwckpktfxersdk.supabase.co
SUPABASE_SECRET_KEY=sb_secret_S7iS0a92tECg5oCH27EheA_vA9EvlDZ
NEXT_PUBLIC_SUPABASE_PUBLISHABLE_OR_ANON_KEY=sb_publishable_0lMtYgrxgXNCdUWSOTpdHA_8Ogqj-a5
PROJECT_ID=kkdcderwckpktfxersdk
PROJECT_NAME=new-real-time
DB_PASSWORD=O4YlTl5JWkCVZvik
DB_USER=supabase_admin

## 🏗️ Architecture

### Database Structure
#### MongoDB (Main ERP/CRM Database)
- **Users Collection**: All users (employees) and clients with full profile information
- **Departments Collection**: Department hierarchy and information
- **Projects Collection**: Project details and assignments
- **Roles Collection**: Role definitions and permissions
- **Leads Collection**: Lead management for client generation

#### Supabase (Real-time Communication Database)
Tables to create:
1. **channels** - Communication channels
   - `id` (UUID, primary key)
   - `type` (TEXT) - dm, group, department, project
   - `name` (TEXT)
   - `avatar_url` (TEXT)
   - `mongo_department_id` (TEXT, nullable)
   - `mongo_project_id` (TEXT, nullable)
   - `mongo_creator_id` (TEXT) - Who created this channel
   - `is_private` (BOOLEAN)
   - `member_count` (INT)
   - `last_message_at` (TIMESTAMP)
   - `created_at` (TIMESTAMP)
   - `updated_at` (TIMESTAMP)

2. **messages** - Message history
   - `id` (UUID, primary key)
   - `channel_id` (UUID, FK to channels)
   - `mongo_sender_id` (TEXT) - Who sent this message
   - `content` (TEXT)
   - `content_type` (TEXT) - text, file, system
   - `thread_id` (UUID, nullable) - For threading
   - `reply_count` (INT)
   - `mongo_mentioned_user_ids` (TEXT[]) - Array of mentioned user IDs
   - `is_edited` (BOOLEAN)
   - `edited_at` (TIMESTAMP)
   - `created_at` (TIMESTAMP)

3. **channel_members** - Channel membership
   - `channel_id` (UUID, FK to channels)
   - `mongo_member_id` (TEXT) - MongoDB user ID
   - `role` (TEXT) - admin, member
   - `last_read_at` (TIMESTAMP)
   - `is_muted` (BOOLEAN)
   - `notification_level` (TEXT) - all, mentions, none
   - `joined_at` (TIMESTAMP)
   - `mongo_invited_by_id` (TEXT)

4. **reactions** - Message reactions
   - `id` (UUID, primary key)
   - `message_id` (UUID, FK to messages)
   - `mongo_reactor_id` (TEXT)
   - `emoji` (TEXT)
   - `created_at` (TIMESTAMP)

5. **attachments** - File attachments
   - `id` (UUID, primary key)
   - `message_id` (UUID, FK to messages)
   - `file_name` (TEXT)
   - `file_size` (BIGINT)
   - `mime_type` (TEXT)
   - `s3_key` (TEXT)
   - `s3_bucket` (TEXT)
   - `width` (INT, nullable)
   - `height` (INT, nullable)
   - `duration_seconds` (INT, nullable)
   - `mongo_uploader_id` (TEXT)
   - `uploaded_at` (TIMESTAMP)

6. **read_receipts** - Detailed read tracking
   - `message_id` (UUID, FK to messages)
   - `mongo_reader_id` (TEXT)
   - `read_at` (TIMESTAMP)

### Helper Functions
- `increment_reply_count()` - Updates reply count for threaded messages
- `get_unread_count()` - Calculates unread messages for user in channel
- `get_user_channels()` - Returns user's channels with metadata

### Supabase Realtime Features
- **Presence Channel**: Built-in presence tracking for online/offline status (replaces separate presence table)
- **Broadcast Channel**: Real-time typing indicators and custom events (replaces typing_indicators table)
- **Postgres Changes**: For message subscriptions and channel updates

## 📱 UI Components & Mock Data

### Components Structure
1. **CommunicationSidebar** - Channel list and navigation
2. **ChatWindow** - Main chat interface
3. **MessageList** - Message display with read receipts
4. **MessageInput** - Message composition
5. **UserDirectory** - User selection for DMs
6. **ChannelList** - Available channels
7. **ChannelMembersList** - Channel members
8. **TypingIndicator** - Shows who's typing
9. **OnlineIndicator** - Shows online users
10. **AttachmentPreview** - File attachments display

### Mock Data Structure

#### Mock Users (from MongoDB simulation)
- User with `isClient: false` = Employee
- User with `isClient: true` = Client/Support User
- Each user linked to department (except clients)
- Roles determine channel access permissions

#### Mock Channels
1. **General Channel** (type: 'general')
   - Auto-created for company
   - All internal users invited
   - No clients

2. **Department Channels** (type: 'department')
   - Auto-created per department
   - All department members + head
   - Manager-controlled access

3. **Project Channels** (type: 'project')
   - Auto-created per project
   - All assigned team members
   - Project-based collaboration

4. **DM Channels** (type: 'dm')
   - User-to-user messaging
   - Automatic creation on first message
   - Bilateral access

5. **Client Support** (type: 'client-support')
   - Support agent to client DM
   - Client-specific support

6. **Group Channels** (type: 'group')
   - Manual creation for custom groups
   - Multi-user conversations

#### Mock Messages
- Message objects with:
  - Text content
  - Timestamps
  - Read receipts
  - Typing indicators (with 3s timeout)
  - Optional attachments/files

#### Mock Presence Data
- Online status tracking via Supabase Presence (25s heartbeat)
- Last activity timestamps via Presence state
- Typing status via Supabase Broadcast with auto-timeout (3s)

## 🔄 Integration Points

### When Connecting to Supabase:
1. **Replace mock channels** with Supabase query
2. **Replace mock messages** with Supabase subscriptions
3. **Replace mock users** with MongoDB API calls (mocked in UI initially)
4. **Real-time subscriptions** for messages and presence
5. **Supabase Presence** for online status (built-in, no separate table needed)
6. **Supabase Broadcast** for typing indicators (built-in, no separate table needed)

### API Endpoints Needed:
1. `GET /api/communications/channels` - Fetch all channels
2. `POST /api/communications/channels` - Create new channel
3. `GET /api/communications/channels/:id/messages` - Fetch messages
4. `POST /api/communications/messages` - Send message
5. `PUT /api/communications/messages/:id` - Mark as read
6. `GET /api/communications/users` - Get available users (from MongoDB)
7. `POST /api/communications/presence` - Update presence status (handled by Supabase Presence)

## ✅ UI/UX Requirements (with Mock Data)

### Responsive Design
- Desktop: Full sidebar + chat window layout
- Tablet: Collapsible sidebar + full chat
- Mobile: Stacked layout with channel selector

### Message Display
- User avatar + name
- Timestamp (grouped by date)
- Read receipt indicators
- Typing indicators below messages
- Message reactions (extensible)

### Channel Features
- Unread message counts
- Online member indicators
- Quick user search
- Sorting options (recent, alphabetical)
- Channel info panel

### Accessibility
- ARIA labels for screen readers
- Keyboard navigation (Tab, Enter, Escape)
- High contrast mode support
- Focus management
- Semantic HTML structure






