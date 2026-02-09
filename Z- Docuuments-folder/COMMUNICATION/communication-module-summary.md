
The `RealtimeManager` is a singleton class in the Communication Module that manages all real-time interactions using Supabase's real-time features. It handles WebSocket connections for instant messaging, presence tracking, typing indicators, and event broadcasting. Built on Supabase's Realtime API, it ensures efficient, low-latency communication across channels while managing connection recovery, throttling, and state synchronization. The class uses a hybrid approach with MongoDB for user data and Supabase PostgreSQL for chat data, optimizing performance by denormalizing sender information in messages.

Below, I'll explain each core method and event type in detail, including their purpose, implementation details, parameters, return values, and integration with the broader system.

### Core Methods

#### 1. `initializePresence(userId: string, userName: string, userAvatar?: string)`
- **Purpose**: Sets up global presence tracking for a user, allowing the system to monitor and broadcast online/offline status across the entire application.
- **Implementation Details**: 
  - Joins a global Supabase channel named `global_presence` using the user's ID as the presence key.
  - Tracks the user's initial state (e.g., visitorId, userName, userAvatar, online_at timestamp) via `presenceChannel.track()`.
  - Listens for presence events: `sync` (initial state sync), `join` (user comes online), and `leave` (user goes offline).
  - Handles errors during subscription and retries if needed.
- **Parameters**: 
  - `userId`: Unique identifier for the user (from MongoDB).
  - `userName`: Display name of the user.
  - `userAvatar` (optional): URL to the user's avatar image.
- **Return Value**: Promise<void> - Resolves when presence is successfully initialized.
- **Integration**: Updates the Redux store with online user lists and triggers UI updates (e.g., green dots on user avatars). Called once per user session in `useCommunications`.

#### 2. `subscribeToChannel(channelId: string, eventHandlers: RealtimeEventHandlers)`
- **Purpose**: Subscribes to a specific chat channel for real-time events, enabling instant updates for messages, reactions, and member changes.
- **Implementation Details**:
  - Creates or reuses a Supabase channel named `rt_${channelId}` with broadcast configuration (e.g., `self: true` for attachments).
  - Prevents duplicate subscriptions by checking existing promises and channels.
  - Subscribes to events like new messages, updates, deletions, typing indicators, reactions, and member changes.
  - Includes connection recovery logic to resubscribe after disconnections.
  - Tracks subscribed channels for reconnection purposes.
- **Parameters**:
  - `channelId`: Unique Supabase UUID of the channel.
  - `eventHandlers`: Object with callback functions for events (e.g., `onNewMessage`, `onTypingStart`).
- **Return Value**: Promise<void> - Resolves when subscription is active.
- **Integration**: Called when a user selects a channel in the UI. Updates Redux with real-time data and triggers UI re-renders.

#### 3. `unsubscribeFromChannel(channelId: string)`
- **Purpose**: Removes a channel subscription to stop receiving real-time updates and free resources.
- **Implementation Details**:
  - Calls `supabase.removeChannel()` on the channel instance.
  - Clears local references (e.g., from `rtChannels` map).
  - Removes from subscription promises and tracked channel IDs.
  - Cleans up typing state for the channel to prevent stale indicators.
- **Parameters**:
  - `channelId`: Unique Supabase UUID of the channel to unsubscribe from.
- **Return Value**: void.
- **Integration**: Triggered when switching channels or closing the app. Ensures no memory leaks and stops unnecessary broadcasts.

#### 4. `sendMessage(channelId: string, messageData: any)`
- **Purpose**: Broadcasts a new message to all subscribers of a channel, enabling instant delivery.
- **Implementation Details**:
  - Ensures the channel is subscribed (subscribes if needed).
  - Sends a `broadcast` event of type `new_message` with the full message payload (including denormalized sender data).
  - Handles errors by logging and potentially retrying.
- **Parameters**:
  - `channelId`: Target channel UUID.
  - `messageData`: Object containing message content, sender info, and metadata.
- **Return Value**: Promise<void>.
- **Integration**: Called after API confirmation in `useCommunications.sendMessage()`. Triggers `onNewMessage` handlers in subscribers' Redux stores.

#### 5. `sendTypingIndicator(channelId: string, userId: string, userName: string)`
- **Purpose**: Sends typing start/stop events with throttling to show user activity without flooding the network.
- **Implementation Details**:
  - Uses debouncing (300ms delay) and throttling (max every 2 seconds) to optimize broadcasts.
  - Sends `typing_start` event with user details; auto-sends `typing_stop` after 3.5 seconds of inactivity.
  - Clears timeouts on stop or channel change.
- **Parameters**:
  - `channelId`: Channel UUID.
  - `userId`: Typing user's ID.
  - `userName`: Typing user's display name.
- **Return Value**: Promise<void>.
- **Integration**: Linked to message input events in `MessageInput`. Updates `typingUsers` in Redux for UI indicators.

#### 6. `sendReaction(channelId: string, messageId: string, emoji: string, userId: string)`
- **Purpose**: Broadcasts emoji reactions (add/remove) to update message reactions in real-time.
- **Implementation Details**:
  - Sends `reaction_added` or `reaction_removed` events based on toggle logic.
  - Includes reaction metadata (e.g., messageId, emoji, userId).
  - Ensures channel subscription before sending.
- **Parameters**:
  - `channelId`: Channel UUID.
  - `messageId`: Target message UUID.
  - `emoji`: Unicode emoji string.
  - `userId`: Reacting user's ID.
- **Return Value**: Promise<void>.
- **Integration**: Triggered by reaction clicks in `MessageReactions`. Updates Redux message state instantly.

#### 7. `updatePresence(state: 'online' | 'away' | 'offline')`
- **Purpose**: Updates and broadcasts a user's presence state to reflect availability.
- **Implementation Details**:
  - Calls `presenceChannel.track()` with updated state (e.g., online_at timestamp).
  - Maintains a heartbeat to keep presence active.
  - Handles state transitions and error logging.
- **Parameters**:
  - `state`: Enum value ('online', 'away', 'offline').
- **Return Value**: Promise<void>.
- **Integration**: Called on app focus/blur or manual status changes. Syncs with global presence for all users.

#### 8. `handleRealtimeEvent(eventType: string, payload: any)`
- **Purpose**: Central dispatcher for all incoming real-time events, routing them to appropriate handlers.
- **Implementation Details**:
  - Matches `eventType` to event handlers (e.g., 'new_message' → `onNewMessage`).
  - Updates Redux store state (e.g., adds messages, updates typing lists).
  - Includes error handling for invalid events.
- **Parameters**:
  - `eventType`: String identifier (e.g., 'new_message').
  - `payload`: Event data object.
- **Return Value**: void.
- **Integration**: Called by Supabase event listeners. Ensures UI stays in sync with real-time data.

### Event Types Handled

These are the primary real-time events processed by `RealtimeManager`. Each event is broadcast via Supabase channels and triggers specific UI/Redux updates.

1. **`new_message`**: Fired when a message is sent. Payload includes full message data (content, sender, timestamp). Triggers `onNewMessage` to add the message to the channel's message list in Redux and UI.

2. **`message_updated`**: Occurs on message edits. Payload has updated message content and edit timestamp. Calls `onMessageUpdate` to replace the message in Redux and highlight changes in the UI.

3. **`message_deleted`**: Triggered by message deletion (soft or hard). Payload includes messageId and deletion metadata. Invokes `onMessageDelete` to remove/hide the message in Redux and UI.

4. **`reaction_added/removed`**: Handles emoji reactions. Payload specifies messageId, emoji, and userId. Updates `onReactionAdd`/`onReactionRemove` to modify reaction counts in Redux and show/hide reaction badges.

5. **`user_typing`**: Indicates typing activity. Payload includes userId, userName, and channelId. Routes to `onTypingStart`/`onTypingStop` to update typing indicators in Redux and display animated dots in the UI.

6. **`presence_changed`**: Tracks user online/offline status. Payload has userId and state. Calls `onUserOnline`/`onUserOffline` to update online user lists in Redux and toggle status indicators.

7. **`channel_updated`**: Fired on channel metadata changes (e.g., name, settings). Payload includes updated channel object. Triggers `onChannelUpdate` to refresh channel info in Redux and UI.

8. **`member_joined/left`**: Manages channel membership changes. Payload details memberId and action. Invokes `onUserJoined`/`onUserLeft` to update member lists in Redux and show notifications.