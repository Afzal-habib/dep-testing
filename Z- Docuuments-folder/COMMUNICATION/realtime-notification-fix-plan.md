    # Realtime Notification Fix Plan

## Date: January 3, 2026

## Problem Analysis

### Root Cause Identified from Logs
    
The receiver side logs reveal the **critical issue**:

```
realtime-manager.ts:385 🔔 Notification channel notifications_69497a2f985d04b802e2ccd5 status: CLOSED
...
realtime-manager.ts:452 🔔 Unsubscribed from notifications
realtime-manager.ts:457 📢 Unsubscribed from user channels
```

**The notification channel is getting CLOSED during React component remounts!**

### Problem Chain:

1. **Initial subscription works** - `subscribeToNotifications` is called and subscribes
2. **React Fast Refresh / component remount happens** - This triggers effect cleanup
3. **Notification channel status becomes CLOSED** - The Supabase channel is closed
4. **`hasInitialized.current` is still `true`** - The ref persists across remounts
5. **Re-subscription is blocked** - Code says "Already subscribed" but channel is actually closed
6. **User receives no notifications** - Because the channel is closed

### Detailed Issue Breakdown:

#### Issue 1: Notification Channel Lifecycle Bug
- The `RealtimeProvider` component has a cleanup function that does nothing (intentionally)
- BUT the `useCommunications` hook has cleanup that unsubscribes from channels
- When navigating or Fast Refresh happens, the `unsubscribeFromNotifications()` is called
- This closes the notification channel permanently

#### Issue 2: hasInitialized.current Stale State
- After cleanup, `hasInitialized.current` remains `true`
- Next render skips re-initialization because of this check
- Result: No active subscription, but code thinks there is one

#### Issue 3: "Already subscribed" Check is Wrong
- In `subscribeToNotifications()`, it checks if `this.notificationChannel` exists
- But having a channel object doesn't mean it's actively subscribed
- The channel might be in CLOSED state

#### Issue 4: Multiple Effect Runs
- The logs show multiple presence sync calls (5+ times)
- This indicates useEffect is running multiple times
- Likely due to missing/wrong dependencies or StrictMode double-mounting

## Solution Plan

### Fix 1: Check Channel State, Not Just Existence

**File:** `lib/realtime-manager.ts`

```typescript
// BEFORE:
async subscribeToNotifications(userId: string): Promise<void> {
  if (this.notificationChannel) {
    console.log('🔔 Already subscribed to notifications for user:', userId)
    return
  }

// AFTER:
async subscribeToNotifications(userId: string): Promise<void> {
  // Check if channel exists AND is actively subscribed
  if (this.notificationChannel) {
    const state = this.notificationChannel.state
    if (state === 'joined' || state === 'joining') {
      console.log('🔔 Already subscribed to notifications for user:', userId)
      return
    }
    // Channel exists but not active - remove it and resubscribe
    console.log('🔔 Notification channel exists but state is:', state, '- resubscribing')
    supabase.removeChannel(this.notificationChannel)
    this.notificationChannel = null
  }
```

### Fix 2: Never Unsubscribe Notifications in Component Cleanup

**File:** `hooks/use-communications.ts`

The cleanup effect should NOT unsubscribe from notifications - only from specific channel subscriptions. The RealtimeProvider manages notification subscriptions.

### Fix 3: Track Subscription State Properly

**File:** `lib/realtime-manager.ts`

Add a proper state tracking mechanism:

```typescript
private notificationSubscriptionState: 'idle' | 'subscribing' | 'subscribed' | 'error' = 'idle'

async subscribeToNotifications(userId: string): Promise<void> {
  if (this.notificationSubscriptionState === 'subscribed' || 
      this.notificationSubscriptionState === 'subscribing') {
    console.log('🔔 Notification subscription in progress or active')
    return
  }
  
  this.notificationSubscriptionState = 'subscribing'
  // ... subscription logic
  
  // On success:
  this.notificationSubscriptionState = 'subscribed'
  
  // On error:
  this.notificationSubscriptionState = 'error'
}
```

### Fix 4: Reset hasInitialized When Appropriate

**File:** `components/providers/realtime-provider.tsx`

```typescript
// Don't use hasInitialized.current for preventing re-subscription
// Instead, let the RealtimeManager handle deduplication

useEffect(() => {
  if (!userId) return
  
  // Always try to subscribe - RealtimeManager will handle deduplication
  const realtimeManager = getRealtimeManager(eventHandlers)
  
  realtimeManager.initializePresence(userId, userName, userAvatar)
  realtimeManager.subscribeToNotifications(userId)
  
  // Cleanup: Only cleanup when user actually logs out
  return () => {
    // Don't unsubscribe here - let RealtimeManager manage lifecycle
  }
}, [userId]) // Only depend on userId
```

### Fix 5: Add Reconnection Logic

**File:** `lib/realtime-manager.ts`

When channel state changes to CLOSED unexpectedly, auto-reconnect:

```typescript
channel.subscribe((status) => {
  if (status === 'CLOSED') {
    // This shouldn't happen during normal operation
    console.warn('🔔 Notification channel unexpectedly closed, reconnecting...')
    this.notificationChannel = null
    this.notificationSubscriptionState = 'idle'
    // Auto-reconnect after short delay
    setTimeout(() => {
      if (this.currentUserId) {
        this.subscribeToNotifications(this.currentUserId)
      }
    }, 1000)
  }
})
```

## Implementation Order

1. **Fix realtime-manager.ts** - Add proper state checking and reconnection
2. **Fix use-communications.ts** - Remove notification unsubscription from cleanup
3. **Fix realtime-provider.tsx** - Simplify initialization logic
4. **Test the complete flow**

## Success Criteria

1. ✅ Sender sends message - sees "Skipping message from self" log
2. ✅ Server broadcasts to recipients - logs show successful broadcast
3. ✅ Receiver gets notification in real-time WITHOUT refresh
4. ✅ Fast Refresh doesn't break notifications
5. ✅ Page navigation doesn't break notifications
6. ✅ No duplicate notifications
7. ✅ No self-notifications

## Testing Steps

1. Open two browsers with different users
2. User A sends message to User B
3. **Check User B's console** for:
   - `📨 Received new message notification`
   - `📨 RealtimeProvider: onNewMessageNotification called`
4. Verify toast notification appears
5. Trigger Fast Refresh on receiver
6. Send another message
7. Verify notifications still work

---

## Implementation Starting Now

## ✅ FIXES APPLIED

### Fix 1: realtime-manager.ts - Channel State Checking
**Problem:** `subscribeToNotifications()` only checked if `this.notificationChannel` exists, not if it's actively connected.

**Solution:** 
- Now checks `channel.state` to see if it's 'joined' or 'joining'
- If channel exists but state is CLOSED, it removes and resubscribes
- Added `notificationUserId` to track the user for auto-reconnection
- Added auto-reconnect logic when channel unexpectedly closes

### Fix 2: use-communications.ts - Removed Destructive Cleanup
**Problem:** The useEffect cleanup was calling `realtimeManager.unsubscribeFromNotifications()` which was destroying the notification subscription on every component remount.

**Solution:**
- Removed the cleanup function that was unsubscribing
- Added comment explaining notifications should persist for the entire session
- The RealtimeProvider now manages the global lifecycle

### Fix 3: realtime-provider.tsx - Better Initialization Tracking  
**Problem:** `hasInitialized.current` was a simple boolean that didn't track WHICH user was initialized, causing issues on logout/login cycles.

**Solution:**
- Changed from `hasInitialized` boolean to `initializedUserIdRef` that tracks the actual user ID
- On logout (userId becomes null), resets the initialization state
- On login with same user, skips re-initialization
- On login with different user, reinitializes properly
- Added error recovery: if initialization fails, resets state so it can retry

### Fix 4: subscribeToUserChannels - Same Pattern Applied
Applied the same channel state checking pattern to `subscribeToUserChannels()` for consistency.

## Testing Instructions

1. **Open two browsers with different users**
2. **Check receiver console after page load** for:
   - `🔔 Notification channel notifications_<userId> status: SUBSCRIBED`
   - `✅ Notification channel subscribed successfully`

3. **Trigger a Fast Refresh on receiver** (save a file)
4. **Check console** - should NOT show:
   - `🔔 Unsubscribed from notifications` 
   - Should show: `🔔 Already subscribed to notifications`

5. **Send message from sender**
6. **Receiver console should show**:
   - `📨 Received new message notification on channel: notifications_<userId>`
   - `📨 Handler exists, calling onNewMessageNotification`
   - `📨 RealtimeProvider: onNewMessageNotification called with data: {...}`

7. **Verify toast notification appears on receiver**

8. **Sender console should show**:
   - `Skipping message from self`

## Success Criteria

- ✅ Notifications persist across Fast Refresh
- ✅ Notifications persist across page navigation
- ✅ Sender does NOT receive self-notifications
- ✅ Receiver gets notifications in real-time
- ✅ Auto-reconnect works if channel closes unexpectedly
