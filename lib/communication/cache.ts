/**
 * Communication Module Cache Layer
 * 
 * Implements a simple in-memory cache with TTL (Time-To-Live) for:
 * - Channel list caching
 * - Message caching per channel
 * - User data caching
 * 
 * This reduces API calls and improves perceived performance.
 */

interface CacheEntry<T> {
  data: T;
  timestamp: number;
  expiresAt: number;
}

interface CacheConfig {
  channelsTTL: number;      // Channels cache TTL in ms (default: 2 minutes)
  messagesTTL: number;      // Messages cache TTL in ms (default: 1 minute)
  userDataTTL: number;      // User data cache TTL in ms (default: 5 minutes)
  maxMessageCacheSize: number; // Max number of channels to cache messages for
}

const DEFAULT_CONFIG: CacheConfig = {
  channelsTTL: 2 * 60 * 1000,      // 2 minutes
  messagesTTL: 1 * 60 * 1000,      // 1 minute
  userDataTTL: 5 * 60 * 1000,      // 5 minutes
  maxMessageCacheSize: 10,         // Cache messages for up to 10 channels
};

class CommunicationCache {
  private channelsCache: CacheEntry<any[]> | null = null;
  private messagesCache: Map<string, CacheEntry<any[]>> = new Map();
  private userDataCache: Map<string, CacheEntry<any>> = new Map();
  private config: CacheConfig;
  
  // Generic key-value cache for operations.ts
  private genericCache: Map<string, CacheEntry<any>> = new Map();

  constructor(config: Partial<CacheConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    
    // Run cleanup periodically (server-side only)
    if (typeof window === 'undefined') {
      setInterval(() => this.cleanup(), 30000);
    }
  }

  // ============================================
  // Generic Key-Value Cache (for operations.ts)
  // ============================================

  /**
   * Get cached value if not expired
   */
  get<T>(key: string): T | null {
    const entry = this.genericCache.get(key) as CacheEntry<T> | undefined;
    if (!entry) return null;

    if (Date.now() > entry.expiresAt) {
      this.genericCache.delete(key);
      return null;
    }

    return entry.data;
  }

  /**
   * Set value with TTL (default 60 seconds)
   */
  set<T>(key: string, data: T, ttl: number = 60000): void {
    this.genericCache.set(key, {
      data,
      timestamp: Date.now(),
      expiresAt: Date.now() + ttl
    });
  }

  /**
   * Delete single key
   */
  delete(key: string): void {
    this.genericCache.delete(key);
  }

  /**
   * Invalidate by pattern (e.g., 'channel:*' invalidates all channel caches)
   * Supports simple wildcard patterns with *
   */
  invalidate(pattern: string): void {
    if (pattern.includes('*')) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
      for (const key of this.genericCache.keys()) {
        if (regex.test(key)) {
          this.genericCache.delete(key);
        }
      }
    } else {
      // Exact match
      this.genericCache.delete(pattern);
    }
  }

  /**
   * Clean up expired entries from all caches
   */
  private cleanup(): void {
    const now = Date.now();
    
    // Clean generic cache
    for (const [key, entry] of this.genericCache.entries()) {
      if (now > entry.expiresAt) {
        this.genericCache.delete(key);
      }
    }
    
    // Clean messages cache
    for (const [key, entry] of this.messagesCache.entries()) {
      if (now > entry.expiresAt) {
        this.messagesCache.delete(key);
      }
    }
    
    // Clean user data cache
    for (const [key, entry] of this.userDataCache.entries()) {
      if (now > entry.expiresAt) {
        this.userDataCache.delete(key);
      }
    }
    
    // Clean channels cache
    if (this.channelsCache && now > this.channelsCache.expiresAt) {
      this.channelsCache = null;
    }
  }

  // ============================================
  // Channels Cache
  // ============================================

  setChannels(channels: any[]): void {
    // Create copies to avoid sharing references with Redux state
    this.channelsCache = {
      data: channels.map(c => ({ ...c })),
      timestamp: Date.now(),
      expiresAt: Date.now() + this.config.channelsTTL,
    };
  }

  getChannels(): any[] | null {
    if (!this.channelsCache) return null;
    
    if (Date.now() > this.channelsCache.expiresAt) {
      this.channelsCache = null;
      return null;
    }
    
    // Return copies to avoid sharing references with Redux state
    return this.channelsCache.data.map(c => ({ ...c }));
  }

  invalidateChannels(): void {
    this.channelsCache = null;
  }

  updateChannelInCache(channelId: string, updates: Partial<any>): void {
    if (!this.channelsCache) return;
    
    const channels = this.channelsCache.data;
    const index = channels.findIndex(c => c.id === channelId);
    
    if (index !== -1) {
      // Create new array to avoid mutating frozen/readonly arrays
      const newChannels = [...channels];
      newChannels[index] = { ...channels[index], ...updates };
      this.channelsCache.data = newChannels;
    }
  }

  addChannelToCache(channel: any): void {
    // If there's no cache yet, initialize it with this channel so
    // real-time additions are preserved for subsequent reads.
    if (!this.channelsCache) {
      this.setChannels([channel])
      return
    }

    // Add a copy to beginning of list
    this.channelsCache.data = [{ ...channel }, ...this.channelsCache.data];
  }

  removeChannelFromCache(channelId: string): void {
    if (!this.channelsCache) return;
    
    this.channelsCache.data = this.channelsCache.data.filter(c => c.id !== channelId);
    // Also remove messages cache for this channel
    this.messagesCache.delete(channelId);
  }

  // ============================================
  // Messages Cache
  // ============================================

  setMessages(channelId: string, messages: any[]): void {
    // Enforce max cache size - remove oldest entries
    if (this.messagesCache.size >= this.config.maxMessageCacheSize) {
      const oldestKey = this.messagesCache.keys().next().value;
      if (oldestKey) {
        this.messagesCache.delete(oldestKey);
      }
    }

    // Create copies to avoid sharing references with Redux state
    this.messagesCache.set(channelId, {
      data: messages.map(m => ({ ...m })),
      timestamp: Date.now(),
      expiresAt: Date.now() + this.config.messagesTTL,
    });
  }

  getMessages(channelId: string): any[] | null {
    const entry = this.messagesCache.get(channelId);
    
    if (!entry) return null;
    
    if (Date.now() > entry.expiresAt) {
      this.messagesCache.delete(channelId);
      return null;
    }
    
    // Return copies to avoid sharing references with Redux state
    return entry.data.map(m => ({ ...m }));
  }

  addMessageToCache(channelId: string, message: any): void {
    const entry = this.messagesCache.get(channelId);
    if (!entry) return;
    
    // Add a copy to end of messages (newest)
    entry.data = [...entry.data, { ...message }];
  }

  updateMessageInCache(channelId: string, messageId: string, updates: Partial<any>): void {
    const entry = this.messagesCache.get(channelId);
    if (!entry) return;
    
    const index = entry.data.findIndex((m: any) => m.id === messageId);
    if (index !== -1) {
      // Create new array to avoid mutation
      const newData = [...entry.data];
      newData[index] = { ...entry.data[index], ...updates };
      entry.data = newData;
    }
  }

  removeMessageFromCache(channelId: string, messageId: string): void {
    const entry = this.messagesCache.get(channelId);
    if (!entry) return;
    
    entry.data = entry.data.filter((m: any) => m.id !== messageId);
  }

  invalidateMessages(channelId: string): void {
    this.messagesCache.delete(channelId);
  }

  // ============================================
  // User Data Cache
  // ============================================

  setUserData(userId: string, userData: any): void {
    this.userDataCache.set(userId, {
      data: userData,
      timestamp: Date.now(),
      expiresAt: Date.now() + this.config.userDataTTL,
    });
  }

  getUserData(userId: string): any | null {
    const entry = this.userDataCache.get(userId);
    
    if (!entry) return null;
    
    if (Date.now() > entry.expiresAt) {
      this.userDataCache.delete(userId);
      return null;
    }
    
    return entry.data;
  }

  setAllUsersData(users: any[]): void {
    users.forEach(user => {
      this.setUserData(user._id || user.id, user);
    });
  }

  getAllCachedUsers(): any[] {
    const now = Date.now();
    const validUsers: any[] = [];
    
    this.userDataCache.forEach((entry, userId) => {
      if (now <= entry.expiresAt) {
        validUsers.push(entry.data);
      } else {
        this.userDataCache.delete(userId);
      }
    });
    
    return validUsers;
  }

  // ============================================
  // Utility Methods
  // ============================================

  clearAll(): void {
    this.channelsCache = null;
    this.messagesCache.clear();
    this.userDataCache.clear();
    this.genericCache.clear();
  }

  getStats(): {
    channelsCached: boolean;
    channelsAge: number | null;
    messagesChannelCount: number;
    usersCached: number;
    genericCacheSize: number;
  } {
    return {
      channelsCached: this.channelsCache !== null,
      channelsAge: this.channelsCache 
        ? Date.now() - this.channelsCache.timestamp 
        : null,
      messagesChannelCount: this.messagesCache.size,
      usersCached: this.userDataCache.size,
      genericCacheSize: this.genericCache.size,
    };
  }

  // Prefetch messages for likely channels (e.g., recent or active)
  async prefetchMessages(
    channelIds: string[], 
    fetchFn: (channelId: string) => Promise<any[]>
  ): Promise<void> {
    const promises = channelIds
      .slice(0, 3) // Only prefetch top 3
      .filter(id => !this.getMessages(id))
      .map(async id => {
        try {
          const messages = await fetchFn(id);
          this.setMessages(id, messages);
        } catch {
          // Ignore prefetch errors
        }
      });
    
    await Promise.all(promises);
  }
}

// Export singleton instance
export const communicationCache = new CommunicationCache();

// Export class for testing or custom instances
export { CommunicationCache, type CacheConfig };
