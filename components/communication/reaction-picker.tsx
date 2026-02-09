"use client"

// Re-export all reaction-related components from emoji-picker
// This file provides backward compatibility for existing imports

export { 
  EmojiPicker as ReactionPicker,
  QuickReactionBar,
  MessageReactions,
  QUICK_REACTIONS,
  EMOJI_CATEGORIES
} from "./emoji-picker"

export type { } from "./emoji-picker"
