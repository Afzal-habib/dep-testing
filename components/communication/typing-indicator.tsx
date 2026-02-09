"use client"

import { ITypingIndicator } from "@/types/communication"
import { cn } from "@/lib/utils"

interface TypingIndicatorProps {
  typingUsers: ITypingIndicator[]
  currentUserId?: string
  className?: string
}

export function TypingIndicator({
  typingUsers,
  currentUserId,
  className
}: TypingIndicatorProps) {
  // Filter out current user from typing indicators
  const otherTypingUsers = typingUsers.filter(
    (user) => user.userId !== currentUserId
  )

  if (otherTypingUsers.length === 0) {
    return null
  }

  // Format the typing message
  const getTypingMessage = () => {
    const names = otherTypingUsers.map((user) => user.userName)
    
    if (names.length === 1) {
      return `${names[0]} is typing`
    } else if (names.length === 2) {
      return `${names[0]} and ${names[1]} are typing`
    } else if (names.length === 3) {
      return `${names[0]}, ${names[1]}, and ${names[2]} are typing`
    } else {
      return `${names[0]}, ${names[1]}, and ${names.length - 2} others are typing`
    }
  }

  return (
    <div className={cn("flex items-center gap-2 text-xs text-muted-foreground", className)}>
      {/* Animated typing dots */}
      <div className="flex items-center gap-0.5">
        <span 
          className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-bounce" 
          style={{ animationDelay: '0ms', animationDuration: '600ms' }}
        />
        <span 
          className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-bounce" 
          style={{ animationDelay: '150ms', animationDuration: '600ms' }}
        />
        <span 
          className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-bounce" 
          style={{ animationDelay: '300ms', animationDuration: '600ms' }}
        />
      </div>
      
      {/* Typing message */}
      <span className="truncate max-w-[200px]">
        {getTypingMessage()}
      </span>
    </div>
  )
}
