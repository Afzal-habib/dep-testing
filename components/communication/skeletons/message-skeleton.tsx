"use client"

import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"

interface MessageSkeletonProps {
  count?: number
  className?: string
}

export function MessageSkeleton({ count = 5, className }: MessageSkeletonProps) {
  return (
    <div className={cn("space-y-4 p-4", className)}>
      {Array.from({ length: count }).map((_, index) => (
        <MessageItemSkeleton 
          key={index} 
          isOwnMessage={index % 3 === 0} // Vary alignment
          hasReactions={index % 2 === 0}
        />
      ))}
    </div>
  )
}

interface MessageItemSkeletonProps {
  isOwnMessage?: boolean
  hasReactions?: boolean
  className?: string
}

export function MessageItemSkeleton({ 
  isOwnMessage = false, 
  hasReactions = false,
  className 
}: MessageItemSkeletonProps) {
  return (
    <div 
      className={cn(
        "flex gap-3",
        isOwnMessage ? "flex-row-reverse" : "flex-row",
        className
      )}
    >
      {/* Avatar */}
      <Skeleton className="h-10 w-10 rounded-full flex-shrink-0" />
      
      <div className={cn(
        "flex flex-col gap-1 max-w-[70%]",
        isOwnMessage ? "items-end" : "items-start"
      )}>
        {/* Header - name and time */}
        <div className="flex items-center gap-2">
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-3 w-12" />
        </div>
        
        {/* Message bubble */}
        <Skeleton 
          className={cn(
            "h-16 rounded-2xl",
            isOwnMessage ? "rounded-br-sm" : "rounded-bl-sm",
            // Vary widths for realism
            Math.random() > 0.5 ? "w-[280px]" : "w-[200px]"
          )} 
        />
        
        {/* Reactions */}
        {hasReactions && (
          <div className="flex gap-1 mt-1">
            <Skeleton className="h-5 w-10 rounded-full" />
            <Skeleton className="h-5 w-12 rounded-full" />
          </div>
        )}
      </div>
    </div>
  )
}

// Skeleton for thread replies loading
export function ThreadRepliesSkeleton({ count = 3 }: { count?: number }) {
  return (
    <div className="space-y-3 pl-6 border-l-2 border-muted ml-12 mt-2">
      {Array.from({ length: count }).map((_, index) => (
        <div key={index} className="flex gap-2">
          <Skeleton className="h-6 w-6 rounded-full flex-shrink-0" />
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Skeleton className="h-3 w-16" />
              <Skeleton className="h-2 w-10" />
            </div>
            <Skeleton className="h-10 w-[180px] rounded-xl" />
          </div>
        </div>
      ))}
    </div>
  )
}

// Typing indicator skeleton
export function TypingIndicatorSkeleton() {
  return (
    <div className="flex items-center gap-2 p-2 text-muted-foreground">
      <div className="flex gap-1">
        <Skeleton className="h-2 w-2 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
        <Skeleton className="h-2 w-2 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
        <Skeleton className="h-2 w-2 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
      </div>
      <Skeleton className="h-3 w-32" />
    </div>
  )
}

export default MessageSkeleton
