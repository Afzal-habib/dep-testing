"use client"

import { Skeleton } from "@/components/ui/skeleton"
import { cn } from "@/lib/utils"

interface ChannelListSkeletonProps {
  count?: number
  className?: string
}

export function ChannelListSkeleton({ count = 6, className }: ChannelListSkeletonProps) {
  return (
    <div className={cn("space-y-1 p-2", className)}>
      {/* Header skeleton */}
      <div className="flex items-center justify-between px-2 py-3">
        <Skeleton className="h-5 w-24" />
        <Skeleton className="h-6 w-6 rounded" />
      </div>
      
      {/* Search skeleton */}
      <div className="px-2 py-2">
        <Skeleton className="h-9 w-full rounded-md" />
      </div>
      
      {/* Channel items */}
      {Array.from({ length: count }).map((_, index) => (
        <ChannelItemSkeleton 
          key={index}
          hasUnread={index < 2}
          isGroup={index % 3 === 0}
        />
      ))}
    </div>
  )
}

interface ChannelItemSkeletonProps {
  hasUnread?: boolean
  isGroup?: boolean
  className?: string
}

export function ChannelItemSkeleton({ 
  hasUnread = false, 
  isGroup = false,
  className 
}: ChannelItemSkeletonProps) {
  return (
    <div 
      className={cn(
        "flex items-center gap-3 p-3 rounded-lg",
        hasUnread && "bg-muted/30",
        className
      )}
    >
      {/* Avatar */}
      <Skeleton 
        className={cn(
          "flex-shrink-0",
          isGroup ? "h-10 w-10 rounded-lg" : "h-10 w-10 rounded-full"
        )} 
      />
      
      {/* Content */}
      <div className="flex-1 min-w-0 space-y-1">
        <div className="flex items-center justify-between">
          {/* Channel name */}
          <Skeleton className="h-4 w-28" />
          {/* Time */}
          <Skeleton className="h-3 w-10" />
        </div>
        
        <div className="flex items-center justify-between">
          {/* Last message */}
          <Skeleton className="h-3 w-36" />
          {/* Unread badge */}
          {hasUnread && (
            <Skeleton className="h-5 w-5 rounded-full" />
          )}
        </div>
      </div>
    </div>
  )
}

// Skeleton for channel section headers
export function ChannelSectionSkeleton() {
  return (
    <div className="px-3 py-2">
      <Skeleton className="h-4 w-20" />
    </div>
  )
}

// Full sidebar skeleton
export function SidebarSkeleton() {
  return (
    <div className="flex flex-col h-full">
      {/* User info skeleton */}
      <div className="p-4 border-b">
        <div className="flex items-center gap-3">
          <Skeleton className="h-10 w-10 rounded-full" />
          <div className="space-y-1">
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-3 w-16" />
          </div>
        </div>
      </div>
      
      {/* Channels section */}
      <div className="flex-1 overflow-hidden">
        <ChannelSectionSkeleton />
        <ChannelListSkeleton count={4} />
        
        <ChannelSectionSkeleton />
        <ChannelListSkeleton count={3} />
      </div>
    </div>
  )
}

export default ChannelListSkeleton
