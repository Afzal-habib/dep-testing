"use client"

import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { IParticipant } from "@/types/communication"
import { cn } from "@/lib/utils"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"

interface OnlineIndicatorProps {
  users: IParticipant[]
  onlineUserIds?: string[] // Real-time online user IDs from Supabase presence
  currentUserId?: string // Current user to exclude from online count
  maxVisible?: number
  showNames?: boolean
  size?: "sm" | "md" | "lg"
  className?: string
}

export function OnlineIndicator({
  users,
  onlineUserIds = [],
  currentUserId,
  maxVisible = 5,
  showNames = false,
  size = "md",
  className
}: OnlineIndicatorProps) {
  // Determine if user is online based on real-time onlineUserIds from Supabase
  const isUserOnline = (user: IParticipant) => {
    return onlineUserIds.length > 0 
      ? onlineUserIds.includes(user.mongo_member_id) 
      : user.isOnline
  }

  // Filter out current user from the list before checking online status
  const filteredUsers = currentUserId 
    ? users.filter(u => u.mongo_member_id !== currentUserId)
    : users
  
  const onlineUsers = filteredUsers.filter(isUserOnline)
  const visibleUsers = onlineUsers.slice(0, maxVisible)
  const remainingCount = onlineUsers.length - visibleUsers.length

  const sizeClasses = {
    sm: "h-6 w-6",
    md: "h-8 w-8",
    lg: "h-10 w-10"
  }

  // WhatsApp-style ring size based on avatar size
  const ringClasses = {
    sm: "ring-2 ring-offset-1",
    md: "ring-2 ring-offset-2",
    lg: "ring-[3px] ring-offset-2"
  }

  const textSizeClasses = {
    sm: "text-xs",
    md: "text-sm",
    lg: "text-base"
  }

  if (onlineUsers.length === 0) {
    return (
      <div className={cn("flex items-center gap-2 text-muted-foreground", textSizeClasses[size], className)}>
        <div className="h-2 w-2 rounded-full bg-gray-400" />
        <span>No one online</span>
      </div>
    )
  }

  return (
    <TooltipProvider>
      <div className={cn("flex items-center gap-2", className)}>
        {/* Online indicator dot */}
        <div className="flex items-center gap-1">
          <div className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className={cn("text-muted-foreground", textSizeClasses[size])}>
            {onlineUsers.length} online
          </span>
        </div>

        {/* User avatars with WhatsApp-style green ring */}
        <div className="flex -space-x-2">
          {visibleUsers.map((user) => (
            <Tooltip key={user.mongo_member_id}>
              <TooltipTrigger>
                <div className="relative">
                  <Avatar className={cn(
                    sizeClasses[size], 
                    "border-2 border-background",
                    // WhatsApp-style green ring for online users
                    ringClasses[size],
                    "ring-emerald-500 ring-offset-background"
                  )}>
                    <AvatarImage src={user.avatar} alt={user.name} />
                    <AvatarFallback className={textSizeClasses[size]}>
                      {user.name
                        ? (() => {
                          const parts = user.name.trim().split(' ');
                          if (parts.length === 1) {
                            return parts[0][0].toUpperCase();
                          }
                          return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                        })()
                        : ''}
                    </AvatarFallback>
                  </Avatar>
                  {/* Online dot indicator */}
                  <div className="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full bg-emerald-500 border-2 border-background animate-pulse" />
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <div className="text-center">
                  <p className="font-medium">{user.name}</p>
                  {user.role && (
                    <p className="text-xs text-muted-foreground">{user.role}</p>
                  )}
                  <Badge variant="outline" className="text-xs mt-1">
                    {user.userType}
                  </Badge>
                </div>
              </TooltipContent>
            </Tooltip>
          ))}

          {remainingCount > 0 && (
            <Tooltip>
              <TooltipTrigger>
                <div className={cn(
                  "flex items-center justify-center rounded-full bg-muted border-2 border-background",
                  sizeClasses[size]
                )}>
                  <span className={cn("font-medium text-muted-foreground", textSizeClasses[size])}>
                    +{remainingCount}
                  </span>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <div className="space-y-1">
                  {onlineUsers.slice(maxVisible).map(user => (
                    <div key={user.mongo_member_id} className="text-sm">
                      {user.name}
                    </div>
                  ))}
                </div>
              </TooltipContent>
            </Tooltip>
          )}
        </div>

        {/* Names list (optional) */}
        {showNames && (
          <div className="flex flex-wrap gap-1">
            {visibleUsers.map((user, index) => (
              <span key={user.mongo_member_id} className={cn("text-muted-foreground", textSizeClasses[size])}>
                {user.name}
                {index < visibleUsers.length - 1 && ", "}
              </span>
            ))}
            {remainingCount > 0 && (
              <span className={cn("text-muted-foreground", textSizeClasses[size])}>
                and {remainingCount} more
              </span>
            )}
          </div>
        )}
      </div>
    </TooltipProvider>
  )
}