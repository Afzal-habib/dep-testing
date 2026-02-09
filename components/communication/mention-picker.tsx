"use client"

import { useState, useRef, useEffect, useMemo } from "react"
import { Input } from "@/components/ui/input"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import { Search, Users, X } from "lucide-react"
import { IParticipant, IChannelMember } from "@/types/communication"

interface MentionUser {
  id: string
  name: string
  email?: string
  avatar?: string
  isOnline?: boolean
}

interface MentionPickerProps {
  users: (IParticipant | IChannelMember | MentionUser)[]
  onSelect: (user: MentionUser | { id: "everyone"; name: "everyone" }) => void
  onClose: () => void
  searchQuery?: string
  onSearchChange?: (query: string) => void
  className?: string
  showEveryone?: boolean // Allow @everyone mention
  channelType?: string // Channel type to determine if mentions are allowed
  disabled?: boolean // Disable mentions for certain channel types
}

export function MentionPicker({
  users,
  onSelect,
  onClose,
  searchQuery = "",
  onSearchChange,
  className,
  showEveryone = true,
  channelType,
  disabled = false
}: MentionPickerProps) {
  
  // Check if mentions are disabled for this channel type (like WhatsApp groups vs DMs)
  const mentionsDisabled = disabled || channelType === 'dm' || channelType === 'client-support'
  
  // Early return if mentions are disabled
  if (mentionsDisabled) {
    return null
  }
  const [localSearchQuery, setLocalSearchQuery] = useState(searchQuery)
  const pickerRef = useRef<HTMLDivElement>(null)
  const searchInputRef = useRef<HTMLInputElement>(null)
  const [selectedIndex, setSelectedIndex] = useState(0)

  // Normalize users to consistent format
  const normalizedUsers = useMemo(() => {
    return users.map(user => {
      if ('mongo_member_id' in user) {
        return {
          id: user.mongo_member_id,
          name: user.name,
          email: user.email,
          avatar: user.avatar,
          isOnline: user.isOnline
        }
      }
      return user as MentionUser
    })
  }, [users])

  // Filter users based on search
  const filteredUsers = useMemo(() => {
    const query = localSearchQuery.toLowerCase()
    return normalizedUsers.filter(user =>
      user.name?.toLowerCase().includes(query) ||
      user.email?.toLowerCase().includes(query)
    )
  }, [normalizedUsers, localSearchQuery])

  // Build options list (everyone + filtered users) - only for group channels
  const options = useMemo(() => {
    const result: Array<MentionUser | { id: "everyone"; name: "everyone"; isSpecial: true }> = []
    
    // Only show @everyone for group channels, not DMs or client support
    const canShowEveryone = showEveryone && 
      channelType !== 'dm' && 
      channelType !== 'client-support' && 
      filteredUsers.length > 1 // Only show @everyone if there are multiple users
    
    if (canShowEveryone && (!localSearchQuery || "everyone".includes(localSearchQuery.toLowerCase()))) {
      result.push({ id: "everyone", name: "everyone", isSpecial: true })
    }
    
    return [...result, ...filteredUsers]
  }, [filteredUsers, showEveryone, localSearchQuery, channelType])

  // Focus search on mount
  useEffect(() => {
    searchInputRef.current?.focus()
  }, [])

  // Close on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (pickerRef.current && !pickerRef.current.contains(e.target as Node)) {
        onClose()
      }
    }
    document.addEventListener("mousedown", handleClickOutside)
    return () => document.removeEventListener("mousedown", handleClickOutside)
  }, [onClose])

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose()
      } else if (e.key === "ArrowDown") {
        e.preventDefault()
        setSelectedIndex(prev => Math.min(prev + 1, options.length - 1))
      } else if (e.key === "ArrowUp") {
        e.preventDefault()
        setSelectedIndex(prev => Math.max(prev - 1, 0))
      } else if (e.key === "Enter" && options[selectedIndex]) {
        e.preventDefault()
        handleSelect(options[selectedIndex])
      }
    }
    document.addEventListener("keydown", handleKeyDown)
    return () => document.removeEventListener("keydown", handleKeyDown)
  }, [onClose, options, selectedIndex])

  // Reset selected index when options change
  useEffect(() => {
    setSelectedIndex(0)
  }, [options.length])

  const handleSearchChange = (value: string) => {
    setLocalSearchQuery(value)
    onSearchChange?.(value)
  }

  const handleSelect = (option: MentionUser | { id: "everyone"; name: "everyone"; isSpecial?: true }) => {
    onSelect(option)
    onClose()
  }

  const getInitials = (name?: string) => {
    if (!name) return "?"
    const parts = name.trim().split(" ")
    if (parts.length === 1) return parts[0][0].toUpperCase()
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase()
  }

  return (
    <div
      ref={pickerRef}
      className={cn(
        "absolute bottom-full mb-2 left-0 w-72 bg-card border rounded-lg shadow-lg z-50",
        className
      )}
    >
      {/* Header with search */}
      <div className="p-2 border-b">
        <div className="relative">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            ref={searchInputRef}
            value={localSearchQuery}
            onChange={(e) => handleSearchChange(e.target.value)}
            placeholder="Search members..."
            className="pl-8 pr-8 h-8 text-sm"
          />
          {localSearchQuery && (
            <button
              onClick={() => handleSearchChange("")}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>

      {/* Options list */}
      <ScrollArea className="max-h-64">
        {options.length === 0 ? (
          <p className="text-center text-sm text-muted-foreground py-4">
            No members found
          </p>
        ) : (
          <div className="py-1">
            {options.map((option, index) => {
              const isEveryone = 'isSpecial' in option && option.isSpecial
              
              return (
                <button
                  key={option.id}
                  onClick={() => handleSelect(option)}
                  className={cn(
                    "w-full flex items-center gap-3 px-3 py-2 text-left transition-colors",
                    index === selectedIndex ? "bg-accent" : "hover:bg-muted"
                  )}
                >
                  {isEveryone ? (
                    <>
                      <div className="h-8 w-8 rounded-full bg-primary/10 flex items-center justify-center">
                        <Users className="h-4 w-4 text-primary" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-sm">@everyone</p>
                        <p className="text-xs text-muted-foreground">
                          Notify all members in this channel
                        </p>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="relative">
                        <Avatar className="h-8 w-8">
                          <AvatarImage src={(option as MentionUser).avatar} alt={(option as MentionUser).name} />
                          <AvatarFallback className="text-xs">
                            {getInitials((option as MentionUser).name)}
                          </AvatarFallback>
                        </Avatar>
                        {(option as MentionUser).isOnline && (
                          <div className="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full bg-emerald-500 border-2 border-background" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-sm truncate">{(option as MentionUser).name}</p>
                        {(option as MentionUser).email && (
                          <p className="text-xs text-muted-foreground truncate">
                            {(option as MentionUser).email}
                          </p>
                        )}
                      </div>
                    </>
                  )}
                </button>
              )
            })}
          </div>
        )}
      </ScrollArea>

      {/* Footer hint */}
      <div className="px-3 py-2 border-t bg-muted/30">
        <p className="text-xs text-muted-foreground">
          Use <kbd className="px-1 bg-muted rounded">↑</kbd> <kbd className="px-1 bg-muted rounded">↓</kbd> to navigate, <kbd className="px-1 bg-muted rounded">Enter</kbd> to select
        </p>
      </div>
    </div>
  )
}
