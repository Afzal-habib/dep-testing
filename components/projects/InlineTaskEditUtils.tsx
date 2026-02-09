"use client"

import React, { memo, useMemo, useState, useCallback } from "react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
  DropdownMenuLabel,
} from "@/components/ui/dropdown-menu"
import {
  Check,
  Clock,
  AlertCircle,
  Loader2,
  Calendar,
  User2,
  ChevronDown,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { useToast } from "@/hooks/use-toast"
import { Input } from "@/components/ui/input"
import { Avatar, AvatarImage, AvatarFallback } from "@/components/ui/avatar"
import { PRIORITY_COLORS, STATUS_COLORS } from "@/lib/colorConstants"

export const priorityIcons: Record<string, React.ComponentType<any>> = {
  low: Clock,
  medium: Clock,
  high: AlertCircle,
  urgent: AlertCircle,
}

// Inline Status Dropdown
interface InlineStatusDropdownProps {
  task: any
  isLoading?: boolean
  canUpdate?: boolean
  onStatusChange: (taskId: string, newStatus: string) => Promise<void>
}

export const InlineStatusDropdown = memo(function InlineStatusDropdown({
  task,
  isLoading = false,
  canUpdate = true,
  onStatusChange,
}: InlineStatusDropdownProps) {
  const { toast } = useToast()
  const [isOpen, setIsOpen] = useState(false)
  const statuses = ["pending", "in-progress", "on-hold", "completed", "closed"]

  const handleStatusChange = async (newStatus: string) => {
    if (newStatus === task.status) {
      setIsOpen(false)
      return
    }

    try {
      await onStatusChange(task._id, newStatus)
      toast({ title: "Success", description: "Status updated successfully" })
      setIsOpen(false)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to update status",
        variant: "destructive",
      })
    }
  }

  return (
    <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          disabled={!canUpdate || isLoading || task.isDeleted}
          className={cn(
            "h-6 px-2 text-xs font-medium",
            STATUS_COLORS[task.status as keyof typeof STATUS_COLORS],
            isLoading && "opacity-60"
          )}
        >
          {isLoading && <Loader2 className="mr-1 h-3 w-3 animate-spin" />}
          <span className="capitalize">{task.status}</span>
          {!isLoading && <ChevronDown className="ml-1 h-3 w-3" />}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-40">
        <DropdownMenuLabel>Change Status</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {statuses.map((status) => (
          <DropdownMenuItem
            key={status}
            onClick={() => handleStatusChange(status)}
            disabled={isLoading || task.isDeleted}
            className={cn(task.status === status && "bg-accent")}
          >
            <Check className={cn("mr-2 h-3 w-3", task.status === status ? "opacity-100" : "opacity-0")} />
            <span className="capitalize">{status}</span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
})

// Inline Priority Dropdown
interface InlinePriorityDropdownProps {
  task: any
  isLoading?: boolean
  canUpdate?: boolean
  onPriorityChange: (taskId: string, newPriority: string) => Promise<void>
}

export const InlinePriorityDropdown = memo(function InlinePriorityDropdown({
  task,
  isLoading = false,
  canUpdate = true,
  onPriorityChange,
}: InlinePriorityDropdownProps) {
  const { toast } = useToast()
  const [isOpen, setIsOpen] = useState(false)
  const priorities = ["low", "medium", "high", "urgent"]

  const handlePriorityChange = async (newPriority: string) => {
    if (newPriority === task.priority) {
      setIsOpen(false)
      return
    }

    try {
      await onPriorityChange(task._id, newPriority)
      toast({ title: "Success", description: "Priority updated successfully" })
      setIsOpen(false)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to update priority",
        variant: "destructive",
      })
    }
  }

  const PriorityIcon = priorityIcons[task.priority as keyof typeof priorityIcons] || Clock

  return (
    <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          disabled={!canUpdate || isLoading || task.isDeleted}
          className={cn(
            "h-6 px-2 text-xs font-medium",
            PRIORITY_COLORS[task.priority as keyof typeof PRIORITY_COLORS],
            isLoading && "opacity-60"
          )}
        >
          {isLoading && <Loader2 className="mr-1 h-3 w-3 animate-spin" />}
          {!isLoading && <PriorityIcon className="mr-1 h-3 w-3" />}
          <span className="capitalize">{task.priority}</span>
          {!isLoading && <ChevronDown className="ml-1 h-3 w-3" />}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-40">
        <DropdownMenuLabel>Change Priority</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {priorities.map((priority) => {
          const Icon = priorityIcons[priority as keyof typeof priorityIcons]
          return (
            <DropdownMenuItem
              key={priority}
              onClick={() => handlePriorityChange(priority)}
              disabled={isLoading}
              className={cn(task.priority === priority && "bg-accent")}
            >
              <Check className={cn("mr-2 h-3 w-3", task.priority === priority ? "opacity-100" : "opacity-0")} />
              <Icon className="mr-2 h-3 w-3" />
              <span className="capitalize">{priority}</span>
            </DropdownMenuItem>
          )
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  )
})

// Inline Due Date Input
interface InlineDueDateInputProps {
  task: any
  isLoading?: boolean
  canUpdate?: boolean
  onDueDateChange: (taskId: string, newDueDate: string) => Promise<void>
}

export const InlineDueDateInput = memo(function InlineDueDateInput({
  task,
  isLoading = false,
  canUpdate = true,
  onDueDateChange,
}: InlineDueDateInputProps) {
  const { toast } = useToast()
  const [isEditing, setIsEditing] = useState(false)
  const [tempDate, setTempDate] = useState(task.dueDate ? new Date(task.dueDate).toISOString().split("T")[0] : "")

  const handleDateChange = async () => {
    if (!tempDate) {
      toast({
        title: "Error",
        description: "Please select a date",
        variant: "destructive",
      })
      return
    }

    try {
      await onDueDateChange(task._id, tempDate)
      toast({ title: "Success", description: "Due date updated successfully" })
      setIsEditing(false)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to update due date",
        variant: "destructive",
      })
    }
  }

  const formattedDate = task.dueDate ? new Date(task.dueDate).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  }) : "No date"

  if (isEditing && canUpdate) {
    return (
      <div className="flex items-center gap-1">
        <Input
          type="date"
          value={tempDate}
          onChange={(e) => setTempDate(e.target.value)}
          disabled={isLoading}
          className="h-6 px-2 text-xs"
        />
        <Button
          size="sm"
          variant="default"
          disabled={isLoading}
          onClick={handleDateChange}
          className="h-6 px-2 text-xs"
        >
          {isLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Check className="h-3 w-3" />}
        </Button>
        <Button
          size="sm"
          variant="ghost"
          disabled={isLoading}
          onClick={() => setIsEditing(false)}
          className="h-6 px-2 text-xs"
        >
          ✕
        </Button>
      </div>
    )
  }

  return (
    <Button
      variant="ghost"
      size="sm"
      disabled={!canUpdate || isLoading || task.isDeleted}
      onClick={() => setIsEditing(true)}
      className="h-6 px-2 text-xs"
    >
      {isLoading && <Loader2 className="mr-1 h-3 w-3 animate-spin" />}
      <Calendar className="mr-1 h-3 w-3" />
      <span>{formattedDate}</span>
    </Button>
  )
})

// Inline Assignee Dropdown
interface InlineAssigneeDropdownProps {
  task: any
  isLoading?: boolean
  assigneeLoading?: boolean
  canUpdate?: boolean
  users?: any[]
  onAssigneeChange: (taskId: string, newAssigneeId: string) => Promise<void>
}

export const InlineAssigneeDropdown = memo(function InlineAssigneeDropdown({
  task,
  isLoading = false,
  assigneeLoading = false,
  canUpdate = true,
  users = [],
  onAssigneeChange,
}: InlineAssigneeDropdownProps) {
  const { toast } = useToast()
  const [isOpen, setIsOpen] = useState(false)
  const [localLoading, setLocalLoading] = useState(false)

  const currentAssignee = useMemo(() => {
    return users.find((u) => u._id === task.assigneeId)
  }, [users, task.assigneeId])

  const handleAssigneeChange = async (newAssigneeId: string) => {
    if (newAssigneeId === task.assigneeId) {
      setIsOpen(false)
      return
    }

    setLocalLoading(true)
    try {
      await onAssigneeChange(task._id, newAssigneeId)
      toast({ title: "Success", description: "Assignee updated successfully" })
      setIsOpen(false)
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Failed to update assignee",
        variant: "destructive",
      })
    } finally {
      setLocalLoading(false)
    }
  }

  const isOperationLoading = isLoading || assigneeLoading || localLoading

  return (
    <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          disabled={!canUpdate || isOperationLoading || task.isDeleted}
          className="h-6 px-1 text-xs"
        >
          {isOperationLoading && (
            <Loader2 className="mr-1 h-3 w-3 animate-spin" />
          )}
          {currentAssignee ? (
            <>
              <Avatar className="h-4 w-4">
                <AvatarImage src={currentAssignee.avatar} />
                <AvatarFallback className="text-xs">
                  {currentAssignee.name ? (() => {
                      const parts = currentAssignee.name.trim().split(' ');
                      if (parts.length === 1) {
                        return parts[0][0].toUpperCase();
                      }
                      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                    })()
                  : ''}
                </AvatarFallback>
              </Avatar>
              <span className="max-w-[100px] truncate">{currentAssignee.name}</span>
            </>
          ) : (
            <span>Unassigned</span>
          )}
          {!isOperationLoading && <ChevronDown className="ml-1 h-3 w-3" />}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-48">
        <DropdownMenuLabel>
          {localLoading ? (
            <div className="flex items-center gap-2">
              <Loader2 className="h-3 w-3 animate-spin" />
              <span>Updating...</span>
            </div>
          ) : assigneeLoading ? (
            <div className="flex items-center gap-2">
              <Loader2 className="h-3 w-3 animate-spin" />
              <span>Loading team members...</span>
            </div>
          ) : (
            "Assign To"
          )}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {assigneeLoading ? (
          <div className="flex items-center justify-center py-4">
            <Loader2 className="h-4 w-4 animate-spin" />
          </div>
        ) : users.length === 0 ? (
          <div className="py-2 px-2 text-xs text-muted-foreground">No team members available</div>
        ) : (
          <>
            <DropdownMenuItem
              onClick={() => handleAssigneeChange("")}
              disabled={isOperationLoading || task.isDeleted}
              className={cn(!task.assigneeId && "bg-accent")}
            >
              <Check className={cn("mr-2 h-3 w-3", !task.assigneeId ? "opacity-100" : "opacity-0")} />
              <span>Unassigned</span>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            {users.map((user) => (
              <DropdownMenuItem
                key={user._id}
                onClick={() => handleAssigneeChange(user._id)}
                disabled={isOperationLoading}
                className={cn(task.assigneeId === user._id && "bg-accent")}
              >
                <Check className={cn("mr-2 h-3 w-3", task.assigneeId === user._id ? "opacity-100" : "opacity-0")} />
                <Avatar className="mr-2 h-4 w-4">
                  <AvatarImage src={user.avatar} />
                  <AvatarFallback className="text-xs">{user.name ? (() => {
                      const parts = user.name.trim().split(' ');
                      if (parts.length === 1) {
                        return parts[0][0].toUpperCase();
                      }
                      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                    })()
                  : ''}</AvatarFallback>
                </Avatar>
                <span className="flex-1 truncate">{user.name}</span>
                {user.email && <span className="ml-2 text-xs text-muted-foreground truncate">{user.email}</span>}
              </DropdownMenuItem>
            ))}
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
})
