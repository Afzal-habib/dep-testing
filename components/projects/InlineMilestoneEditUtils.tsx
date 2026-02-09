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
  ChevronDown,
  Target,
  Timer,
  CheckCircle,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { useToast } from "@/hooks/use-toast"
import { Input } from "@/components/ui/input"

// Color configurations for milestones
export const milestoneStatusColors: Record<string, string> = {
  pending: "bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700",
  "in-progress": "bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800",
  completed: "bg-emerald-100 text-emerald-800 border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800",
  "on-hold": "bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-900/20 dark:text-amber-400 dark:border-amber-800",
}

export const milestonePriorityColors: Record<string, string> = {
  low: "bg-green-50 text-green-700 border-green-200 dark:bg-green-900/10 dark:text-green-400 dark:border-green-800",
  medium: "bg-yellow-50 text-yellow-700 border-yellow-200 dark:bg-yellow-900/10 dark:text-yellow-400 dark:border-yellow-800",
  high: "bg-orange-50 text-orange-700 border-orange-200 dark:bg-orange-900/10 dark:text-orange-400 dark:border-orange-800",
  urgent: "bg-red-50 text-red-700 border-red-200 dark:bg-red-900/10 dark:text-red-400 dark:border-red-800",
}

export const milestonePriorityIcons: Record<string, React.ComponentType<any>> = {
  low: Clock,
  medium: Timer,
  high: AlertCircle,
  urgent: AlertCircle,
}

export const milestoneStatusIcons: Record<string, React.ComponentType<any>> = {
  pending: Target,
  "in-progress": Timer,
  completed: CheckCircle,
  "on-hold": Clock,
}

// Inline Status Dropdown for Milestones
export const InlineMilestoneStatusDropdown = memo(({ 
  milestone, 
  isLoading = false, 
  canUpdate = true, 
  onStatusChange,
  isMilestoneLoading
}: {
  milestone: any
  isLoading?: boolean
  canUpdate?: boolean
  onStatusChange: (milestoneId: string, newStatus: string) => Promise<void>
  isMilestoneLoading?: (id: string) => boolean
}) => {
  const { toast } = useToast()
  const [isUpdating, setIsUpdating] = useState(false)
  const isIndividualLoading = isMilestoneLoading?.(milestone._id) || false

  const handleStatusChange = useCallback(async (newStatus: string) => {
    if (!canUpdate || isLoading || isUpdating || isIndividualLoading) return
    
    setIsUpdating(true)
    try {
      await onStatusChange(milestone._id, newStatus)
      toast({
        title: "Status updated",
        description: `Milestone status changed to ${newStatus}`,
      })
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to update milestone status",
        variant: "destructive",
      })
    } finally {
      setIsUpdating(false)
    }
  }, [canUpdate, isLoading, isUpdating, onStatusChange, milestone._id, toast])

  const StatusIcon = milestoneStatusIcons[milestone.status] || Target
  
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild disabled={!canUpdate || isLoading || isUpdating}>
        <Button 
          variant="ghost" 
          size="sm" 
          className={cn(
            "h-6 px-2 text-xs font-medium border cursor-pointer",
            milestoneStatusColors[milestone.status] || milestoneStatusColors.pending,
            (!canUpdate || isLoading || isUpdating || isIndividualLoading) && "opacity-50 cursor-not-allowed"
          )}
        >
          {isLoading || isUpdating || isIndividualLoading ? (
            <Loader2 className="h-3 w-3 animate-spin mr-1" />
          ) : (
            <StatusIcon className="h-3 w-3 mr-1" />
          )}
          {isLoading || isUpdating || isIndividualLoading ? 'Updating...' : milestone.status}
          {canUpdate && !isLoading && !isUpdating && !isIndividualLoading && (
            <ChevronDown className="h-3 w-3 ml-1" />
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-36">
        <DropdownMenuLabel>Change Status</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {Object.keys(milestoneStatusColors).map((status) => {
          const StatusIcon = milestoneStatusIcons[status] || Target
          return (
            <DropdownMenuItem
              key={status}
              onClick={() => handleStatusChange(status)}
              className="text-xs"
              disabled={status === milestone.status}
            >
              <StatusIcon className="h-3 w-3 mr-2" />
              <span className="capitalize">{status.replace('-', ' ')}</span>
              {status === milestone.status && <Check className="h-3 w-3 ml-auto" />}
            </DropdownMenuItem>
          )
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  )
})

InlineMilestoneStatusDropdown.displayName = "InlineMilestoneStatusDropdown"

// Inline Priority Dropdown for Milestones
export const InlineMilestonePriorityDropdown = memo(({ 
  milestone, 
  isLoading = false, 
  canUpdate = true, 
  onPriorityChange,
  isMilestoneLoading
}: {
  milestone: any
  isLoading?: boolean
  canUpdate?: boolean
  onPriorityChange: (milestoneId: string, newPriority: string) => Promise<void>
  isMilestoneLoading?: (id: string) => boolean
}) => {
  const isIndividualLoading = isMilestoneLoading?.(milestone._id) || false
  const { toast } = useToast()
  const [isUpdating, setIsUpdating] = useState(false)

  const handlePriorityChange = useCallback(async (newPriority: string) => {
    if (!canUpdate || isLoading || isUpdating || isIndividualLoading) return
    
    setIsUpdating(true)
    try {
      await onPriorityChange(milestone._id, newPriority)
      toast({
        title: "Priority updated",
        description: `Milestone priority changed to ${newPriority}`,
      })
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to update milestone priority",
        variant: "destructive",
      })
    } finally {
      setIsUpdating(false)
    }
  }, [canUpdate, isLoading, isUpdating, onPriorityChange, milestone._id, toast])

  const PriorityIcon = milestonePriorityIcons[milestone.priority] || Clock
  
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild disabled={!canUpdate || isLoading || isUpdating || isIndividualLoading}>
        <Button 
          variant="ghost" 
          size="sm" 
          className={cn(
            "h-6 px-2 text-xs font-medium border cursor-pointer",
            milestonePriorityColors[milestone.priority] || milestonePriorityColors.medium,
            (!canUpdate || isLoading || isUpdating || isIndividualLoading) && "opacity-50 cursor-not-allowed"
          )}
        >
          {isLoading || isUpdating || isIndividualLoading ? (
            <Loader2 className="h-3 w-3 animate-spin mr-1" />
          ) : (
            <PriorityIcon className="h-3 w-3 mr-1" />
          )}
          {isLoading || isUpdating || isIndividualLoading ? 'Updating...' : milestone.priority}
          {canUpdate && !isLoading && !isUpdating && !isIndividualLoading && (
            <ChevronDown className="h-3 w-3 ml-1" />
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-32">
        <DropdownMenuLabel>Change Priority</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {Object.keys(milestonePriorityColors).map((priority) => {
          const PriorityIcon = milestonePriorityIcons[priority] || Clock
          return (
            <DropdownMenuItem
              key={priority}
              onClick={() => handlePriorityChange(priority)}
              className="text-xs"
              disabled={priority === milestone.priority}
            >
              <PriorityIcon className="h-3 w-3 mr-2" />
              <span className="capitalize">{priority}</span>
              {priority === milestone.priority && <Check className="h-3 w-3 ml-auto" />}
            </DropdownMenuItem>
          )
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  )
})

InlineMilestonePriorityDropdown.displayName = "InlineMilestonePriorityDropdown"

// Inline Due Date Input for Milestones
export const InlineMilestoneDueDateInput = memo(({ 
  milestone, 
  isLoading = false, 
  canUpdate = true, 
  onDueDateChange,
  isMilestoneLoading
}: {
  milestone: any
  isLoading?: boolean
  canUpdate?: boolean
  onDueDateChange: (milestoneId: string, newDueDate: string) => Promise<void>
  isMilestoneLoading?: (id: string) => boolean
}) => {
  const isIndividualLoading = isMilestoneLoading?.(milestone._id) || false
  const { toast } = useToast()
  const [isUpdating, setIsUpdating] = useState(false)
  const [isEditing, setIsEditing] = useState(false)
  const [tempDate, setTempDate] = useState("")

  const formattedDate = useMemo(() => {
    if (!milestone.dueDate) return "No due date"
    try {
      return new Date(milestone.dueDate).toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: milestone.dueDate && new Date(milestone.dueDate).getFullYear() !== new Date().getFullYear() 
          ? 'numeric' : undefined
      })
    } catch {
      return "Invalid date"
    }
  }, [milestone.dueDate])

  const isOverdue = useMemo(() => {
    if (!milestone.dueDate || milestone.status === "completed") return false
    return new Date(milestone.dueDate) < new Date()
  }, [milestone.dueDate, milestone.status])

  const handleDateChange = useCallback(async (newDate: string) => {
    if (!canUpdate || isLoading || isUpdating || isIndividualLoading) return
    
    setIsUpdating(true)
    try {
      await onDueDateChange(milestone._id, newDate)
      toast({
        title: "Due date updated",
        description: `Milestone due date changed to ${new Date(newDate).toLocaleDateString()}`,
      })
    } catch (error) {
      toast({
        title: "Error", 
        description: "Failed to update milestone due date",
        variant: "destructive",
      })
    } finally {
      setIsUpdating(false)
      setIsEditing(false)
    }
  }, [canUpdate, isLoading, isUpdating, onDueDateChange, milestone._id, toast])

  const handleEdit = useCallback(() => {
    if (!canUpdate || isLoading || isUpdating || isIndividualLoading) return
    setTempDate(milestone.dueDate ? new Date(milestone.dueDate).toISOString().split('T')[0] : "")
    setIsEditing(true)
  }, [canUpdate, isLoading, isUpdating, milestone.dueDate])

  const handleCancel = useCallback(() => {
    setIsEditing(false)
    setTempDate("")
  }, [])

  const handleSubmit = useCallback((e: React.FormEvent) => {
    e.preventDefault()
    if (tempDate) {
      handleDateChange(tempDate)
    } else {
      handleCancel()
    }
  }, [tempDate, handleDateChange, handleCancel])

  if (isEditing) {
    return (
      <form onSubmit={handleSubmit} className="flex items-center gap-1">
        <Input
          type="date"
          value={tempDate}
          onChange={(e) => setTempDate(e.target.value)}
          className="h-6 text-xs w-32"
          disabled={isUpdating}
        />
        <Button
          type="submit"
          size="sm"
          variant="ghost"
          className="h-6 px-1"
          disabled={isUpdating}
        >
          {isUpdating ? <Loader2 className="h-3 w-3 animate-spin" /> : <Check className="h-3 w-3" />}
        </Button>
      </form>
    )
  }

  return (
    <Button
      variant="ghost"
      size="sm"
      className={cn(
        "h-6 px-2 text-xs font-medium border cursor-pointer",
        isOverdue 
          ? "bg-red-50 text-red-700 border-red-200 dark:bg-red-900/10 dark:text-red-400 dark:border-red-800"
          : "bg-slate-50 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700",
        (!canUpdate || isLoading || isUpdating || isIndividualLoading) && "opacity-50 cursor-not-allowed"
      )}
      onClick={handleEdit}
      disabled={!canUpdate || isLoading || isUpdating || isIndividualLoading}
    >
      {isLoading || isUpdating || isIndividualLoading ? (
        <Loader2 className="h-3 w-3 animate-spin mr-1" />
      ) : (
        <Calendar className="h-3 w-3 mr-1" />
      )}
      {isLoading || isUpdating || isIndividualLoading ? 'Updating...' : formattedDate}
    </Button>
  )
})

InlineMilestoneDueDateInput.displayName = "InlineMilestoneDueDateInput"

// Calculate progress automatically based on status
export const getProgressFromStatus = (status: string): number => {
  switch (status) {
    case 'pending': return 0
    case 'in-progress': return 50
    case 'completed': return 100
    case 'on-hold': return 25
    default: return 0
  }
}

// Display-only Progress Component (calculated from status)
export const InlineMilestoneProgressDisplay = memo(({ 
  milestone, 
  isLoading = false 
}: {
  milestone: any
  isLoading?: boolean
}) => {
  const progress = getProgressFromStatus(milestone.status)

  return (
    <div className={cn(
      "h-6 px-2 text-xs font-medium border rounded flex items-center",
      progress >= 100 
        ? "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/10 dark:text-emerald-400 dark:border-emerald-800"
        : progress >= 50
        ? "bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-900/10 dark:text-blue-400 dark:border-blue-800"
        : progress > 0
        ? "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-900/10 dark:text-amber-400 dark:border-amber-800"
        : "bg-slate-50 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700"
    )}>
      {isLoading ? (
        <Loader2 className="h-3 w-3 animate-spin mr-1" />
      ) : (
        <Target className="h-3 w-3 mr-1" />
      )}
      {progress}%
      <span className="ml-1 text-xs opacity-75">({milestone.status})</span>
    </div>
  )
})

InlineMilestoneProgressDisplay.displayName = "InlineMilestoneProgressDisplay"