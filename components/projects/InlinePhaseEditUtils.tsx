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
  Pause,
  XCircle,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { useToast } from "@/hooks/use-toast"
import { Input } from "@/components/ui/input"

// Color configurations for phases
export const phaseStatusColors: Record<string, string> = {
  pending: "bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700",
  "in-progress": "bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/20 dark:text-blue-400 dark:border-blue-800",
  completed: "bg-emerald-100 text-emerald-800 border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800",
  "on-hold": "bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-900/20 dark:text-amber-400 dark:border-amber-800",
  cancelled: "bg-red-100 text-red-800 border-red-200 dark:bg-red-900/20 dark:text-red-400 dark:border-red-800",
}



export const phaseStatusIcons: Record<string, React.ComponentType<any>> = {
  pending: Target,
  "in-progress": Timer,
  completed: CheckCircle,
  "on-hold": Pause,
  cancelled: XCircle,
}

// Inline Status Dropdown for Phases
export const InlinePhaseStatusDropdown = memo(({ 
  phase, 
  isLoading = false, 
  canUpdate = true, 
  onStatusChange,
  isPhaseLoading
}: {
  phase: any
  isLoading?: boolean
  canUpdate?: boolean
  onStatusChange: (phaseId: string, newStatus: "pending" | "in-progress" | "completed" | "on-hold" | "cancelled" | "planning") => Promise<void>
  isPhaseLoading?: (id: string) => boolean
}) => {
  const { toast } = useToast()
  const [isUpdating, setIsUpdating] = useState(false)
  const isIndividualLoading = isPhaseLoading?.(phase._id) || false

  const handleStatusChange = useCallback(async (newStatus: "pending" | "in-progress" | "completed" | "on-hold" | "cancelled" | "planning") => {
    if (!canUpdate || isLoading || isUpdating || isIndividualLoading) return
    
    setIsUpdating(true)
    try {
      await onStatusChange(phase._id, newStatus)
      toast({
        title: "Status updated",
        description: `Phase status changed to ${newStatus}`,
      })
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to update phase status",
        variant: "destructive",
      })
    } finally {
      setIsUpdating(false)
    }
  }, [canUpdate, isLoading, isUpdating, onStatusChange, phase._id, toast])

  const StatusIcon = phaseStatusIcons[phase.status] || Target
  
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild disabled={!canUpdate || isLoading || isUpdating}>
        <Button 
          variant="ghost" 
          size="sm" 
          className={cn(
            "h-6 px-2 text-xs font-medium border cursor-pointer",
            phaseStatusColors[phase.status] || phaseStatusColors.pending,
            (!canUpdate || isLoading || isUpdating || isIndividualLoading) && "opacity-50 cursor-not-allowed"
          )}
        >
          {isLoading || isUpdating || isIndividualLoading ? (
            <Loader2 className="h-3 w-3 animate-spin mr-1" />
          ) : (
            <StatusIcon className="h-3 w-3 mr-1" />
          )}
          {isLoading || isUpdating || isIndividualLoading ? 'Updating...' : phase.status}
          {canUpdate && !isLoading && !isUpdating && !isIndividualLoading && (
            <ChevronDown className="h-3 w-3 ml-1" />
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-36">
        <DropdownMenuLabel>Change Status</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {Object.keys(phaseStatusColors).map((status) => {
          const StatusIcon = phaseStatusIcons[status] || Target
          return (
            <DropdownMenuItem
              key={status}
              onClick={() => handleStatusChange( status as "pending" | "in-progress" | "completed" | "on-hold" | "cancelled" | "planning")}
              className="text-xs"
              disabled={status === phase.status}
            >
              <StatusIcon className="h-3 w-3 mr-2" />
              <span className="capitalize">{status.replace('-', ' ')}</span>
              {status === phase.status && <Check className="h-3 w-3 ml-auto" />}
            </DropdownMenuItem>
          )
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  )
})

InlinePhaseStatusDropdown.displayName = "InlinePhaseStatusDropdown"

// Inline Due Date Input for Phases (End Date)
export const InlinePhaseEndDateInput = memo(({ 
  phase, 
  isLoading = false, 
  canUpdate = true, 
  onEndDateChange,
  isPhaseLoading
}: {
  phase: any
  isLoading?: boolean
  canUpdate?: boolean
  onEndDateChange: (phaseId: string, newEndDate: string) => Promise<void>
  isPhaseLoading?: (id: string) => boolean
}) => {
  const { toast } = useToast()
  const [isUpdating, setIsUpdating] = useState(false)
  const [isEditing, setIsEditing] = useState(false)
  const [tempDate, setTempDate] = useState("")
  const isIndividualLoading = isPhaseLoading?.(phase._id) || false

  const formattedDate = useMemo(() => {
    if (!phase.endDate) return "No end date"
    try {
      return new Date(phase.endDate).toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: phase.endDate && new Date(phase.endDate).getFullYear() !== new Date().getFullYear() 
          ? 'numeric' : undefined
      })
    } catch {
      return "Invalid date"
    }
  }, [phase.endDate])

  const isOverdue = useMemo(() => {
    if (!phase.endDate || phase.status === "completed") return false
    return new Date(phase.endDate) < new Date()
  }, [phase.endDate, phase.status])

  const handleDateChange = useCallback(async (newDate: string) => {
    if (!canUpdate || isLoading || isUpdating || isIndividualLoading) return
    
    setIsUpdating(true)
    try {
      await onEndDateChange(phase._id, newDate)
      toast({
        title: "End date updated",
        description: `Phase end date changed to ${new Date(newDate).toLocaleDateString()}`,
      })
    } catch (error) {
      toast({
        title: "Error", 
        description: "Failed to update phase end date",
        variant: "destructive",
      })
    } finally {
      setIsUpdating(false)
      setIsEditing(false)
    }
  }, [canUpdate, isLoading, isUpdating, onEndDateChange, phase._id, toast])

  const handleEdit = useCallback(() => {
    if (!canUpdate || isLoading || isUpdating || isIndividualLoading) return
    setTempDate(phase.endDate ? new Date(phase.endDate).toISOString().split('T')[0] : "")
    setIsEditing(true)
  }, [canUpdate, isLoading, isUpdating, phase.endDate])

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

InlinePhaseEndDateInput.displayName = "InlinePhaseEndDateInput"