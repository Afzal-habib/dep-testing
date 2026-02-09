"use client"

import { useState, useEffect, useCallback, useMemo } from "react"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  FileText,
  Search,
  Filter,
  ChevronDown,
  ChevronUp,
  X,
  Loader2,
  History,
  Edit,
  Trash2,
  RotateCcw,
  Plus,
  AlertTriangle,
  Calendar,
  User,
  MessageSquare,
  RefreshCw
} from "lucide-react"
import { cn } from "@/lib/utils"
import { formatDistanceToNow, format } from "date-fns"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { ScrollArea } from "@/components/ui/scroll-area"
import CustomModal from "@/components/shared/custom-modal"
import { useToast } from "@/hooks/use-toast"
import { apiRequest } from "@/lib/utils/api-client"
import HtmlTextRenderer from "../shared/html-text-renderer"

// Types
interface AuditLogActor {
  id: string
  name: string
  email: string
  role?: string
}

interface AuditLogEntry {
  id: string
  message_id: string
  channel_id: string
  action: 'created' | 'edited' | 'trashed' | 'restored' | 'permanently_deleted'
  actor: AuditLogActor
  previous_content?: string
  new_content?: string
  metadata: Record<string, any>
  created_at: string
}

interface AuditLogFilters {
  channelId?: string
  messageId?: string
  action?: string
  actorId?: string
  startDate?: string
  endDate?: string
}

interface AuditLogViewProps {
  isOpen: boolean
  onClose: () => void
  channelId?: string // Optional: Pre-filter by channel
  className?: string
}

// Action config for UI
const ACTION_CONFIG: Record<string, { 
  label: string
  icon: React.ElementType
  color: string
  bgColor: string
}> = {
  created: {
    label: 'Created',
    icon: Plus,
    color: 'text-green-600 dark:text-green-400',
    bgColor: 'bg-green-100 dark:bg-green-900/30'
  },
  edited: {
    label: 'Edited',
    icon: Edit,
    color: 'text-blue-600 dark:text-blue-400',
    bgColor: 'bg-blue-100 dark:bg-blue-900/30'
  },
  trashed: {
    label: 'Trashed',
    icon: Trash2,
    color: 'text-amber-600 dark:text-amber-400',
    bgColor: 'bg-amber-100 dark:bg-amber-900/30'
  },
  restored: {
    label: 'Restored',
    icon: RotateCcw,
    color: 'text-purple-600 dark:text-purple-400',
    bgColor: 'bg-purple-100 dark:bg-purple-900/30'
  },
  permanently_deleted: {
    label: 'Deleted',
    icon: AlertTriangle,
    color: 'text-red-600 dark:text-red-400',
    bgColor: 'bg-red-100 dark:bg-red-900/30'
  }
}

export function AuditLogView({
  isOpen,
  onClose,
  channelId: preFilterChannelId,
  className
}: AuditLogViewProps) {
  const { toast } = useToast()
  
  // State
  const [logs, setLogs] = useState<AuditLogEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null)
  
  // Filters
  const [filters, setFilters] = useState<AuditLogFilters>({
    channelId: preFilterChannelId
  })
  const [showFilters, setShowFilters] = useState(false)
  
  // Pagination
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 30,
    total: 0,
    totalPages: 0,
    hasMore: false
  })
  
  // Stats
  const [stats, setStats] = useState<{
    actionCounts: Record<string, number>
    totalLogs: number
  } | null>(null)

  // Fetch audit logs
  const fetchLogs = useCallback(async (reset: boolean = true) => {
    if (reset) {
      setLoading(true)
      setLogs([])
    } else {
      setLoadingMore(true)
    }
    setError(null)

    try {
      const params = new URLSearchParams()
      params.append('limit', String(pagination.limit))
      params.append('offset', reset ? '0' : String(logs.length))
      
      if (filters.channelId) params.append('channel_id', filters.channelId)
      if (filters.messageId) params.append('message_id', filters.messageId)
      if (filters.action) params.append('action', filters.action)
      if (filters.actorId) params.append('actor_id', filters.actorId)
      if (filters.startDate) params.append('start_date', filters.startDate)
      if (filters.endDate) params.append('end_date', filters.endDate)

      const response = await apiRequest(`/api/communication/messages/audit-logs?${params.toString()}`)
      
      // Handle both wrapped and unwrapped responses
      let logsData: AuditLogEntry[] = []
      let paginationData = pagination
      let statsData = stats

      if (Array.isArray(response)) {
        logsData = response
      } else if (response && typeof response === 'object') {
        if (response.data) {
          logsData = response.data
          if (response.pagination) paginationData = response.pagination
          if (response.stats) statsData = response.stats
        } else if (response.success === false) {
          throw new Error(response.error || 'Failed to fetch audit logs')
        }
      }

      if (reset) {
        setLogs(logsData)
      } else {
        setLogs(prev => [...prev, ...logsData])
      }
      
      setPagination(paginationData)
      if (statsData) setStats(statsData)

    } catch (err: any) {
      const message = err.message || 'Failed to fetch audit logs'
      setError(message)
      toast({
        title: "Error",
        description: message,
        variant: "destructive"
      })
    } finally {
      setLoading(false)
      setLoadingMore(false)
    }
  }, [filters, pagination.limit, logs.length, stats, toast])

  // Fetch on open
  useEffect(() => {
    if (isOpen) {
      fetchLogs(true)
    }
  }, [isOpen]) // eslint-disable-line react-hooks/exhaustive-deps

  // Refetch when filters change
  useEffect(() => {
    if (isOpen) {
      fetchLogs(true)
    }
  }, [filters]) // eslint-disable-line react-hooks/exhaustive-deps

  // Get avatar initials
  const getInitials = (name: string | undefined) => {
    if (!name) return "?"
    return name
      .split(" ")
      .map(n => n[0])
      .join("")
      .toUpperCase()
      .slice(0, 2)
  }

  // Clear filters
  const clearFilters = useCallback(() => {
    setFilters({ channelId: preFilterChannelId })
  }, [preFilterChannelId])

  // Check if filters are active
  const hasActiveFilters = useMemo(() => {
    return !!(
      filters.action ||
      filters.actorId ||
      filters.messageId ||
      filters.startDate ||
      filters.endDate ||
      (filters.channelId && filters.channelId !== preFilterChannelId)
    )
  }, [filters, preFilterChannelId])

  // Render action badge
  const renderActionBadge = (action: string) => {
    const config = ACTION_CONFIG[action] || {
      label: action,
      icon: History,
      color: 'text-gray-600',
      bgColor: 'bg-gray-100'
    }
    const Icon = config.icon

    return (
      <Badge 
        variant="outline" 
        className={cn("gap-1", config.color, config.bgColor, "border-transparent")}
      >
        <Icon className="h-3 w-3" />
        {config.label}
      </Badge>
    )
  }

  // Render content diff
  const renderContentDiff = (log: AuditLogEntry) => {
    if (log.action === 'created') {
      return (
        <div className="mt-2 p-3 bg-green-50 dark:bg-green-950/30 rounded-md border border-green-200 dark:border-green-800">
          <p className="text-xs font-medium text-green-700 dark:text-green-300 mb-1">Content:</p>
          <HtmlTextRenderer 
            content={log.new_content || ''} 
            className="text-sm text-green-900 dark:text-green-100"
          />
        </div>
      )
    }

    if (log.action === 'edited') {
      return (
        <div className="mt-2 space-y-2">
          {log.previous_content && (
            <div className="p-3 bg-red-50 dark:bg-red-950/30 rounded-md border border-red-200 dark:border-red-800">
              <p className="text-xs font-medium text-red-700 dark:text-red-300 mb-1">Previous:</p>
              <HtmlTextRenderer 
                content={log.previous_content} 
                className="text-sm text-red-900 dark:text-red-100 line-through opacity-70"
              />
            </div>
          )}
          {log.new_content && (
            <div className="p-3 bg-green-50 dark:bg-green-950/30 rounded-md border border-green-200 dark:border-green-800">
              <p className="text-xs font-medium text-green-700 dark:text-green-300 mb-1">New:</p>
              <HtmlTextRenderer 
                content={log.new_content} 
                className="text-sm text-green-900 dark:text-green-100"
              />
            </div>
          )}
        </div>
      )
    }

    if (log.action === 'trashed' || log.action === 'permanently_deleted') {
      return (
        <div className="mt-2 p-3 bg-red-50 dark:bg-red-950/30 rounded-md border border-red-200 dark:border-red-800">
          <p className="text-xs font-medium text-red-700 dark:text-red-300 mb-1">Deleted Content:</p>
          <HtmlTextRenderer 
            content={log.previous_content || log.new_content || '[Content not preserved]'} 
            className="text-sm text-red-900 dark:text-red-100"
          />
          {log.metadata?.trash_reason && (
            <p className="mt-2 text-xs text-red-600 dark:text-red-400">
              Reason: {log.metadata.trash_reason}
            </p>
          )}
        </div>
      )
    }

    if (log.action === 'restored') {
      return (
        <div className="mt-2 p-3 bg-purple-50 dark:bg-purple-950/30 rounded-md border border-purple-200 dark:border-purple-800">
          <p className="text-xs font-medium text-purple-700 dark:text-purple-300 mb-1">Restored Content:</p>
          <HtmlTextRenderer 
            content={log.new_content || log.previous_content || '[Content not preserved]'} 
            className="text-sm text-purple-900 dark:text-purple-100"
          />
        </div>
      )
    }

    return null
  }

  // Render metadata
  const renderMetadata = (metadata: Record<string, any>) => {
    const relevantKeys = Object.keys(metadata).filter(k => 
      !['ip_address', 'user_agent'].includes(k) && metadata[k]
    )
    
    if (relevantKeys.length === 0) return null

    return (
      <div className="mt-2 p-2 bg-muted/50 rounded text-xs space-y-1">
        {metadata.sender_name && (
          <p><span className="font-medium">Original Sender:</span> {metadata.sender_name}</p>
        )}
        {metadata.days_in_trash !== undefined && (
          <p><span className="font-medium">Days in Trash:</span> {metadata.days_in_trash}</p>
        )}
        {metadata.retention_policy && (
          <p><span className="font-medium">Retention:</span> {metadata.retention_policy}</p>
        )}
      </div>
    )
  }

  return (
    <CustomModal
      isOpen={isOpen}
      onClose={onClose}
      title="Message Audit Logs"
      modalSize="xl"
      className={className}
      headerActions={
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => fetchLogs(true)}
            disabled={loading}
          >
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
          <Button
            variant={showFilters ? "secondary" : "outline"}
            size="sm"
            onClick={() => setShowFilters(!showFilters)}
            className="gap-1"
          >
            <Filter className="h-4 w-4" />
            Filters
            {hasActiveFilters && (
              <Badge variant="destructive" className="h-4 w-4 p-0 text-[10px]">
                !
              </Badge>
            )}
          </Button>
        </div>
      }
      actions={
        <Button variant="outline" onClick={onClose}>
          Close
        </Button>
      }
    >
      <div className="mb-2 text-sm text-muted-foreground">
        View the complete history of message actions for compliance and investigation.
      </div>

      {/* Stats Bar */}
      <div className="flex items-center gap-2 text-sm text-muted-foreground pb-2 border-b mb-3">
        <History className="h-4 w-4" />
        <span>{stats?.totalLogs || logs.length} total logs</span>
      </div>

        {/* Filters Panel */}
        {showFilters && (
          <div className="p-3 bg-muted/30 rounded-lg border space-y-3">
            <div className="grid grid-cols-2 gap-3">
              {/* Action Filter */}
              <div className="space-y-1">
                <Label className="text-xs">Action Type</Label>
                <Select
                  value={filters.action || "all"}
                  onValueChange={(value) => setFilters(f => ({ ...f, action: value === "all" ? undefined : value }))}
                >
                  <SelectTrigger className="h-8">
                    <SelectValue placeholder="All actions" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All actions</SelectItem>
                    <SelectItem value="created">Created</SelectItem>
                    <SelectItem value="edited">Edited</SelectItem>
                    <SelectItem value="trashed">Trashed</SelectItem>
                    <SelectItem value="restored">Restored</SelectItem>
                    <SelectItem value="permanently_deleted">Deleted</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Message ID Filter */}
              <div className="space-y-1">
                <Label className="text-xs">Message ID</Label>
                <Input
                  placeholder="Filter by message ID"
                  value={filters.messageId || ""}
                  onChange={(e) => setFilters(f => ({ ...f, messageId: e.target.value || undefined }))}
                  className="h-8"
                />
              </div>

              {/* Date Range */}
              <div className="space-y-1">
                <Label className="text-xs">From Date</Label>
                <Input
                  type="date"
                  value={filters.startDate || ""}
                  onChange={(e) => setFilters(f => ({ ...f, startDate: e.target.value || undefined }))}
                  className="h-8"
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">To Date</Label>
                <Input
                  type="date"
                  value={filters.endDate || ""}
                  onChange={(e) => setFilters(f => ({ ...f, endDate: e.target.value || undefined }))}
                  className="h-8"
                />
              </div>
            </div>

            {hasActiveFilters && (
              <Button
                variant="ghost"
                size="sm"
                onClick={clearFilters}
                className="gap-1 text-muted-foreground"
              >
                <X className="h-3 w-3" />
                Clear filters
              </Button>
            )}
          </div>
        )}

        {/* Action Stats */}
        {stats?.actionCounts && Object.keys(stats.actionCounts).length > 0 && (
          <div className="flex flex-wrap gap-2 pb-2">
            {Object.entries(stats.actionCounts).map(([action, count]) => (
              <Button
                key={action}
                variant={filters.action === action ? "secondary" : "ghost"}
                size="sm"
                className="h-7 text-xs gap-1"
                onClick={() => setFilters(f => ({ 
                  ...f, 
                  action: f.action === action ? undefined : action 
                }))}
              >
                {renderActionBadge(action)}
                <span className="ml-1">({count})</span>
              </Button>
            ))}
          </div>
        )}

        {/* Logs List */}
        <ScrollArea className="h-[50vh] pr-4">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Loader2 className="h-8 w-8 animate-spin mb-2" />
              <p>Loading audit logs...</p>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center py-12 text-destructive">
              <AlertTriangle className="h-8 w-8 mb-2" />
              <p>{error}</p>
              <Button variant="outline" size="sm" className="mt-4" onClick={() => fetchLogs(true)}>
                Try Again
              </Button>
            </div>
          ) : logs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <FileText className="h-12 w-12 mb-4 opacity-50" />
              <p className="text-lg font-medium">No audit logs found</p>
              <p className="text-sm">
                {hasActiveFilters 
                  ? "Try adjusting your filters"
                  : "Message actions will appear here"}
              </p>
            </div>
          ) : (
            <div className="space-y-2 py-2">
              {logs.map((log) => (
                <div
                  key={log.id}
                  className={cn(
                    "p-3 rounded-lg border transition-colors",
                    expandedLogId === log.id 
                      ? "bg-muted/50 border-primary/30" 
                      : "bg-card hover:bg-muted/30"
                  )}
                >
                  {/* Header Row */}
                  <div 
                    className="flex items-start gap-3 cursor-pointer"
                    onClick={() => setExpandedLogId(expandedLogId === log.id ? null : log.id)}
                  >
                    {/* Actor Avatar */}
                    <Avatar className="h-8 w-8">
                      <AvatarFallback className="text-xs">
                        {getInitials(log.actor.name)}
                      </AvatarFallback>
                    </Avatar>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-medium text-sm">{log.actor.name}</span>
                        {log.actor.role && (
                          <Badge variant="outline" className="text-[10px] h-5">
                            {log.actor.role}
                          </Badge>
                        )}
                        {renderActionBadge(log.action)}
                      </div>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground mt-1">
                        <Calendar className="h-3 w-3" />
                        <time dateTime={log.created_at}>
                          {format(new Date(log.created_at), 'PPpp')}
                        </time>
                        <span>•</span>
                        <span>{formatDistanceToNow(new Date(log.created_at), { addSuffix: true })}</span>
                      </div>
                    </div>

                    {/* Expand Toggle */}
                    <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                      {expandedLogId === log.id ? (
                        <ChevronUp className="h-4 w-4" />
                      ) : (
                        <ChevronDown className="h-4 w-4" />
                      )}
                    </Button>
                  </div>

                  {/* Expanded Content */}
                  {expandedLogId === log.id && (
                    <div className="mt-3 pt-3 border-t">
                      {/* IDs */}
                      <div className="flex gap-4 text-xs text-muted-foreground mb-2">
                        <div className="flex items-center gap-1">
                          <MessageSquare className="h-3 w-3" />
                          <span className="font-mono">{log.message_id.slice(0, 8)}...</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <span className="font-medium">Channel:</span>
                          <span className="font-mono">{log.channel_id.slice(0, 8)}...</span>
                        </div>
                      </div>

                      {/* Content Diff */}
                      {renderContentDiff(log)}

                      {/* Metadata */}
                      {renderMetadata(log.metadata)}
                    </div>
                  )}
                </div>
              ))}

              {/* Load More */}
              {pagination.hasMore && (
                <div className="flex justify-center py-4">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => fetchLogs(false)}
                    disabled={loadingMore}
                    className="gap-2"
                  >
                    {loadingMore ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Loading...
                      </>
                    ) : (
                      <>
                        <ChevronDown className="h-4 w-4" />
                        Load More ({logs.length} of {pagination.total})
                      </>
                    )}
                  </Button>
                </div>
              )}
            </div>
          )}
        </ScrollArea>
      </CustomModal>
  )
}
