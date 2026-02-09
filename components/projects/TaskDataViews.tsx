"use client"

import type React from "react"
import { Fragment, memo, useState, useMemo } from "react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
import {
  Plus,
  Edit,
  Trash2,
  Eye,
  MoreHorizontal,
  ChevronDown,
  ChevronUp,
  CheckSquare,
  ListTodo,
  CheckCircle,
  RefreshCw,
} from "lucide-react"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import HtmlTextRenderer from "@/components/shared/html-text-renderer" // Fixed import to use default export
import { cn } from "@/lib/utils"
import { DndContext, DragOverlay, type DragEndEvent, type DragStartEvent, useDroppable, closestCenter } from "@dnd-kit/core"
import { SortableContext, useSortable, verticalListSortingStrategy } from "@dnd-kit/sortable"
import {
  InlineStatusDropdown,
  InlinePriorityDropdown,
  InlineDueDateInput,
  InlineAssigneeDropdown,
} from "@/components/projects/InlineTaskEditUtils"


interface TaskViewProps {
  departmentId: string
  departmentName: string
  departmentTasks: any[]
  collapsedTasks: Set<string>
  // collapsedDepartments: Set<string> // Removed as it's not used in the provided updates
  canCreate: (resource: string) => boolean
  canUpdate: (resource: string) => boolean
  canDelete: (resource: string) => boolean
  onOpenCreateTaskModal: (
    departmentId: string,
    departmentName: string,
    parentTaskId?: string,
    defaultTask?: any,
  ) => void
  onOpenEditTaskModal: (task: any) => void
  onDeleteTask: (taskId: string) => Promise<void>
  onRestoreTask: (taskId: string) => Promise<void>
  onToggleTaskCollapse: (taskId: string) => void
  onSelectTaskForDetails: (task: any) => void
  getSubTasks: (parentTaskId: string) => any[]
  getDepartmentName: (departmentId: string) => string
  onProjectUpdate?: () => void
  onShowTaskDetails?: (show: boolean) => void
  isActionLoadingForTask?: (taskId: string) => boolean
  isActionLoadingForDepartment?: (departmentId: string) => boolean
  // Inline update handlers
  onStatusChange?: (taskId: string, newStatus: string) => Promise<void>
  onPriorityChange?: (taskId: string, newPriority: string) => Promise<void>
  onDueDateChange?: (taskId: string, newDueDate: string) => Promise<void>
  onAssigneeChange?: (taskId: string, newAssigneeId: string) => Promise<void>
  departmentUsers?: any[]
  usersLoading?: boolean
}

// Board Column Component - Extracted from inline code
export const BoardColumn: React.FC<{
  id: string
  title: string
  tasks: any[]
  departmentId: string
  onOpenCreateTaskModal: (
    departmentId: string,
    departmentName: string,
    parentTaskId?: string,
    defaultTask?: any,
  ) => void
  onOpenEditTaskModal?: (task: any) => void
  onDeleteTask?: (taskId: string) => Promise<void>
  onRestoreTask?: (taskId: string) => Promise<void>
  canUpdate?: (resource: string) => boolean
  canDelete?: (resource: string) => boolean
  getDepartmentName: (departmentId: string) => string
  onSelectTaskForDetails: (task: any) => void
  onShowTaskDetails?: (show: boolean) => void
  isActionLoadingForDepartment?: (departmentId: string) => boolean
  isActionLoadingForTask?: (taskId: string) => boolean
  draggingTask?: any
  onStatusChange?: (taskId: string, newStatus: string) => Promise<void>
  onPriorityChange?: (taskId: string, newPriority: string) => Promise<void>
  onDueDateChange?: (taskId: string, newDueDate: string) => Promise<void>
  onAssigneeChange?: (taskId: string, newAssigneeId: string) => Promise<void>
  departmentUsers?: any[]
  usersLoading?: boolean
  collapsed?: boolean
  onToggleCollapse?: () => void
}> = ({
  id,
  title,
  tasks,
  departmentId,
  onOpenCreateTaskModal,
  getDepartmentName,
  onSelectTaskForDetails,
  onShowTaskDetails,
  isActionLoadingForDepartment,
  isActionLoadingForTask,
  draggingTask,
  onOpenEditTaskModal,
  onDeleteTask,
  onRestoreTask,
  canUpdate,
  canDelete,
  onStatusChange,
  onPriorityChange,
  onDueDateChange,
  onAssigneeChange,
  departmentUsers,
  usersLoading,
  collapsed,
  onToggleCollapse,
}) => {
    const { isOver, setNodeRef } = useDroppable({ id })
    // Use the collapsed prop passed from the parent if available
    const _collapsed = typeof collapsed === 'boolean' ? collapsed : false
    const toggleCollapsed = () => onToggleCollapse?.()

    return (
      <div
        ref={setNodeRef}
        className={cn(
          'border border-border rounded bg-card/30 flex flex-col transition-all duration-300',
          isOver ? 'ring-2 ring-primary/30' : '',
          _collapsed ? 'p-1 w-16 overflow-hidden whitespace-nowrap' : 'p-3 w-100'
        )}
        style={{
          height: '600px',
        }}
        aria-expanded={!_collapsed}
      >
        {/* Fixed Header - Always visible */}
        <div className={`flex items-center justify-between mb-3 flex-shrink-0 ${_collapsed ? "flex-col gap-10" : "flex-row"} `}>
          <div className={`flex items-center ${_collapsed ? "flex-col  gap-8" : "flex-row  gap-2"}`}>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 w-7 p-0 transition-transform"
              onClick={() => toggleCollapsed()}
              onPointerDown={(e) => { e.stopPropagation(); }}
              aria-label={_collapsed ? 'Expand column' : 'Collapse column'}
              title={_collapsed ? 'Expand column' : 'Collapse column'}
              aria-expanded={!_collapsed}
              style={{
                transform: collapsed ? 'rotate(-90deg)' : 'rotate(0deg)',
              }}
            >
              <ChevronDown className="h-4 w-4" />
            </Button>
            <div className="capitalize font-medium text-sm truncate" style={{
              transform: _collapsed ? 'rotate(90deg)' : 'rotate(0deg)',
            }}>{title.replace("-", " ")}</div>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0" >
            <Badge className="text-xs">{tasks.length}</Badge>
          </div>
        </div>

        {/* Scrollable Content Area */}
        {!_collapsed && (
          <>
            <div className="mb-3 flex items-center justify-end flex-shrink-0">
              <Button
                variant="ghost"
                size="sm"
                className="h-7 w-7 p-0"
                onClick={() =>
                  onOpenCreateTaskModal(departmentId, getDepartmentName(departmentId), undefined, { status: title })
                }
                disabled={isActionLoadingForDepartment?.(departmentId)}
              >
                <Plus className="h-4 w-4" />
              </Button>
            </div>

            {/* Scrollable Tasks Container */}
            <div className="space-y-2 overflow-y-auto flex-1 pr-2 custom-scrollbar" style={{
              height: "600px",
            }}>
              {/* Only render tasks list if column is expanded */}
              {tasks.length === 0 ? (
                <div className="p-3 text-center text-sm text-muted-foreground border-2 border-dashed border-muted rounded-lg">
                  {isOver && draggingTask ? (
                    <div className="text-primary font-medium">Drop here</div>
                  ) : (
                    "No tasks"
                  )}
                </div>
              ) : (
                <div className={cn(
                  "space-y-2 transition-colors duration-200",
                  isOver && "bg-primary/5 rounded-lg p-1"
                )}>
                  {tasks.map((task, index) => (
                    <DraggableTask
                      key={task._id}
                      task={task}
                      taskIndex={index}
                      onSelectTaskForDetails={onSelectTaskForDetails}
                      onShowTaskDetails={onShowTaskDetails}
                      isActionLoadingForTask={isActionLoadingForTask}
                      onOpenEditTaskModal={onOpenEditTaskModal}
                      onDeleteTask={onDeleteTask}
                      onRestoreTask={onRestoreTask}
                      canUpdate={canUpdate}
                      canDelete={canDelete}
                      isActionLoadingForDepartment={isActionLoadingForDepartment}
                      departmentId={departmentId}
                      onStatusChange={onStatusChange}
                      onPriorityChange={onPriorityChange}
                      onDueDateChange={onDueDateChange}
                      onAssigneeChange={onAssigneeChange}
                      departmentUsers={departmentUsers}
                      usersLoading={usersLoading}
                      isBoard={true}
                    />
                  ))}
                  {/* Drop zone indicator when hovering over column */}
                  {isOver && draggingTask && (
                    <div className="p-2 rounded border-2 border-dashed border-primary bg-primary/10 animate-pulse">
                      <div className="text-xs text-primary font-medium text-center">
                        Drop to move here
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </>
        )}
      </div>
    )
  }

// Draggable Task Component for Board View - Optimized for drag-and-drop with minimal inline edits
const DraggableTask: React.FC<{
  task: any
  onSelectTaskForDetails: (task: any) => void
  onShowTaskDetails?: (show: boolean) => void
  isActionLoadingForTask?: (taskId: string) => boolean
  onOpenEditTaskModal?: (task: any) => void
  onDeleteTask?: (taskId: string) => Promise<void>
  onRestoreTask?: (taskId: string) => Promise<void>
  canUpdate?: (resource: string) => boolean
  canDelete?: (resource: string) => boolean
  isActionLoadingForDepartment?: (departmentId: string) => boolean
  departmentId?: string
  onStatusChange?: (taskId: string, newStatus: string) => Promise<void>
  onPriorityChange?: (taskId: string, newPriority: string) => Promise<void>
  onDueDateChange?: (taskId: string, newDueDate: string) => Promise<void>
  onAssigneeChange?: (taskId: string, newAssigneeId: string) => Promise<void>
  departmentUsers?: any[]
  usersLoading?: boolean
  isBoard?: boolean
  taskIndex?: number
}> = ({ task, taskIndex, onSelectTaskForDetails, onShowTaskDetails, isActionLoadingForTask, onOpenEditTaskModal, onDeleteTask, onRestoreTask, canUpdate, canDelete, isActionLoadingForDepartment, departmentId, onStatusChange, onPriorityChange, onDueDateChange, onAssigneeChange, departmentUsers, usersLoading, isBoard = false }) => {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging, isOver } = useSortable({
    id: String(task._id),
    disabled: !!isActionLoadingForTask?.(task._id),
    data: {
      type: 'task',
      task,
      index: taskIndex
    }
  })

  // Optimize transform with smooth animations
  const style: any = {
    transform: transform ? `translate3d(${transform.x}px, ${transform.y}px, 0)` : undefined,
    transition: isDragging ? 'none' : transition || 'transform 200ms ease-in-out',
    zIndex: isDragging ? 1000 : isOver ? 100 : 'auto',
  }

  return (
    <div className="relative group">
      <div
        ref={setNodeRef}
        style={style as any}
        {...attributes}
        {...listeners}
        className={cn(
          "p-3 rounded border border-border bg-card shadow cursor-grab transition-all duration-200",
          "hover:shadow-md hover:border-primary/30",
          isDragging && "opacity-0 pointer-events-none",
          isOver && "ring-2 ring-primary/20 border-primary/50",
          isActionLoadingForTask?.(task._id) && "opacity-50 cursor-not-allowed"
        )}
        onClick={() => {
          if (isActionLoadingForTask?.(task._id)) return
          onSelectTaskForDetails(task)
          onShowTaskDetails?.(true)
        }}
      >
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <div className="flex flex-col min-w-0">
              <div className="text-sm font-medium mr-6">{task.title}</div>
              {/* Compact metadata row for board view - no description */}
              <div className="flex items-center gap-2 mt-3 text-xs text-muted-foreground justify-between flex-wrap">
                <div className="flex items-center gap-1 flex-wrap">
                  {/* Task Order Number */}
                  <Badge variant="secondary" className="text-xs h-5 px-1.5 bg-slate-100 dark:bg-slate-800">
                    #{task.order || task._id?.toString().slice(-4).toUpperCase()}
                  </Badge>
                  {task.dueDate && new Date(task.dueDate) < new Date() && task.status !== "completed" && (
                    <Badge variant="destructive" className="text-xs whitespace-nowrap">
                      Overdue
                    </Badge>
                  )}
                  {/* Priority Inline Dropdown - Available in all views */}
                  {task.priority && (
                    <div onClick={(e) => e.stopPropagation()} onPointerDown={(e) => e.stopPropagation()}>
                      <InlinePriorityDropdown
                        task={task}
                        isLoading={isActionLoadingForTask?.(task._id)}
                        canUpdate={canUpdate?.("tasks")}
                        onPriorityChange={onPriorityChange || (async () => { })}
                      />
                    </div>
                  )}

                  {/* Due date inline edit - Available in all views */}
                  {task.dueDate && (
                    <div onClick={(e) => e.stopPropagation()} onPointerDown={(e) => e.stopPropagation()}>
                      <InlineDueDateInput
                        task={task}
                        isLoading={isActionLoadingForTask?.(task._id)}
                        canUpdate={canUpdate?.("tasks")}
                        onDueDateChange={onDueDateChange || (async () => { })}
                      />
                    </div>
                  )}
                </div>

                {/* Assignee - Always editable via dropdown with pointer-events handling */}
                <div onClick={(e) => e.stopPropagation()} onPointerDown={(e) => e.stopPropagation()}>
                  <InlineAssigneeDropdown
                    task={task}
                    isLoading={isActionLoadingForTask?.(task._id)}
                    assigneeLoading={usersLoading}
                    canUpdate={canUpdate?.("tasks")}
                    users={departmentUsers}
                    onAssigneeChange={onAssigneeChange || (async () => { })}
                  />
                </div>

              </div>
            </div>
          </div>
          {/* Status is intentionally removed from board card to keep UI compact */}
        </div>
      </div>

      {/* Inline avatar positioned to the right within the header */}
      <div className="absolute right-8 top-1/2 -translate-y-1/2 z-0">

      </div>

      {/* Hover-only action menu placed at top-right of task card */}
      <div className="absolute top-2 right-2 z-10">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 w-7 p-0 opacity-0 group-hover:opacity-100 transition-opacity hover:bg-muted"
              onClick={(e) => e.stopPropagation()}
              onPointerDown={(e) => e.stopPropagation()}
            >
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-44">
            <DropdownMenuItem
              onClick={(e) => {
                e.stopPropagation()
                onSelectTaskForDetails(task)
                onShowTaskDetails?.(true)
              }}
              disabled={isActionLoadingForTask?.(task._id)}
            >
              <Eye className="h-4 w-4 mr-2" />
              View Details
            </DropdownMenuItem>
            {canUpdate && canUpdate("tasks") && (
              <DropdownMenuItem
                onClick={(e) => {
                  e.stopPropagation()
                  onOpenEditTaskModal?.(task)
                }}
                disabled={isActionLoadingForTask?.(task._id)}
              >
                <Edit className="h-4 w-4 mr-2" />
                Edit
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
            {canDelete && canDelete("tasks") && !task.isDeleted && (
              <DropdownMenuItem
                onClick={(e) => {
                  e.stopPropagation()
                  onDeleteTask?.(task._id)
                }}
                className="text-red-600"
                disabled={isActionLoadingForTask?.(task._id) || isActionLoadingForDepartment?.(departmentId || "")}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Delete
              </DropdownMenuItem>
            )}
            {canDelete && canDelete("tasks") && task.isDeleted && (
              <DropdownMenuItem
                onClick={(e) => {
                  e.stopPropagation()
                  onRestoreTask?.(task._id)
                }}
                className="text-green-600"
                disabled={isActionLoadingForTask?.(task._id) || isActionLoadingForDepartment?.(departmentId || "")}
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                Restore
              </DropdownMenuItem>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  )
}

export const TaskGridView: React.FC<TaskViewProps> = memo(function TaskGridView({
  departmentId,
  departmentName,
  departmentTasks,
  collapsedTasks,
  canCreate,
  canUpdate,
  canDelete,
  onOpenCreateTaskModal,
  onOpenEditTaskModal,
  onDeleteTask,
  onRestoreTask,
  onToggleTaskCollapse,
  onSelectTaskForDetails,
  getSubTasks,
  onShowTaskDetails,
  isActionLoadingForTask,
  isActionLoadingForDepartment,
  onStatusChange,
  onPriorityChange,
  onDueDateChange,
  onAssigneeChange,
  departmentUsers,
  usersLoading,
}) {
  return (
    <div className="space-y-0">
      {departmentTasks.map((task) => {
        const subTasks = getSubTasks(task._id)
        const completedSubTasks = subTasks.filter((st) => st.status === "completed").length
        const isOverdue = task.dueDate && new Date(task.dueDate) < new Date() && task.status !== "completed"
        const isCollapsed = collapsedTasks.has(task._id)

        return (
          <Card
            key={task._id}
            className="group transition-all duration-200 hover:shadow-md border-0 border-b rounded-none"
          >
            <CardContent className="p-4">
              {/* Task Header */}
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3 flex-1 min-w-0">
                  {/* Collapse Toggle */}
                  {subTasks.length > 0 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => onToggleTaskCollapse(task._id)}
                      className="h-8 w-8 p-0 mt-0.5 flex-shrink-0 hover:bg-primary/10"
                    >
                      {isCollapsed ? <ChevronDown className="h-4 w-4" /> : <ChevronUp className="h-4 w-4" />}
                    </Button>
                  )}

                  {/* Title and Metadata */}
                  <div className="flex-1 min-w-0 pt-0.5">
                    <div className="flex items-center gap-2 mb-2">
                      {task.status === "completed" ? (
                        <CheckCircle className="h-4 w-4 text-emerald-500" />
                      ) : task.status === "in-progress" ? (
                        <ListTodo className="h-4 w-4 text-blue-500" />
                      ) : (
                        <CheckSquare className="h-4 w-4 text-muted-foreground" />
                      )}
                      <h4 className="font-semibold text-base text-foreground truncate">{task.title}</h4>
                      {isActionLoadingForTask?.(task._id) && (
                        <RefreshCw className="h-4 w-4 text-muted-foreground animate-spin ml-2" />
                      )}
                      {isOverdue && (
                        <Badge variant="destructive" className="text-xs whitespace-nowrap">
                          Overdue
                        </Badge>
                      )}
                    </div>

                    {/* Badges Section */}
                    <div className="flex items-center gap-2 flex-wrap">
                      {/* Status Inline Edit */}
                      <InlineStatusDropdown
                        task={task}
                        isLoading={isActionLoadingForTask?.(task._id)}
                        canUpdate={canUpdate("tasks")}
                        onStatusChange={onStatusChange || (async () => { })}
                      />

                      {/* Priority Inline Edit */}
                      <InlinePriorityDropdown
                        task={task}
                        isLoading={isActionLoadingForTask?.(task._id)}
                        canUpdate={canUpdate("tasks")}
                        onPriorityChange={onPriorityChange || (async () => { })}
                      />

                      {/* Due Date Inline Edit */}
                      <InlineDueDateInput
                        task={task}
                        isLoading={isActionLoadingForTask?.(task._id)}
                        canUpdate={canUpdate("tasks")}
                        onDueDateChange={onDueDateChange || (async () => { })}
                      />

                      {/* Assignee Inline Edit */}
                      <InlineAssigneeDropdown
                        task={task}
                        isLoading={isActionLoadingForTask?.(task._id)}
                        assigneeLoading={usersLoading}
                        canUpdate={canUpdate("tasks")}
                        users={departmentUsers}
                        onAssigneeChange={onAssigneeChange || (async () => { })}
                      />

                      {/* Subtask Progress Badge */}
                      {subTasks.length > 0 && (
                        <Badge
                          variant="secondary"
                          className="text-xs h-6 px-2 bg-emerald-50 text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400"
                        >
                          <CheckSquare className="h-3 w-3 mr-1.5" />
                          {completedSubTasks}/{subTasks.length}
                        </Badge>
                      )}
                    </div>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="flex items-center gap-1 flex-shrink-0">
                  {canCreate("tasks") && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-8 text-xs border-primary/30 hover:bg-primary/5 bg-transparent"
                      onClick={() => onOpenCreateTaskModal(departmentId, departmentName, task._id)}
                      disabled={isActionLoadingForTask?.(task._id) || isActionLoadingForDepartment?.(departmentId)}
                    >
                      <Plus className="h-3.5 w-3.5 mr-1" />
                      Subtask
                    </Button>
                  )}

                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-8 w-8 p-0 opacity-0 group-hover:opacity-100 transition-opacity hover:bg-muted"
                      >
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-44">
                      <DropdownMenuItem
                        onClick={() => {
                          onSelectTaskForDetails(task)
                          onShowTaskDetails?.(true)
                        }}
                        disabled={isActionLoadingForTask?.(task._id)}
                      >
                        <Eye className="h-4 w-4 mr-2" />
                        View Details
                      </DropdownMenuItem>
                      {canUpdate("tasks") && (
                        <DropdownMenuItem onClick={() => onOpenEditTaskModal(task)} disabled={isActionLoadingForTask?.(task._id)}>
                          <Edit className="h-4 w-4 mr-2" />
                          Edit
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuSeparator />
                      {canDelete("tasks") && !task.isDeleted && (
                        <DropdownMenuItem onClick={(e) => { e.stopPropagation(); onDeleteTask(task._id); }} className="text-red-600" disabled={isActionLoadingForTask?.(task._id)}>
                          <Trash2 className="h-4 w-4 mr-2" />
                          Delete
                        </DropdownMenuItem>
                      )}
                      {canDelete("tasks") && task.isDeleted && (
                        <DropdownMenuItem onClick={(e) => { e.stopPropagation(); onRestoreTask(task._id); }} className="text-green-600" disabled={isActionLoadingForTask?.(task._id)}>
                          <RefreshCw className="h-4 w-4 mr-2" />
                          Restore
                        </DropdownMenuItem>
                      )}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </div>

              {/* Description Section */}
              {task.description && (
                <div className="mt-3 ml-11">
                  <HtmlTextRenderer
                    content={task.description}
                    maxLength={300}
                    renderAsHtml={true}
                    truncateHtml={true}
                  />
                </div>
              )}

              {/* Subtasks Section */}
              {subTasks.length > 0 && !isCollapsed && (
                <div className="mt-4 ml-11 space-y-2 border-t pt-3">
                  {subTasks.map((subTask) => (
                    <div key={subTask._id} className="flex items-center justify-between p-3 rounded-lg bg-muted/40 hover:bg-muted/60 transition-colors group/subtask border border-border/50">

                      <div className="flex items-center gap-3 flex-1 min-w-0">

                        {subTask.status === "completed" ? (
                          <CheckCircle className="h-4 w-4 text-emerald-500" />
                        ) : subTask.type === "main-task" ? (
                          <ListTodo className="h-4 w-4 text-blue-500" />
                        ) : (
                          <CheckSquare className="h-4 w-4 text-muted-foreground" />
                        )}
                        <div className="flex items-center gap-2 mb-2">
                          <span className="text-sm font-medium text-foreground truncate">
                            {subTask.title}
                            {isActionLoadingForTask?.(subTask._id) && <RefreshCw className="inline-block h-3 w-3 ml-2 text-muted-foreground animate-spin" />}
                          </span>
                          {subTask.dueDate && new Date(subTask.dueDate) < new Date() && subTask.status !== "completed" && (
                            <Badge variant="destructive" className="text-xs whitespace-nowrap">
                              Overdue
                            </Badge>
                          )}
                        </div>

                        {/* Subtask Badges */}
                        {/* Subtask Assignee */}
                        <div className="flex items-center gap-1.5 ml-auto flex-shrink-0">
                          {/* Status Inline Edit */}
                          <InlineStatusDropdown
                            task={subTask}
                            isLoading={isActionLoadingForTask?.(subTask._id)}
                            canUpdate={canUpdate("tasks")}
                            onStatusChange={onStatusChange || (async () => { })}
                          />

                          {/* Priority Inline Edit */}
                          <InlinePriorityDropdown
                            task={subTask}
                            isLoading={isActionLoadingForTask?.(subTask._id)}
                            canUpdate={canUpdate("tasks")}
                            onPriorityChange={onPriorityChange || (async () => { })}
                          />

                          {/* Due Date Inline Edit */}
                          <InlineDueDateInput
                            task={subTask}
                            isLoading={isActionLoadingForTask?.(subTask._id)}
                            canUpdate={canUpdate("tasks")}
                            onDueDateChange={onDueDateChange || (async () => { })}
                          />

                          {/* Assignee Inline Edit */}
                          <InlineAssigneeDropdown
                            task={subTask}
                            isLoading={isActionLoadingForTask?.(subTask._id)}
                            assigneeLoading={usersLoading}
                            canUpdate={canUpdate("tasks")}
                            users={departmentUsers}
                            onAssigneeChange={onAssigneeChange || (async () => { })}
                          />
                        </div>
                      </div>

                      {/* Subtask Actions */}
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm" className="h-7 w-7 p-0 ml-2 opacity-0 group-hover/subtask:opacity-100 transition-opacity hover:bg-muted">
                            <MoreHorizontal className="h-3.5 w-3.5" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-40">
                          <DropdownMenuItem onClick={() => { onSelectTaskForDetails(subTask); onShowTaskDetails?.(true); }} className="text-xs" disabled={isActionLoadingForTask?.(subTask._id)}>
                            <Eye className="h-3.5 w-3.5 mr-2" />
                            View
                          </DropdownMenuItem>
                          {canUpdate('tasks') && (
                            <DropdownMenuItem onClick={() => onOpenEditTaskModal(subTask)} className="text-xs" disabled={isActionLoadingForTask?.(subTask._id)}>
                              <Edit className="h-3.5 w-3.5 mr-2" />
                              Edit
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuSeparator />
                          {canDelete('tasks') && !subTask.isDeleted && (
                            <DropdownMenuItem onClick={(e) => { e.stopPropagation(); onDeleteTask(subTask._id); }} className="text-red-600 focus:text-red-600 focus:bg-red-50 dark:focus:bg-red-950/30 text-xs" disabled={isActionLoadingForTask?.(subTask._id)}>
                              <Trash2 className="h-3.5 w-3.5 mr-2" />
                              Delete
                            </DropdownMenuItem>
                          )}
                          {canDelete('tasks') && subTask.isDeleted && (
                            <DropdownMenuItem onClick={(e) => { e.stopPropagation(); onRestoreTask(subTask._id); }} className="text-green-600 focus:text-green-600 focus:bg-green-50 dark:focus:bg-green-950/30 text-xs" disabled={isActionLoadingForTask?.(subTask._id)}>
                              <RefreshCw className="h-3.5 w-3.5 mr-2" />
                              Restore
                            </DropdownMenuItem>
                          )}
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
})

export const TaskTableView: React.FC<TaskViewProps> = memo(function TaskTableView({
  departmentId,
  departmentName,
  departmentTasks,
  collapsedTasks,
  canCreate,
  canUpdate,
  canDelete,
  onOpenCreateTaskModal,
  onOpenEditTaskModal,
  onDeleteTask,
  onRestoreTask,
  onToggleTaskCollapse,
  onSelectTaskForDetails,
  getSubTasks,
  onShowTaskDetails,
  isActionLoadingForTask,
  isActionLoadingForDepartment,
  onStatusChange,
  onPriorityChange,
  onDueDateChange,
  onAssigneeChange,
  departmentUsers,
  usersLoading,
}) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Summary</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Priority</TableHead>
          <TableHead>Assignee</TableHead>
          <TableHead>Due Date</TableHead>
          <TableHead>Subtasks</TableHead>
          <TableHead className="w-[90px]">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {departmentTasks.map((task) => {
          const subTasks = getSubTasks(task._id)
          const isCollapsed = collapsedTasks.has(task._id)
          const completedSubTasks = subTasks.filter((st) => st.status === "completed").length

          return (
            <Fragment key={task._id}>
              <TableRow className="align-top">
                <TableCell className="p-2">
                  <div className="flex gap-2">
                    <div className="flex gap-1">
                      {subTasks.length > 0 && (
                        <Button
                          title="Toggle Subtasks"
                          variant="ghost"
                          size="sm"
                          className="h-7 w-7 p-0"
                          onClick={(e) => {
                            e.stopPropagation()
                            onToggleTaskCollapse(task._id)
                          }}
                        >
                          {isCollapsed ? <ChevronDown className="h-4 w-4" /> : <ChevronUp className="h-4 w-4" />}
                        </Button>
                      )}
                      {task.status === "completed" ? (
                        <CheckCircle className="h-4 w-4 text-emerald-500 mt-1" />
                      ) : task.status === "in-progress" ? (
                        <ListTodo className="h-4 w-4 text-blue-500 mt-1" />
                      ) : (
                        <CheckSquare className="h-4 w-4 text-muted-foreground mt-1" />
                      )}
                    </div>
                    <div className="flex flex-col">
                      <div className="flex items-center gap-2 mb-2">
                        <div className="text-sm font-medium text-foreground">{task.title}{isActionLoadingForTask?.(task._id) && <RefreshCw className="inline-block h-3 w-3 ml-2 text-muted-foreground animate-spin" />}</div>
                        {task.dueDate && new Date(task.dueDate) < new Date() && task.status !== "completed" && (
                          <Badge variant="destructive" className="text-xs whitespace-nowrap">
                            Overdue
                          </Badge>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground mb-2">
                        <HtmlTextRenderer
                          content={task.description}
                          maxLength={200}
                          className="line-clamp-3"
                          fallbackText="No description"
                          showFallback={true}
                          renderAsHtml={true}
                          truncateHtml={true}
                        />
                      </div>
                    </div>
                  </div>
                </TableCell>
                <TableCell className="p-2">
                  <InlineStatusDropdown
                    task={task}
                    isLoading={isActionLoadingForTask?.(task._id)}
                    canUpdate={canUpdate("tasks")}
                    onStatusChange={onStatusChange || (async () => { })}
                  />
                </TableCell>
                <TableCell className="p-2">
                  <InlinePriorityDropdown
                    task={task}
                    isLoading={isActionLoadingForTask?.(task._id)}
                    canUpdate={canUpdate("tasks")}
                    onPriorityChange={onPriorityChange || (async () => { })}
                  />
                </TableCell>
                {/* Assignee Inline Edit */}
                <TableCell className="p-2">
                  <InlineAssigneeDropdown
                    task={task}
                    isLoading={isActionLoadingForTask?.(task._id)}
                    assigneeLoading={usersLoading}
                    canUpdate={canUpdate("tasks")}
                    users={departmentUsers}
                    onAssigneeChange={onAssigneeChange || (async () => { })}
                  />
                </TableCell>
                <TableCell className="p-2">
                  <InlineDueDateInput
                    task={task}
                    isLoading={isActionLoadingForTask?.(task._id)}
                    canUpdate={canUpdate("tasks")}
                    onDueDateChange={onDueDateChange || (async () => { })}
                  />
                </TableCell>
                <TableCell className="p-2">
                  {subTasks.length > 0 ? `${completedSubTasks}/${subTasks.length}` : "—"}
                </TableCell>
                <TableCell className="pl-6">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild title="Perform Actions(delete, edit, add)">
                      <Button variant="ghost" size="sm" className="h-8 w-8 p-0" onClick={(e) => e.stopPropagation()}>
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-44" aria-label="Task actions menu">
                      {canCreate("tasks") && (
                        <DropdownMenuItem
                          onClick={(e) => {
                            e.stopPropagation()
                            onOpenCreateTaskModal(departmentId, departmentName, task._id)
                          }}
                        >
                          <Plus className="h-3.5 w-3.5 mr-1" />
                          Subtask
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuItem
                        onClick={() => {
                          onSelectTaskForDetails(task)
                          onShowTaskDetails?.(true)
                        }}
                        disabled={isActionLoadingForTask?.(task._id)}
                      >
                        <Eye className="h-4 w-4 mr-2" />
                        View Details
                      </DropdownMenuItem>
                      {canUpdate("tasks") && (
                        <DropdownMenuItem onClick={() => onOpenEditTaskModal(task)} disabled={isActionLoadingForTask?.(task._id)}>
                          <Edit className="h-4 w-4 mr-2" />
                          Edit
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuSeparator />
                      {canDelete("tasks") && (
                        <DropdownMenuItem
                          onClick={(e) => { e.stopPropagation(); onDeleteTask(task._id); }}
                          className="text-red-600 focus:text-red-600 focus:bg-red-50 dark:focus:bg-red-950/30"
                          disabled={isActionLoadingForTask?.(task._id)}
                        >
                          <Trash2 className="h-4 w-4 mr-2" />
                          Delete
                        </DropdownMenuItem>
                      )}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
              {/* Subtasks rows */}
              {subTasks.length > 0 &&
                !isCollapsed &&
                subTasks.map((subTask) => (
                  <TableRow key={subTask._id} className="bg-muted/20">
                    <TableCell className="p-2">
                      <div className="ml-8 flex items-center gap-2">
                        {subTask.status === "completed" ? (
                          <CheckCircle className="h-4 w-4 text-emerald-500" />
                        ) : subTask.type === "main-task" ? (
                          <ListTodo className="h-4 w-4 text-blue-500" />
                        ) : (
                          <CheckSquare className="h-4 w-4 text-muted-foreground" />
                        )}
                        <div className="flex items-center gap-2 mb-2">
                          <span className="text-xs font-medium">{subTask.title}</span>
                          {subTask.dueDate && new Date(subTask.dueDate) < new Date() && subTask.status !== "completed" && (
                            <Badge variant="destructive" className="text-xs whitespace-nowrap">
                              Overdue
                            </Badge>
                          )}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="p-2">
                      <InlineStatusDropdown
                        task={subTask}
                        isLoading={isActionLoadingForTask?.(subTask._id)}
                        canUpdate={canUpdate("tasks")}
                        onStatusChange={onStatusChange || (async () => { })}
                      />
                    </TableCell>
                    <TableCell className="p-2">
                      <InlinePriorityDropdown
                        task={subTask}
                        isLoading={isActionLoadingForTask?.(subTask._id)}
                        canUpdate={canUpdate("tasks")}
                        onPriorityChange={onPriorityChange || (async () => { })}
                      />
                    </TableCell>
                    {/* Subtask Assignee */}
                    <TableCell className="p-2 text-xs">
                      <InlineAssigneeDropdown
                        task={subTask}
                        isLoading={isActionLoadingForTask?.(subTask._id)}
                        assigneeLoading={usersLoading}
                        canUpdate={canUpdate("tasks")}
                        users={departmentUsers}
                        onAssigneeChange={onAssigneeChange || (async () => { })}
                      />
                    </TableCell>
                    <TableCell className="p-2 text-xs">
                      <InlineDueDateInput
                        task={subTask}
                        isLoading={isActionLoadingForTask?.(subTask._id)}
                        canUpdate={canUpdate("tasks")}
                        onDueDateChange={onDueDateChange || (async () => { })}
                      />
                    </TableCell>
                    <TableCell className="p-2 text-xs">—</TableCell>
                    <TableCell className="pl-6">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild title="Perform Actions(delete, edit, add)">
                          <Button variant="ghost" size="sm" className="h-8 w-8 p-0" onClick={(e) => e.stopPropagation()}>
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-40" aria-label="Task actions menu">
                          <DropdownMenuItem onClick={() => { onSelectTaskForDetails(subTask); onShowTaskDetails?.(true); }} className="text-xs" disabled={isActionLoadingForTask?.(subTask._id)}>
                            <Eye className="h-3.5 w-3.5 mr-2" />
                            View
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => onOpenEditTaskModal(subTask)} className="text-xs" disabled={isActionLoadingForTask?.(subTask._id)}>
                            <Edit className="h-3.5 w-3.5 mr-2" />
                            Edit
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem onClick={(e) => { e.stopPropagation(); onDeleteTask(subTask._id); }} className="text-red-600 focus:text-red-600 focus:bg-red-50 dark:focus:bg-red-950/30 text-xs" disabled={isActionLoadingForTask?.(subTask._id)}>
                            <Trash2 className="h-3.5 w-3.5 mr-2" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
            </Fragment>
          )
        })}
      </TableBody>
    </Table>
  )
})

export const TaskBoardView: React.FC<
  Omit<TaskViewProps, "collapsedTasks" | "onToggleTaskCollapse" | "getSubTasks"> & {
    // Removed collapsedTasks, onToggleTaskCollapse, and getSubTasks as they are not used here
    onHandleDragStart?: (event: DragStartEvent) => void
    onHandleDragEnd: (event: DragEndEvent) => void
    sensors: any // sensors prop moved from TaskViewProps
    draggingTask?: any
    isActionLoadingForTask?: (taskId: string) => boolean
    isActionLoadingForDepartment?: (departmentId: string) => boolean
  }
> = memo(function TaskBoardView({
  departmentId,
  departmentName,
  departmentTasks,
  canCreate,
  canUpdate,
  canDelete,
  onOpenCreateTaskModal,
  onOpenEditTaskModal,
  onDeleteTask,
  onRestoreTask,
  onSelectTaskForDetails,
  getDepartmentName,
  sensors,
  onHandleDragStart,
  onHandleDragEnd,
  onShowTaskDetails,
  isActionLoadingForTask,
  isActionLoadingForDepartment,
  draggingTask,
  onStatusChange,
  onPriorityChange,
  onDueDateChange,
  onAssigneeChange,
  departmentUsers,
  usersLoading,
}) {
  const statuses = ["pending", "in-progress", "on-hold", "completed", "closed"]
  const [collapsedColumns, setCollapsedColumns] = useState<Set<string>>(new Set())

  const toggleColumnCollapse = (columnId: string) => {
    setCollapsedColumns((s) => {
      const copy = new Set(s)
      if (copy.has(columnId)) copy.delete(columnId)
      else copy.add(columnId)
      return copy
    })
  }

  // Memoize sorted tasks by status to prevent unnecessary re-renders
  const tasksByStatus = useMemo(() => {
    const result: Record<string, any[]> = {}
    statuses.forEach(status => {
      result[status] = departmentTasks
        .filter((t) => (t.status || "pending") === status)
        .sort((a, b) => {
          // Sort by order field first, then by creation date
          const orderA = a.order || 0
          const orderB = b.order || 0
          if (orderA !== orderB) return orderA - orderB
          return new Date(a.createdAt || 0).getTime() - new Date(b.createdAt || 0).getTime()
        })
    })
    return result
  }, [departmentTasks, statuses])

  return (
    <DndContext
      onDragStart={onHandleDragStart}
      onDragEnd={onHandleDragEnd}
      sensors={sensors}
      collisionDetection={closestCenter}
    >
      <div className="flex gap-3 p-4 h-full w-100 overflow-x-auto">
        {statuses.map((status) => {
          const columnId = `${departmentId}::${status}`
          const columnTasks = tasksByStatus[status] || []
          return (
            <div
              key={columnId}
              className={cn(
                collapsedColumns.has(columnId) ? 'flex-initial min-w-[48px] w-auto' : 'flex-1 min-w-[350px] max-w-sm',
                'transition-all duration-300 ease-in-out'
              )}
            >
              <SortableContext
                items={columnTasks.map((t) => String(t._id))}
                strategy={verticalListSortingStrategy}
              >
                <BoardColumn
                  id={columnId}
                  title={status}
                  tasks={columnTasks}
                  collapsed={collapsedColumns.has(columnId)}
                  onToggleCollapse={() => toggleColumnCollapse(columnId)}
                  departmentId={departmentId}
                  onOpenCreateTaskModal={onOpenCreateTaskModal}
                  getDepartmentName={getDepartmentName}
                  onSelectTaskForDetails={onSelectTaskForDetails}
                  onShowTaskDetails={onShowTaskDetails}
                  isActionLoadingForDepartment={isActionLoadingForDepartment}
                  isActionLoadingForTask={isActionLoadingForTask}
                  draggingTask={draggingTask}
                  onOpenEditTaskModal={onOpenEditTaskModal}
                  onDeleteTask={onDeleteTask}
                  onRestoreTask={onRestoreTask}
                  canUpdate={canUpdate}
                  canDelete={canDelete}
                  onStatusChange={onStatusChange}
                  onPriorityChange={onPriorityChange}
                  onDueDateChange={onDueDateChange}
                  onAssigneeChange={onAssigneeChange}
                  departmentUsers={departmentUsers}
                  usersLoading={usersLoading}
                />
              </SortableContext>
            </div>
          )
        })}
      </div>
      <DragOverlay
        dropAnimation={{
          duration: 200,
          easing: 'cubic-bezier(0.18, 0.67, 0.6, 1.22)',
        }}
        zIndex={1000}
      >
        {draggingTask ? (
          <Card className="p-3 border border-border bg-card shadow-2xl transform rotate-3 scale-105 transition-all" style={{ width: '300px' }}>
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <div className="flex flex-col min-w-0">
                  <div className="text-sm font-medium mr-6">{draggingTask.title}</div>
                  {/* Compact metadata row for board view - no description */}
                  <div className="flex items-center gap-2 mt-3 text-xs text-muted-foreground justify-between flex-wrap">
                    <div className="flex items-center gap-1 flex-wrap">
                      {/* Task Order Number */}
                      <Badge variant="secondary" className="text-xs h-5 px-1.5 bg-slate-100 dark:bg-slate-800">
                        #{draggingTask.order || draggingTask._id?.toString().slice(-4).toUpperCase()}
                      </Badge>
                      {draggingTask.dueDate && new Date(draggingTask.dueDate) < new Date() && draggingTask.status !== "completed" && (
                        <Badge variant="destructive" className="text-xs whitespace-nowrap">
                          Overdue
                        </Badge>
                      )}
                      {/* Priority Inline Dropdown - Available in all views */}
                      {draggingTask.priority && (
                        <div onClick={(e) => e.stopPropagation()} onPointerDown={(e) => e.stopPropagation()}>
                          <InlinePriorityDropdown
                            task={draggingTask}
                            isLoading={isActionLoadingForTask?.(draggingTask._id)}
                            canUpdate={canUpdate?.("tasks")}
                            onPriorityChange={onPriorityChange || (async () => { })}
                          />
                        </div>
                      )}

                      {/* Due date inline edit - Available in all views */}
                      {draggingTask.dueDate && (
                        <div onClick={(e) => e.stopPropagation()} onPointerDown={(e) => e.stopPropagation()}>
                          <InlineDueDateInput
                            task={draggingTask}
                            isLoading={isActionLoadingForTask?.(draggingTask._id)}
                            canUpdate={canUpdate?.("tasks")}
                            onDueDateChange={onDueDateChange || (async () => { })}
                          />
                        </div>
                      )}
                    </div>

                    {/* Assignee - Always editable via dropdown with pointer-events handling */}
                    <div onClick={(e) => e.stopPropagation()} onPointerDown={(e) => e.stopPropagation()}>
                      <InlineAssigneeDropdown
                        task={draggingTask}
                        isLoading={isActionLoadingForTask?.(draggingTask._id)}
                        assigneeLoading={usersLoading}
                        canUpdate={canUpdate?.("tasks")}
                        users={departmentUsers}
                        onAssigneeChange={onAssigneeChange || (async () => { })}
                      />
                    </div>

                  </div>
                </div>
              </div>
            </div>
          </Card>
        ) : null}
      </DragOverlay>
    </DndContext>
  )
})
