"use client";

import React, { useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { SearchableSelect } from "@/components/shared/generic-form";
import CustomModal from "@/components/shared/custom-modal";
import RichTextEditor from "@/components/shared/rich-text-editor";
import HtmlTextRenderer from "@/components/shared/html-text-renderer";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
    DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import {
    InlineStatusDropdown,
    InlinePriorityDropdown,
    InlineDueDateInput,
    InlineAssigneeDropdown,
} from "@/components/projects/InlineTaskEditUtils";
import { Label } from "@/components/ui/label";
import { RefreshCw, Plus, Trash2, Edit3, MoreVertical, Eye, Edit, MoreHorizontal, ChevronDown, ChevronUp, CheckCircle, ListTodo, CheckSquare } from "lucide-react";
import { TaskCommentsSection } from "@/components/projects/TaskCommentsSection";
import { TimeTrackingSection } from "@/components/projects/TimeTrackingSection";
import { useUsers } from '@/hooks/use-users';
import { useQueryClient } from '@tanstack/react-query'
import { useTasks } from '@/hooks/use-tasks';
import { useGenericQueryById } from '@/hooks/use-generic-query';
import { useToast } from '@/hooks/use-toast';
import { createTaskFormSchema, updateTaskFormSchema, CreateTaskFormData } from '@/lib/validations/task';
import { User as UserType, Task, CreateTaskData, UpdateTaskData } from '@/types';
import { Clock, AlertCircle, User, CheckCircle2, Edit2, UserPlus } from "lucide-react";
type TaskModalMode = 'create' | 'edit' | 'assign';

interface TaskModalProps {
    isOpen: boolean;
    onClose: () => void;
    mode: TaskModalMode;
    task?: Task | null;
    projectId: string;
    departmentId?: string;
    departmentName?: string;
    parentTaskId?: string;
    onSuccess?: () => void;
}

export function TaskModal({
    isOpen,
    onClose,
    mode,
    task,
    projectId,
    departmentId,
    departmentName,
    parentTaskId,
    onSuccess
}: TaskModalProps) {
    const { toast } = useToast();
    const [loading, setLoading] = React.useState(false);
    const { users } = useUsers();
    const { createTask, updateTask, assignTask, isActionLoadingForTask } = useTasks();
    
    const targetProjectId = (mode === 'edit' || mode === 'assign') && task ? task.projectId : projectId;

    // Form schema based on mode
    const getFormSchema = () => {
        if (mode === 'create') return createTaskFormSchema;
        return updateTaskFormSchema;
    };

    // Form setup
    const form = useForm<CreateTaskFormData>({
        mode: 'onSubmit',
        resolver: zodResolver(getFormSchema()),
        defaultValues: {
            title: "",
            description: "",
            projectId,
            departmentId,
            status: (task && task.status) || 'pending',
            type: parentTaskId ? "sub-task" : "task",
            priority: "medium",
            parentTaskId: parentTaskId || "",
            assigneeId: "",
            dueDate: "",
            estimatedHours: "",
        },
    });

    // Reset form when modal opens/closes or mode changes
    useEffect(() => {
        if (isOpen) {
            if (mode === 'create') {
                form.reset({
                    title: "",
                    description: "",
                    projectId,
                    departmentId,
                    type: parentTaskId ? "sub-task" : "task",
                    status: task?.status || 'pending',
                    priority: "medium",
                    parentTaskId: parentTaskId || "",
                    assigneeId: "",
                    dueDate: "",
                    estimatedHours: "",
                });
            } else if (mode === 'edit' && task) {
                form.reset({
                    title: task.title,
                    description: task.description || "",
                    projectId: task.projectId,
                    departmentId: task.departmentId,
                    type: task.type,
                    status: task.status || 'pending',
                    priority: task.priority,
                    parentTaskId: task.parentTaskId || "",
                    assigneeId: task.assigneeId || "",
                    dueDate: task.dueDate ? new Date(task.dueDate).toISOString().split('T')[0] : "",
                    estimatedHours: task.estimatedHours ? task.estimatedHours.toString() : "",
                });
            } else if (mode === 'assign' && task) {
                form.reset({
                    title: task.title,
                    description: task.description || "",
                    projectId: task.projectId,
                    departmentId: task.departmentId,
                    type: task.type,
                    priority: task.priority,
                    parentTaskId: task.parentTaskId || "",
                    assigneeId: task.assigneeId || "",
                    dueDate: task.dueDate ? new Date(task.dueDate).toISOString().split('T')[0] : "",
                    estimatedHours: task.estimatedHours ? task.estimatedHours.toString() : "",
                });
            }
        } else {
            form.reset();
        }
    }, [isOpen, mode, task, projectId, departmentId, parentTaskId, form]);

    // Get department users for assignment with better error handling
    const { departmentUsers, usersLoading } = React.useMemo(() => {
        // Use the task's departmentId for edit and assign modes to ensure consistency
        const targetDepartmentId = (mode === 'edit' || mode === 'assign') && task ? task.departmentId : departmentId;

        if (!targetDepartmentId) {
            return { departmentUsers: [], usersLoading: false };
        }

        if (!users || users.length === 0) {
            return { departmentUsers: [], usersLoading: true };
        }

        const result = users.filter(user => {
            return user?.department?._id === targetDepartmentId && 
                   user?.status === 'active' &&
                   user?._id && 
                   user?.name;
        });

        return { departmentUsers: result, usersLoading: false };
    }, [users, departmentId, mode, task]);

    // Handle form submission
    const handleSubmit = async (data: CreateTaskFormData) => {
        // Prevent double-action if the task is currently in progress
        if ((mode === 'edit' || mode === 'assign') && task && isActionLoadingForTask?.(task._id)) {
            toast({ title: 'Please wait', description: 'This task is already being updated', variant: 'destructive' })
            return
        }
        setLoading(true);
        try {
            if (mode === 'create') {
                // Transform form data to match API expectations for create
                const transformedData: CreateTaskData = {
                    title: data.title,
                    description: data.description,
                    projectId: data.projectId,
                    departmentId: data.departmentId,
                    parentTaskId: data.parentTaskId || undefined,
                    assigneeId: data.assigneeId === 'unassigned' ? undefined : data.assigneeId,
                    status: data.status,
                    priority: data.priority,
                    type: data.type,
                    // Convert string fields to numbers where needed
                    estimatedHours: data.estimatedHours ? parseFloat(data.estimatedHours) : undefined,
                    actualHours: data.actualHours ? parseFloat(data.actualHours) : undefined,
                    // Convert date strings to Date objects
                    startDate: data.startDate ? new Date(data.startDate) : undefined,
                    dueDate: data.dueDate ? new Date(data.dueDate) : undefined,
                };

                await createTask(transformedData);
                toast({
                    title: "Task Created",
                    description: `${data.type === 'task' ? 'Task' : 'Sub-task'} "${data.title}" has been created successfully.`,
                });
            } else if (mode === 'edit' && task) {
                // Transform form data to match API expectations for update
                const transformedData: UpdateTaskData = {
                    title: data.title,
                    description: data.description,
                    projectId: data.projectId,
                    departmentId: data.departmentId,
                    parentTaskId: data.parentTaskId || undefined,
                    assigneeId: data.assigneeId === 'unassigned' ? undefined : data.assigneeId,
                    status: data.status,
                    priority: data.priority,
                    type: data.type,
                    // Convert string fields to numbers where needed
                    estimatedHours: data.estimatedHours ? parseFloat(data.estimatedHours) : undefined,
                    actualHours: data.actualHours ? parseFloat(data.actualHours) : undefined,
                    // Convert date strings to Date objects
                    startDate: data.startDate ? new Date(data.startDate) : undefined,
                    dueDate: data.dueDate ? new Date(data.dueDate) : undefined,
                };

                await updateTask(task._id!, transformedData);
                toast({
                    title: "Task Updated",
                    description: `Task "${data.title}" has been updated successfully.`,
                });
            } else if (mode === 'assign' && task) {
                if (data.assigneeId && data.assigneeId !== 'unassigned' && data.assigneeId !== task.assigneeId) {
                    await assignTask(task._id!, data.assigneeId);
                    const assigneeName = departmentUsers.find(u => u._id === data.assigneeId)?.name || 'Unknown';
                    toast({
                        title: "Task Assigned",
                        description: `Task "${task.title}" has been assigned to ${assigneeName}.`,
                    });
                } else if (data.assigneeId === 'unassigned' && task.assigneeId) {
                    await assignTask(task._id!, ""); // Unassign
                    toast({
                        title: "Task Unassigned",
                        description: `Task "${task.title}" has been unassigned.`,
                    });
                }
            }

            onSuccess?.();
            onClose();
        } catch (error: any) {
            toast({
                title: `${mode === 'create' ? 'Creation' : mode === 'edit' ? 'Update' : 'Assignment'} Failed`,
                description: error.message || `Failed to ${mode} task`,
                variant: "destructive",
            });
        } finally {
            setLoading(false);
        }
    };

    // Get modal title and icon
    const getModalTitle = () => {
        if (mode === 'create') {
            const taskType = form.watch('type') === 'sub-task' ? 'Sub-Task' : 'Task';
            return `Create New ${taskType}`;
        } else if (mode === 'edit') {
            const taskType = task?.type === 'sub-task' ? 'Sub-Task' : 'Task';
            return `Edit ${taskType}`;
        } else {
            return 'Assign Task';
        }
    };

    const getModalIcon = () => {
        if (mode === 'create') return CheckCircle2;
        if (mode === 'edit') return Edit2;
        return UserPlus;
    };

    // Check if fields should be disabled
    const isFieldDisabled = (fieldName: string) => {
        if (mode === 'assign') {
            return fieldName !== 'assigneeId';
        }
        return false;
    };

    const priorityConfig = {
        low: { color: 'bg-blue-100 text-blue-800', icon: Clock },
        medium: { color: 'bg-yellow-100 text-yellow-800', icon: Clock },
        high: { color: 'bg-orange-100 text-orange-800', icon: AlertCircle },
        urgent: { color: 'bg-red-100 text-red-800', icon: AlertCircle }
    };

    const Icon = getModalIcon();

    return (
        <CustomModal
            isOpen={isOpen}
            onClose={onClose}
            title={getModalTitle()}
            modalSize="lg"
        >
            <div className="space-y-6">
                {/* Header */}
                <div className="flex items-center gap-3 pb-4 border-b">
                    <div className="p-2 bg-primary/10 rounded-lg">
                        <Icon className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                        <h3 className="text-lg font-semibold">{getModalTitle()}</h3>
                        <p className="text-sm text-muted-foreground">
                            {mode === 'create' && `Create a new ${form.watch('type') === 'sub-task' ? 'sub-task' : 'task'} for ${departmentName}`}
                            {mode === 'edit' && `Edit task details and properties`}
                            {mode === 'assign' && `Assign task to team member in ${departmentName}`}
                        </p>
                    </div>
                </div>

                {/* Form */}
                <Form {...form}>
                    <form onSubmit={form.handleSubmit(handleSubmit)} className="space-y-4">
                        <div className="grid grid-cols-1 gap-4">
                            {/* Title Field */}
                            <FormField
                                control={form.control}
                                name="title"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>Task Title</FormLabel>
                                        <FormControl>
                                            <Input
                                                placeholder="Enter task title"
                                                disabled={isFieldDisabled('title')}
                                                {...field}
                                            />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />

                            {/* Description Field */}
                            <FormField
                                control={form.control}
                                name="description"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>Description</FormLabel>
                                        <FormControl>
                                            <RichTextEditor
                                                value={field.value || ''}
                                                onChange={field.onChange}
                                                placeholder="Task description (optional)"
                                                disabled={loading || isFieldDisabled('description')}
                                                height="100px"
                                            />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />

                            <div className="grid grid-cols-2 gap-4">
                                {/* Priority Field */}
                                <FormField
                                    control={form.control}
                                    name="priority"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>Priority</FormLabel>
                                            <FormControl>
                                                <SearchableSelect
                                                    options={[
                                                        { label: "Low Priority", value: "low" },
                                                        { label: "Medium Priority", value: "medium" },
                                                        { label: "High Priority", value: "high" },
                                                        { label: "Urgent Priority", value: "urgent" }
                                                    ]}
                                                    value={field.value}
                                                    onValueChange={field.onChange}
                                                    placeholder="Select priority..."
                                                    disabled={isFieldDisabled('priority')}
                                                />
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />

                                {/* Assignee Field */}
                                <FormField
                                    control={form.control}
                                    name="assigneeId"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>
                                                {mode === 'assign' ? 'Assignee' : 'Assignee (Optional)'}
                                                {mode === 'assign' && <span className="text-red-500 ml-1">*</span>}
                                            </FormLabel>
                                            <FormControl>
                                                <SearchableSelect
                                                    options={[
                                                        { label: "No assignee", value: "unassigned" },
                                                        ...departmentUsers.map((user: UserType) => ({
                                                            label: `${user.name} (${user.email})`,
                                                            value: user._id!
                                                        }))
                                                    ]}
                                                    value={field.value || "unassigned"}
                                                    onValueChange={field.onChange}
                                                    placeholder={usersLoading ? "Loading users..." : departmentUsers.length === 0 ? "No users in department" : "Search and select assignee..."}
                                                    disabled={isFieldDisabled('assigneeId') || usersLoading}
                                                />
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                            </div>

                            {/* Date Fields - Only for create and edit modes */}
                            {mode !== 'assign' && (
                                <div className="grid grid-cols-2 gap-4">
                                    {/* Due Date Field */}
                                    <FormField
                                        control={form.control}
                                        name="dueDate"
                                        render={({ field }) => (
                                            <FormItem>
                                                <FormLabel>Due Date (Optional)</FormLabel>
                                                <FormControl>
                                                    <Input
                                                        type="date"
                                                        {...field}
                                                        disabled={isFieldDisabled('dueDate')}
                                                    />
                                                </FormControl>
                                                <FormMessage />
                                            </FormItem>
                                        )}
                                    />

                                    {/* Estimated Hours Field */}
                                    <FormField
                                        control={form.control}
                                        name="estimatedHours"
                                        render={({ field }) => (
                                            <FormItem>
                                                <FormLabel>Estimated Hours (Optional)</FormLabel>
                                                <FormControl>
                                                    <Input
                                                        type="number"
                                                        min="0"
                                                        step="0.5"
                                                        placeholder="0"
                                                        {...field}
                                                        disabled={isFieldDisabled('estimatedHours')}
                                                    />
                                                </FormControl>
                                                <FormMessage />
                                            </FormItem>
                                        )}
                                    />
                                </div>
                            )}

                            {/* Type Field - Hidden but needed for validation */}
                            <FormField
                                control={form.control}
                                name="type"
                                render={({ field }) => (
                                    <input type="hidden" {...field} />
                                )}
                            />

                            {/* Project and Department IDs - Hidden but needed for validation */}
                            <FormField
                                control={form.control}
                                name="projectId"
                                render={({ field }) => (
                                    <input type="hidden" {...field} />
                                )}
                            />

                            <FormField
                                control={form.control}
                                name="departmentId"
                                render={({ field }) => (
                                    <input type="hidden" {...field} />
                                )}
                            />

                            {/* Parent Task ID - Hidden but needed for sub-tasks */}
                            {parentTaskId && (
                                <FormField
                                    control={form.control}
                                    name="parentTaskId"
                                    render={({ field }) => (
                                        <input type="hidden" {...field} />
                                    )}
                                />
                            )}
                        </div>

                        {/* Action Buttons */}
                        <div className="flex justify-end gap-2 pt-4">
                            <Button
                                type="button"
                                variant="outline"
                                onClick={onClose}
                                disabled={loading}
                            >
                                Cancel
                            </Button>
                            <Button
                                type="submit"
                                disabled={loading || ((task && isActionLoadingForTask?.(task._id)) ?? false)}
                            >
                                {loading ? (
                                    mode === 'create' ? "Creating..." :
                                        mode === 'edit' ? "Updating..." :
                                            "Assigning..."
                                ) : (
                                    mode === 'create' ? `Create ${form.watch('type') === 'sub-task' ? 'Sub-Task' : 'Task'}` :
                                        mode === 'edit' ? "Update Task" :
                                            "Assign Task"
                                )}
                            </Button>
                        </div>
                    </form>
                </Form>
            </div>
        </CustomModal>
    );
}

// Sub-component: Department Manager Modal
export function DepartmentManagerModal({
    isOpen,
    onClose,
    categorizationForm,
    departments,
    departmentsLoading,
    modalLoading,
    departmentToAdd,
    setDepartmentToAdd,
    setModalLoading,
    isDepartmentLoading,
    departmentOperationLoading,
    handleDepartmentToggle,
    getDepartmentsToRender,
    getDepartmentName
}: any) {
    const departmentsToRender = (getDepartmentsToRender?.() || [])
    return (
        <CustomModal
            isOpen={isOpen}
            onClose={onClose}
            title="Manage Project Departments"
            modalSize="md"
        >
            <div className="space-y-4">
                <p className="text-sm text-muted-foreground">Add or remove departments used for project categorization and task creation. Only active departments can be assigned to projects.</p>
                <div>
                    <SearchableSelect
                        options={(Array.isArray(departments) ? departments : [])
                            .filter((d: any) => {
                                try {
                                    // Only show active departments
                                    if (d?.status !== 'active') return false

                                    const selected = (categorizationForm?.getValues('departmentIds') || [])
                                        .map(String);
                                    return !selected.includes(String(d?._id));
                                } catch (e) {
                                    return true;
                                }
                            })
                            .map((d: any) => ({ label: d?.name || 'Unknown', value: String(d?._id) }))}
                        value={departmentToAdd}
                        onValueChange={(v: any) => setDepartmentToAdd(v)}
                        placeholder="Select an active department to add"
                        disabled={departmentsLoading || modalLoading}
                        loading={departmentsLoading}
                    />
                </div>

                <div className="flex items-center gap-2 justify-end">
                    <Button variant="outline" onClick={onClose}>Cancel</Button>
                    <Button
                        onClick={async () => {
                            if (!departmentToAdd) return;
                            setModalLoading?.(true);
                            try {
                                // Add using toggle helper - it'll persist using applyUpdatedDepartments
                                await handleDepartmentToggle(departmentToAdd, false);
                                setDepartmentToAdd(undefined);
                            } catch (e) {
                                console.error('Error adding department:', e);
                            } finally {
                                setModalLoading?.(false);
                            }
                        }}
                        disabled={!departmentToAdd || modalLoading}
                    >
                        {modalLoading ? <RefreshCw className="h-4 w-4 mr-2 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
                        Add
                    </Button>
                </div>

                <div>
                    <div className="text-sm text-muted-foreground mb-2">Selected Departments <span className="ml-2 text-xs text-muted-foreground">({departmentsToRender.length})</span></div>
                    <div className="flex flex-wrap gap-2">
                        {departmentsToRender.length === 0 ? (
                            <div className="text-sm text-muted-foreground">No departments selected</div>
                        ) : (
                            departmentsToRender.map((sd: any) => (
                                <div key={sd.departmentId} className="flex items-center gap-2 bg-card/40 border border-border rounded-full px-3 py-1">
                                    <span className="text-sm">{getDepartmentName(sd.departmentId)}</span>
                                    <Button variant="ghost" size="icon" onClick={async () => { await handleDepartmentToggle(sd.departmentId, true); }} disabled={isDepartmentLoading?.(sd.departmentId) || modalLoading}>
                                        <Trash2 className="h-4 w-4 text-destructive" />
                                    </Button>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            </div>
        </CustomModal>
    );
}

// Sub-component: Task Details Modal
export function TaskDetailsModal({
    isOpen,
    onClose,
    // support both prop names used across the codebase for flexibility
    selectedTask,
    task,
    projectId,
    onTaskUpdate,
    getDepartmentName,
    // new handlers passed from parent for consistent behavior
    onOpenCreateTaskModal,
    onDeleteTask,
    isActionLoadingForDepartment,
    // Inline edit props
    isActionLoadingForTask,
    canUpdate,
    canDelete,
    canCreate,
    onStatusChange,
    onPriorityChange,
    onDueDateChange,
    onAssigneeChange,
    departmentUsers,
    usersLoading,
    // handlers for nested task actions
    onOpenEditTaskModal,
    onOpenTaskDetails,
}: any) {
    // allow either `selectedTask` or `task` prop to be used
    const selected = selectedTask || task
    if (!selected) return null;

    // Fetch fresh task details if possible
    const taskOptions = React.useMemo(() => ({ entityName: 'tasks', baseUrl: '/api/tasks' }), [])
    const { data: freshTask /*, isLoading */ } = useGenericQueryById(taskOptions, String(selected._id), !!selected._id)
    const taskToShow = freshTask || selected
    const queryClient = useQueryClient()
    const { updateTask: updateTaskHook, assignTask: assignTaskHook, tasks: allTasks } = useTasks()
    const { toast } = useToast()

    // UI state: whether we are editing the task inline in the details modal
    const [isEditing, setIsEditing] = React.useState(false)
    const [subtasksCollapsed, setSubtasksCollapsed] = React.useState(true)
    const subTasksForCurrent = React.useMemo(() => {
        try {
            if (!allTasks || !taskToShow || !taskToShow._id) return []
            return (allTasks || []).filter((t: any) => String(t.parentTaskId || '') === String(taskToShow._id) && String(t.projectId || '') === String(projectId || ''))
        } catch (e) {
            return []
        }
    }, [allTasks, taskToShow?._id, projectId])

    // Setup form for inline edit using the same schema as the edit modal
    const editForm = useForm<CreateTaskFormData>({
        mode: 'onSubmit',
        resolver: zodResolver(updateTaskFormSchema),
        defaultValues: {
            title: taskToShow.title || '',
            description: taskToShow.description || '',
            projectId: String(taskToShow.projectId || ''),
            departmentId: String(taskToShow.departmentId || ''),
            status: taskToShow.status || 'pending',
            type: taskToShow.type || 'task',
            priority: taskToShow.priority || 'medium',
            parentTaskId: taskToShow.parentTaskId || '',
            assigneeId: taskToShow.assigneeId || 'unassigned',
            dueDate: taskToShow.dueDate ? new Date(taskToShow.dueDate).toISOString().split('T')[0] : '',
            estimatedHours: taskToShow.estimatedHours ? String(taskToShow.estimatedHours) : '',
        }
    })
    // Reset form when the shown task changes
    React.useEffect(() => {
        if (taskToShow) {
            editForm.reset({
                title: taskToShow.title || '',
                description: taskToShow.description || '',
                projectId: String(taskToShow.projectId || ''),
                departmentId: String(taskToShow.departmentId || ''),
                status: taskToShow.status || 'pending',
                type: taskToShow.type || 'task',
                priority: taskToShow.priority || 'medium',
                parentTaskId: taskToShow.parentTaskId || '',
                assigneeId: taskToShow.assigneeId || 'unassigned',
                dueDate: taskToShow.dueDate ? new Date(taskToShow.dueDate).toISOString().split('T')[0] : '',
                estimatedHours: taskToShow.estimatedHours ? String(taskToShow.estimatedHours) : '',
            })
        }
    }, [taskToShow])

    // If modal is closed, reset editing state
    React.useEffect(() => {
        if (!isOpen) setIsEditing(false)
    }, [isOpen])
    return (
        <CustomModal
            isOpen={isOpen}
            onClose={onClose}
            title={taskToShow.title}
            modalSize="lg"
            position="top-right"
            headerActions={
                <div className="flex items-center gap-2">
                    {canUpdate?.("tasks") ? (
                        !isEditing ? (
                            <Button variant="outline" size="sm" className="h-7" onClick={() => setIsEditing(true)}>
                                <Edit3 className="h-3.5 w-3.5" />
                                Edit
                            </Button>
                        ) : (
                            <Button variant="ghost" size="sm" className="h-7" onClick={() => setIsEditing(false)}>
                                Close Edit
                            </Button>
                        )
                    ) : null}
                    <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                            <Button variant="outline" size="sm" className="h-7 w-7">
                                <MoreVertical className="h-4 w-4" />
                            </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                            {onOpenCreateTaskModal && canCreate && canCreate('tasks') && !taskToShow.parentTaskId && (
                                <DropdownMenuItem
                                    onClick={(e) => {
                                        e.stopPropagation()
                                        onOpenCreateTaskModal?.(
                                            String(taskToShow.departmentId || ''),
                                            (getDepartmentName && String(getDepartmentName(String(taskToShow.departmentId || '')))) || undefined,
                                            taskToShow._id,
                                        )
                                    }}
                                >
                                    <Plus className="h-4 w-4" />
                                    Add Sub Task
                                </DropdownMenuItem>
                            )}
                            {canDelete?.("tasks") && (
                                <DropdownMenuItem
                                    className="text-destructive"
                                    disabled={isActionLoadingForTask?.(taskToShow._id) || isActionLoadingForDepartment?.(String(taskToShow.departmentId || ''))}
                                    onClick={(e) => {
                                        e.stopPropagation()
                                        onDeleteTask?.(taskToShow._id)
                                    }}
                                >
                                    <Trash2 className="h-4 w-4" />
                                    Delete Task
                                </DropdownMenuItem>
                            )}
                        </DropdownMenuContent>
                    </DropdownMenu>
                </div>
            }
        >
            <div className="space-y-6">
                {/* Task Info - inline editable controls OR edit form */}
                <div>
                    {!isEditing && (
                        <>
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <Label>Status</Label>
                                    <div className="mt-2">
                                        <InlineStatusDropdown
                                            task={taskToShow}
                                            isLoading={isActionLoadingForTask?.(taskToShow._id)}
                                            canUpdate={canUpdate?.("tasks")}
                                            onStatusChange={onStatusChange || (async () => { })}
                                        />
                                    </div>
                                </div>
                                <div>
                                    <Label>Priority</Label>
                                    <div className="mt-2">
                                        <InlinePriorityDropdown
                                            task={taskToShow}
                                            isLoading={isActionLoadingForTask?.(taskToShow._id)}
                                            canUpdate={canUpdate?.("tasks")}
                                            onPriorityChange={onPriorityChange || (async () => { })}
                                        />
                                    </div>
                                </div>
                                <div>
                                    <Label>Due Date</Label>
                                    <div className="mt-2">
                                        <InlineDueDateInput
                                            task={taskToShow}
                                            isLoading={isActionLoadingForTask?.(taskToShow._id)}
                                            canUpdate={canUpdate?.("tasks")}
                                            onDueDateChange={onDueDateChange || (async () => { })}
                                        />
                                    </div>
                                </div>
                                <div>
                                    <Label>Assignee</Label>
                                    <div className="mt-2">
                                        <InlineAssigneeDropdown
                                            task={taskToShow}
                                            isLoading={isActionLoadingForTask?.(taskToShow._id)}
                                            assigneeLoading={usersLoading}
                                            canUpdate={canUpdate?.("tasks")}
                                            users={departmentUsers}
                                            onAssigneeChange={onAssigneeChange || (async () => { })}
                                        />
                                    </div>
                                </div>
                            </div>
                            {taskToShow.description && (
                                <div>
                                    <Label>Description</Label>
                                    <HtmlTextRenderer
                                        content={taskToShow.description}
                                        maxLength={120}
                                        fallbackText="No description"
                                        showFallback={true}
                                        renderAsHtml={true}
                                    />
                                </div>
                            )}

                    {/* Subtasks list for main tasks (collapsible) */}
                    {!isEditing && !taskToShow.parentTaskId && subTasksForCurrent.length > 0 && (
                        <div className="mt-4">
                                <div className="flex items-center justify-between mb-2">
                                    <div className="flex items-center gap-2">
                                        <h4 className="font-medium">Subtasks</h4>
                                        <Badge variant="secondary" className="text-xs h-5">{subTasksForCurrent.length}</Badge>
                                    </div>
                                    <div>
                                        <Button variant="ghost" size="sm" className="h-7" onClick={() => setSubtasksCollapsed(prev => !prev)}>
                                            {subtasksCollapsed ? <ChevronDown className="h-4 w-4" /> : <ChevronUp className="h-4 w-4" />}
                                        </Button>
                                    </div>
                                </div>
                                {!subtasksCollapsed && (
                                    <div className="space-y-2">
                                        {subTasksForCurrent.map((sub: any) => (
                                            <div key={sub._id} className="flex items-center justify-between p-3 rounded-lg bg-muted/40 hover:bg-muted/60 transition-colors border border-border/50">
                                                <div className="flex items-center gap-3 min-w-0">
                                                    {sub.status === 'completed' ? (
                                                        <CheckCircle className="h-4 w-4 text-emerald-500" />
                                                    ) : sub.type === 'main-task' ? (
                                                        <ListTodo className="h-4 w-4 text-blue-500" />
                                                    ) : (
                                                        <CheckSquare className="h-4 w-4 text-muted-foreground" />
                                                    )}
                                                    <div className="flex flex-col min-w-0">
                                                        <div className="flex items-center gap-2 mb-1">
                                                            <div className="font-medium text-sm truncate">{sub.title}</div>
                                                            {isActionLoadingForTask?.(sub._id) && <RefreshCw className="h-3 w-3 ml-2 text-muted-foreground animate-spin" />}
                                                        </div>
                                                        <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                                            <InlineStatusDropdown task={sub} isLoading={isActionLoadingForTask?.(sub._id)} canUpdate={canUpdate?.('tasks')} onStatusChange={onStatusChange || (async () => {})} />
                                                            <InlinePriorityDropdown task={sub} isLoading={isActionLoadingForTask?.(sub._id)} canUpdate={canUpdate?.('tasks')} onPriorityChange={onPriorityChange || (async () => {})} />
                                                            {sub.dueDate && <InlineDueDateInput task={sub} isLoading={isActionLoadingForTask?.(sub._id)} canUpdate={canUpdate?.('tasks')} onDueDateChange={onDueDateChange || (async () => {})} />}
                                                        </div>
                                                    </div>
                                                </div>
                                                <div className="flex items-center gap-2">
                                                    <DropdownMenu>
                                                        <DropdownMenuTrigger asChild>
                                                            <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={(e) => e.stopPropagation()}>
                                                                <MoreHorizontal className="h-4 w-4" />
                                                            </Button>
                                                        </DropdownMenuTrigger>
                                                        <DropdownMenuContent align="end" className="w-40">
                                                            <DropdownMenuItem onClick={(e) => { e.stopPropagation(); onOpenTaskDetails?.(sub); }} className="text-xs" disabled={isActionLoadingForTask?.(sub._id)}>
                                                                <Eye className="h-3.5 w-3.5 mr-2" />
                                                                View
                                                            </DropdownMenuItem>
                                                            {canUpdate?.('tasks') && (
                                                                <DropdownMenuItem onClick={(e) => { e.stopPropagation(); onOpenEditTaskModal?.(sub); }} className="text-xs" disabled={isActionLoadingForTask?.(sub._id)}>
                                                                    <Edit className="h-3.5 w-3.5 mr-2" />
                                                                    Edit
                                                                </DropdownMenuItem>
                                                            )}
                                                            <DropdownMenuSeparator />
                                                            {canDelete?.('tasks') && (
                                                                <DropdownMenuItem onClick={(e) => { e.stopPropagation(); onDeleteTask?.(sub._id); }} className="text-red-600 text-xs" disabled={isActionLoadingForTask?.(sub._id) || isActionLoadingForDepartment?.(String(sub.departmentId || ''))}>
                                                                    <Trash2 className="h-3.5 w-3.5 mr-2" />
                                                                    Delete
                                                                </DropdownMenuItem>
                                                            )}
                                                        </DropdownMenuContent>
                                                    </DropdownMenu>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                    )}
                        </>
                    )}

                    {/* Edit form when toggled */}
                    {isEditing && (
                        <div className="mt-4">
                            <Form {...editForm}>
                                <form
                                    onSubmit={editForm.handleSubmit(async (data) => {
                                        try {
                                            // transform incoming values
                                            const transformed: UpdateTaskData = {
                                                title: data.title,
                                                description: data.description,
                                                projectId: data.projectId,
                                                departmentId: data.departmentId,
                                                parentTaskId: data.parentTaskId || undefined,
                                                assigneeId: data.assigneeId === 'unassigned' ? undefined : data.assigneeId,
                                                status: data.status,
                                                priority: data.priority,
                                                estimatedHours: data.estimatedHours ? parseFloat(data.estimatedHours) : undefined,
                                                startDate: data.startDate ? new Date(data.startDate) : undefined,
                                                dueDate: data.dueDate ? new Date(data.dueDate) : undefined,
                                            }

                                            // If only assignee changed we can call assignTask for clarity
                                            const onlyAssigneeChanged = (data.title === (taskToShow.title || '') &&
                                                data.description === (taskToShow.description || '') &&
                                                data.status === (taskToShow.status || 'pending') &&
                                                data.priority === (taskToShow.priority || 'medium') &&
                                                data.dueDate === (taskToShow.dueDate ? new Date(taskToShow.dueDate).toISOString().split('T')[0] : '') &&
                                                data.assigneeId !== (taskToShow.assigneeId || 'unassigned'))

                                            if (onlyAssigneeChanged) {
                                                await assignTaskHook(taskToShow._id, data.assigneeId === 'unassigned' ? '' : data.assigneeId || "")
                                            } else {
                                                await updateTaskHook(taskToShow._id, transformed)
                                            }

                                            // Refresh cache for this task and tasks lists
                                            queryClient.invalidateQueries({
                                                predicate: (query) => {
                                                    const key = query.queryKey
                                                    if (!key) return false
                                                    if (key[0] === 'tasks') return true
                                                    return false
                                                }
                                            })

                                            setIsEditing(false)
                                            toast({ title: 'Task Updated', description: 'The task was updated successfully.' })
                                            onTaskUpdate?.()
                                        } catch (err: any) {
                                            toast({ title: 'Update Failed', description: err?.message || 'Failed to update task', variant: 'destructive' })
                                        }
                                    })}
                                    className="space-y-4"
                                >
                                    <div className="grid grid-cols-1 gap-4">
                                        <FormField control={editForm.control} name="title" render={({ field }) => (
                                            <FormItem>
                                                <FormLabel>Title</FormLabel>
                                                <FormControl>
                                                    <Input {...field} />
                                                </FormControl>
                                                <FormMessage />
                                            </FormItem>
                                        )} />

                                        <FormField control={editForm.control} name="description" render={({ field }) => (
                                            <FormItem>
                                                <FormLabel>Description</FormLabel>
                                                <FormControl>
                                                    <RichTextEditor value={field.value} onChange={field.onChange} />
                                                </FormControl>
                                                <FormMessage />
                                            </FormItem>
                                        )} />

                                        <div className="grid grid-cols-2 gap-4">
                                            <FormField control={editForm.control} name="priority" render={({ field }) => (
                                                <FormItem>
                                                    <FormLabel>Priority</FormLabel>
                                                    <FormControl>
                                                        <SearchableSelect
                                                            options={[{ label: 'Low', value: 'low' }, { label: 'Medium', value: 'medium' }, { label: 'High', value: 'high' }, { label: 'Urgent', value: 'urgent' }]}
                                                            value={field.value}
                                                            onValueChange={field.onChange}
                                                        />
                                                    </FormControl>
                                                    <FormMessage />
                                                </FormItem>
                                            )} />

                                            <FormField control={editForm.control} name="assigneeId" render={({ field }) => (
                                                <FormItem>
                                                    <FormLabel>Assignee</FormLabel>
                                                    <FormControl>
                                                        <SearchableSelect
                                                            options={[
                                                                { label: 'Unassigned', value: 'unassigned' },
                                                                ...(departmentUsers || []).map((u: any) => ({ label: u.name, value: String(u._id) }))
                                                            ]}
                                                            value={field.value}
                                                            onValueChange={field.onChange}
                                                            placeholder="Select assignee"
                                                            disabled={usersLoading}
                                                        />
                                                    </FormControl>
                                                    <FormMessage />
                                                </FormItem>
                                            )} />
                                        </div>

                                        <div className="grid grid-cols-2 gap-4">
                                            <FormField control={editForm.control} name="status" render={({ field }) => (
                                                <FormItem>
                                                    <FormLabel>Status</FormLabel>
                                                    <FormControl>
                                                        <SearchableSelect
                                                            options={[
                                                                { label: 'Pending', value: 'pending' },
                                                                { label: 'In Progress', value: 'in-progress' },
                                                                { label: 'On Hold', value: 'on-hold' },
                                                                { label: 'Completed', value: 'completed' },
                                                                { label: 'Cancelled', value: 'cancelled' },
                                                                { label: 'Closed', value: 'closed' },
                                                                { label: 'Deleted', value: 'deleted' },
                                                            ]}
                                                            value={field.value}
                                                            onValueChange={field.onChange}
                                                        />
                                                    </FormControl>
                                                    <FormMessage />
                                                </FormItem>
                                            )} />

                                            <FormField control={editForm.control} name="dueDate" render={({ field }) => (
                                                <FormItem>
                                                    <FormLabel>Due Date</FormLabel>
                                                    <FormControl>
                                                        <Input type="date" {...field} />
                                                    </FormControl>
                                                    <FormMessage />
                                                </FormItem>
                                            )} />
                                        </div>
                                    </div>

                                    <div className="flex justify-end gap-2 pt-2">
                                        <Button type="button" variant="outline" onClick={() => { setIsEditing(false); editForm.reset(); }}>
                                            Cancel
                                        </Button>
                                        <Button type="submit" disabled={isActionLoadingForTask?.(taskToShow._id) || (editForm.formState.isSubmitting)}>
                                            Save
                                        </Button>
                                    </div>
                                </form>
                            </Form>
                        </div>
                    )}
                </div>

                {/* Comments Section */}
                <TaskCommentsSection
                    taskId={taskToShow._id}
                    projectId={projectId}
                    departmentId={taskToShow.departmentId}
                />

                {/* Time Tracking Section */}
                <TimeTrackingSection
                    taskId={taskToShow._id}
                    projectId={projectId}
                    estimatedHours={taskToShow.estimatedHours}
                    currentActualHours={taskToShow.actualHours}
                />
            </div>
        </CustomModal>
    );
}