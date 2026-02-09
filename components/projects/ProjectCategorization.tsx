"use client"

import { useState, useEffect, useMemo, useCallback, memo, useRef, createRef } from "react"
import { useForm } from "react-hook-form"
import { Button } from "@/components/ui/button"
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Plus, CheckSquare, Building2, ChevronDown, ChevronUp } from "lucide-react"
import { TaskModal, DepartmentManagerModal, TaskDetailsModal } from "@/components/projects/TaskModal"
import { useDepartments } from "@/hooks/use-departments"
import { useTasks } from "@/hooks/use-tasks"
import { useAppDispatch } from '@/hooks/redux'
import { setTasks } from '@/store/slices/taskSlice'
import { useUsers } from "@/hooks/use-users"
import { useProject } from "@/hooks/use-projects"
import { usePermissions } from "@/hooks/use-permissions"
import { useToast } from "@/hooks/use-toast"
import Swal from "sweetalert2"
import { Grid3X3, List, Filter } from "lucide-react"
import { InlineLoader } from '@/components/ui/loader'
import { type DragEndEvent, type DragStartEvent, PointerSensor, useSensor, useSensors } from "@dnd-kit/core"

import { TaskGridView, TaskTableView, TaskBoardView } from "@/components/projects/TaskDataViews"
import GenericFilter, { FilterConfig } from '@/components/shared/generic-filter'
import { useQueryClient } from '@tanstack/react-query'


interface ProjectCategorizationProps {
    projectId: string
    project: any
    onProjectUpdate?: () => void
}

interface DepartmentSelection {
    departmentId: string
    additionalInfo: string
}

export const ProjectCategorization = memo(function ProjectCategorization({
    projectId,
    project,
    onProjectUpdate,
}: ProjectCategorizationProps) {
    const { toast } = useToast()
    const [loading, setLoading] = useState(false)
    const [taskModal, setTaskModal] = useState<{
        isOpen: boolean
        mode: "create" | "edit" | "assign"
        task?: any
        departmentId?: string
        departmentName?: string
        parentTaskId?: string
    }>({
        isOpen: false,
        mode: "create",
    })
    const [showTaskDetails, setShowTaskDetails] = useState(false)
    const [selectedTaskForDetails, setSelectedTaskForDetails] = useState<any>(null)
    const [collapsedTasks, setCollapsedTasks] = useState<Set<string>>(new Set())
    const [collapsedDepartments, setCollapsedDepartments] = useState<Set<string>>(new Set())
    const [selectedDepartments, setSelectedDepartments] = useState<DepartmentSelection[]>([])
    const [departmentModalOpen, setDepartmentModalOpen] = useState(false)
    const [departmentToAdd, setDepartmentToAdd] = useState<string | undefined>(undefined)
    const [modalLoading, setModalLoading] = useState(false)
    const [departmentOperationLoading, setDepartmentOperationLoading] = useState<Set<string>>(new Set())
    const [taskView, setTaskView] = useState<"grid" | "table" | "board">(() => {
        try {
            const pid = projectId || 'global'
            const saved = typeof window !== 'undefined' ? window.localStorage.getItem(`taskView:${pid}`) : null
            if (saved === 'grid' || saved === 'table' || saved === 'board') return saved
            // fallback to global key
            const fallback = typeof window !== 'undefined' ? window.localStorage.getItem(`taskView:global`) : null
            if (fallback === 'grid' || fallback === 'table' || fallback === 'board') return fallback
        } catch (e) {
            /* ignore */
        }
        return 'grid'
    })

    const setTaskViewAndPersist = useCallback((view: "grid" | "table" | "board") => {
        setTaskView(view)
        try {
            const pid = projectId || 'global'
            if (typeof window !== 'undefined') window.localStorage.setItem(`taskView:${pid}`, view)
        } catch (e) {
            // ignore localStorage errors
        }
    }, [projectId])

    const pointerSensor = useSensor(PointerSensor)
    const sensors = useSensors(
        useSensor(PointerSensor, {
            activationConstraint: {
                distance: 8,
            },
        })
    )
    const [draggingTask, setDraggingTask] = useState<any | null>(null)

    const { departments, loading: departmentsLoading, error: departmentsError } = useDepartments()
    const {
        tasks,
        createTask,
        updateTask,
        deleteTask,
        restoreTask,
        bulkOrderUpdate,
        loading: taskLoading,
        setFilters: setTaskFilters,
        filters,
        refreshTasks,
        error: tasksError,
        isActionLoadingForTask,
        isActionLoadingForDepartment,
    } = useTasks()
    // filters are obtained from the hook destructure above
    const {
        users,
        loading: usersLoading,
        setFilters: setUserFilters,
        clearError: clearUserError,
        fetchUsers,
    } = useUsers()
    const { updateProject } = useProject()
    const { canCreate, canUpdate, canDelete } = usePermissions()
    const dispatch = useAppDispatch()
    const queryClient = useQueryClient()

    useEffect(() => {
        setUserFilters({})
        clearUserError()
        if (users.length === 0) {
            fetchUsers()
        }
    }, [])

    // Ensure departments are loaded for proper department name resolution
    useEffect(() => {
        if (!departmentsLoading && (!departments || departments.length === 0)) {
            console.log('ProjectCategorization: No departments found, triggering refresh...')
            // Trigger a background refresh of departments
            queryClient.invalidateQueries({ queryKey: ['departments'] })
        }
    }, [departments, departmentsLoading, queryClient])

    const selectedDepartmentIds = useMemo(() => selectedDepartments.map((d) => d.departmentId), [selectedDepartments])

    // Set task filters only once on projectId change - don't continuously refresh
    const initialFiltersSetRef = useRef(false)

    useEffect(() => {
        if (!projectId || typeof projectId !== "string") return

        // Only set filters once for this projectId to enable initial data fetch
        if (!initialFiltersSetRef.current) {
            setTaskFilters({ projectId })
            initialFiltersSetRef.current = true
        }
    }, [projectId, setTaskFilters])

    useEffect(() => {
        const handleVisibilityChange = () => {
            if (!document.hidden && selectedDepartments.length > 0) {
                // Could refresh if needed
            }
        }

        document.addEventListener("visibilitychange", handleVisibilityChange)
        return () => document.removeEventListener("visibilitychange", handleVisibilityChange)
    }, [])

    const categorizationForm = useForm<{ departmentIds: string[] }>({
        defaultValues: {
            departmentIds: [] as string[],
        },
    })

    const watchedDepartmentIds = categorizationForm.watch("departmentIds")

    const getDepartmentName = useCallback(
        (departmentId: string) => {
            if (!departmentId) return "No Department"
            
            if (!Array.isArray(departments)) {
                // If departments is not loaded yet, show loading state
                return departmentsLoading ? "Loading..." : "No Departments Available"
            }

            try {
                const department = departments.find((d) => d?._id === departmentId)
                if (department) {
                    return department.name || "Unnamed Department"
                }
                
                // If not found and departments are still loading, show loading state
                if (departmentsLoading) {
                    return "Loading..."
                }
                
                // Return a more user-friendly message with partial ID for debugging
                console.log("Department not found for ID:", departmentId, "Available departments:", departments.length)
                return `Department (${departmentId.slice(-6)})`
            } catch (error) {
                console.error("Error finding department name:", error)
                return "Error Loading Department"
            }
        },
        [departments, departmentsLoading],
    )

    const tableFilterForm = useForm({
        defaultValues: {
            q: "",
            status: "all",
            priority: "all",
        },
    })
    const [qFilter, statusFilter, priorityFilter] = tableFilterForm.watch(["q", "status", "priority"])
    const onTableFilterSubmit = (data: any) => {
        // We'll use form watch for live filtering
    }

    // Generic filter state - for department specific toggles
    const [deptFilterOpen, setDeptFilterOpen] = useState<Record<string, boolean>>({})
    const deptFilterButtonRefs = useRef<Record<string, React.RefObject<HTMLButtonElement | null>>>({})
    const [globalFilterOpen, setGlobalFilterOpen] = useState(false)
    const globalFilterButtonRef = useRef<HTMLButtonElement | null>(null)
    const [appliedDeptFilters, setAppliedDeptFilters] = useState<Record<string, any>>({})
    // Compute number of applied global filters (ignore projectId/departmentId)
    const globalFilterCount = useMemo(() => {
        const keys = ['search', 'status', 'priority', 'assigneeId', 'dueDateFrom', 'dueDateTo']
        if (!filters) return 0
        return keys.reduce((count, k) => {
            const v = (filters as any)[k]
            if (v === undefined || v === null) return count
            if (v === '' || v === 'all') return count
            return count + 1
        }, 0)
    }, [filters])

    // Build options for assignee select (active users only)
    const assigneeOptions = useMemo(() => {
        return users
            .filter(u => u.status === 'active')
            .map(u => ({ value: String(u._id), label: u.name }))
    }, [users])

    const globalFilterConfig: FilterConfig = useMemo(() => ({
        fields: [
            { key: 'search', label: 'Search', type: 'text', placeholder: 'Search task title or description', cols: 12 },
            {
                key: 'status', label: 'Status', type: 'select', placeholder: 'All', options: [
                    { value: 'all', label: 'All' },
                    { value: 'pending', label: 'Pending' },
                    { value: 'in-progress', label: 'In Progress' },
                    { value: 'on-hold', label: 'On Hold' },
                    { value: 'completed', label: 'Completed' },
                    { value: 'closed', label: 'Closed' },
                ], cols: 6
            },
            {
                key: 'priority', label: 'Priority', type: 'select', placeholder: 'All', options: [
                    { value: 'all', label: 'All' },
                    { value: 'low', label: 'Low' },
                    { value: 'medium', label: 'Medium' },
                    { value: 'high', label: 'High' },
                    { value: 'urgent', label: 'Urgent' },
                ], cols: 6
            },
            { key: 'assigneeId', label: 'Assignee', type: 'select', placeholder: 'Any', options: [{ value: 'all', label: 'Any' }, ...assigneeOptions], searchable: true, cols: 12 },
            { key: 'dueDateFrom', label: 'Due Date From', type: 'date', cols: 6 },
            { key: 'dueDateTo', label: 'Due Date To', type: 'date', cols: 6 },
        ]
        ,
        defaultValues: { search: '', status: 'all', priority: 'all', assigneeId: 'all', dueDateFrom: '', dueDateTo: '' }
    }), [assigneeOptions])

    // Provide a department-scoped filter config so the assignee select only shows department users
    const getDepartmentFilterConfig = useCallback((departmentId: string) => {
        const deptUsers = users.filter(u => String(u.department?._id) === String(departmentId) && u.status === 'active')
        const deptAssigneeOptions = [{ value: 'all', label: 'Any' }, ...deptUsers.map(u => ({ value: String(u._id), label: u.name }))]

        // Copy base config and replace assignee select options
        const fields = globalFilterConfig.fields.map((f) => {
            if (f.key === 'assigneeId') {
                return { ...f, options: deptAssigneeOptions }
            }
            return f
        })

        return { ...globalFilterConfig, fields }
    }, [globalFilterConfig, users])

    const applyFilters = useCallback((values: any, opts?: { departmentId?: string }) => {
        const mapped: any = {}
        if (opts?.departmentId) {
            // For dept filters we store values directly
            if (values.search) mapped.search = values.search
            if (values.status && values.status !== 'all') mapped.status = values.status
            if (values.priority && values.priority !== 'all') mapped.priority = values.priority
            if (values.assigneeId && values.assigneeId !== 'all') mapped.assigneeId = values.assigneeId
            if (values.dueDateFrom) mapped.dueDateFrom = values.dueDateFrom
            if (values.dueDateTo) mapped.dueDateTo = values.dueDateTo
        } else {
            // For global filters, always set the keys, defaulting to empty for clearing behavior
            mapped.search = values.search || ''
            mapped.status = values.status && values.status !== 'all' ? values.status : ''
            mapped.priority = values.priority && values.priority !== 'all' ? values.priority : ''
            mapped.assigneeId = values.assigneeId && values.assigneeId !== 'all' ? values.assigneeId : ''
            mapped.dueDateFrom = values.dueDateFrom || ''
            mapped.dueDateTo = values.dueDateTo || ''
        }
        mapped.projectId = projectId
        if (opts?.departmentId) mapped.departmentId = opts.departmentId
        if (opts?.departmentId) {
            // Per-department filters: keep them client-side in appliedDeptFilters
            setAppliedDeptFilters(prev => ({ ...prev, [opts.departmentId!]: values }))
        } else {
            // Global filter: update global filters which will refetch tasks
            setTaskFilters(mapped)
        }
    }, [projectId, setTaskFilters])

    // Watch existing table filters and apply live for quick queries
    useEffect(() => {
        const mapped: any = {
            projectId,
            search: qFilter || '',
            status: statusFilter && statusFilter !== 'all' ? statusFilter : '',
            priority: priorityFilter && priorityFilter !== 'all' ? priorityFilter : '',
            assigneeId: ''
        }
        setTaskFilters(mapped)
    }, [qFilter, statusFilter, priorityFilter, setTaskFilters, projectId])

    // Reset global filters
    const resetGlobalFilters = useCallback(() => {
        // Reset store filters to only projectId
        setTaskFilters({ projectId })
        // reset local quick filters
        try {
            tableFilterForm.reset({ q: '', status: 'all', priority: 'all' })
        } catch (e) {
            // ignore
        }
        // close the UI panel
        setGlobalFilterOpen(false)
    }, [projectId, setTaskFilters, tableFilterForm])

    const openCreateTaskModal = useCallback(
        (departmentId: string, departmentName: string, parentTaskId?: string, defaultTask?: any) => {
            setTaskModal({
                isOpen: true,
                mode: "create",
                departmentId,
                departmentName,
                parentTaskId,
                task: defaultTask,
            })
        },
        [],
    )

    const openEditTaskModal = useCallback(
        (task: any) => {
            setTaskModal({
                isOpen: true,
                mode: "edit",
                task,
                departmentId: task.departmentId,
                departmentName: getDepartmentName(task.departmentId),
            })
        },
        [getDepartmentName],
    )

    const closeTaskModal = useCallback(() => {
        setTaskModal({
            isOpen: false,
            mode: "create",
        })
    }, [])

    const openDepartmentModal = useCallback(() => {
        setDepartmentToAdd(undefined)
        setDepartmentModalOpen(true)
    }, [])

    const closeDepartmentModal = useCallback(() => {
        setDepartmentToAdd(undefined)
        setDepartmentModalOpen(false)
    }, [])

    // Handle toggling (add/remove) departments from the project - called by DepartmentManagerModal


    useEffect(() => {
        let departmentIds: string[] | undefined

        if (project?.departmentIds && Array.isArray(project.departmentIds) && project.departmentIds.length > 0) {
            departmentIds = project.departmentIds.map((id: any) => (typeof id === "string" ? id : id.toString()))
        } else if (
            project?.departmentTasks &&
            Array.isArray(project.departmentTasks) &&
            project.departmentTasks.length > 0
        ) {
            departmentIds = project.departmentTasks.map((deptTask: any) => deptTask.departmentId.toString())
        }

        const formDepartmentIds = categorizationForm.getValues("departmentIds") || []
        if (selectedDepartments.length === 0 && formDepartmentIds.length === 0) {
            if (departmentIds && departmentIds.length > 0) {
                const deptSelections: DepartmentSelection[] = departmentIds.map(
                    (deptId: any): DepartmentSelection => ({
                        departmentId: String(deptId),
                        additionalInfo: "",
                    }),
                )
                setSelectedDepartments(deptSelections)
                categorizationForm.setValue("departmentIds", departmentIds)
                toast({
                    title: "Project Departments Loaded",
                    description: `${departmentIds.length} departments loaded for this project`,
                })
            } else if (project) {
                if (tasks.length > 0) {
                    const taskDepartmentIds = [
                        ...new Set(
                            tasks
                                .filter((task) => task.projectId?.toString() === projectId.toString() && task.departmentId)
                                .map((task) => task.departmentId.toString()),
                        ),
                    ]
                    if (taskDepartmentIds.length > 0) {
                        const inferredDeptSelections: DepartmentSelection[] = taskDepartmentIds.map(
                            (deptId: any): DepartmentSelection => ({
                                departmentId: String(deptId),
                                additionalInfo: "",
                            }),
                        )
                        setSelectedDepartments(inferredDeptSelections)
                        categorizationForm.setValue("departmentIds", taskDepartmentIds)
                        toast({
                            title: "Departments Inferred",
                            description: `Found ${taskDepartmentIds.length} departments from existing tasks`,
                            variant: "default",
                        })
                    }
                }
            }
        }
    }, [project, projectId, tasks.length])

    const toggleTaskCollapse = useCallback((taskId: string) => {
        setCollapsedTasks((prev) => {
            const newSet = new Set(prev)
            if (newSet.has(taskId)) {
                newSet.delete(taskId)
            } else {
                newSet.add(taskId)
            }
            return newSet
        })
    }, [])

    const toggleDepartmentCollapse = useCallback((departmentId: string) => {
        setCollapsedDepartments((prev) => {
            const newSet = new Set(prev)
            if (newSet.has(departmentId)) {
                newSet.delete(departmentId)
            } else {
                newSet.add(departmentId)
            }
            return newSet
        })
    }, [])

    useEffect(() => {
        if (departmentsError) {
            toast({
                variant: "destructive",
                title: "Error",
                description: "Failed to load departments",
            })
        }

        if (tasksError) {
            toast({
                variant: "destructive",
                title: "Error",
                description: "Failed to load tasks",
            })
        }
    }, [departmentsError, tasksError, toast])

    const applyUpdatedDepartments = async (updatedDepartments: string[], retryCount = 0): Promise<boolean> => {
        const maxRetries = 3
        try {
            setLoading(true)

            if (!projectId || typeof projectId !== "string" || projectId.length !== 24) {
                const msg = "Project ID is missing or invalid — cannot update departments."
                toast({ variant: "destructive", title: "Error", description: msg })
                if (project?.departmentIds) {
                    const reverted: DepartmentSelection[] = project.departmentIds.map((id: any) => ({
                        departmentId: String(id),
                        additionalInfo: "",
                    }))
                    setSelectedDepartments(reverted)
                    categorizationForm.setValue("departmentIds", project.departmentIds)
                }
                return false
            }

            const updatedSelections: DepartmentSelection[] = updatedDepartments.map((deptId: string) => ({
                departmentId: deptId,
                additionalInfo: "",
            }))
            setSelectedDepartments(updatedSelections)
            categorizationForm.setValue("departmentIds", updatedDepartments)

            const invalidDept = updatedDepartments.find((d) => typeof d !== "string" || !/^[0-9a-fA-F]{24}$/.test(d))
            if (invalidDept) {
                toast({
                    variant: "destructive",
                    title: "Validation Error",
                    description: "One or more selected departments are invalid.",
                })
                if (project?.departmentIds) {
                    const reverted: DepartmentSelection[] = project.departmentIds.map((id: any) => ({
                        departmentId: String(id),
                        additionalInfo: "",
                    }))
                    setSelectedDepartments(reverted)
                    categorizationForm.setValue("departmentIds", project.departmentIds)
                }
                return false
            }

            // Determine which departments changed so we can only reload those
            const existingDeptIds: string[] = (project?.departmentIds && Array.isArray(project.departmentIds) ? project.departmentIds.map((d: any) => (typeof d === "string" ? d : String(d))) : [])
            const added = updatedDepartments.filter((d) => !existingDeptIds.includes(d))
            const removed = existingDeptIds.filter((d) => !updatedDepartments.includes(d))
            const changed = [...new Set([...added, ...removed])]

            // Mark changed departments as loading
            setDepartmentOperationLoading((prev) => {
                const newSet = new Set(prev)
                changed.forEach((id) => newSet.add(id))
                return newSet
            })

            await updateProject(projectId, { operation: "categorize", departmentIds: updatedDepartments } as any)

            if (onProjectUpdate) onProjectUpdate()

            // After update, only invalidate queries for changed departments to trigger minimal refetch
            // This ensures React Query refetches only the affected department data
            try {
                for (const deptId of changed) {
                    // Invalidate queries that match this specific department
                    await queryClient.invalidateQueries({
                        queryKey: ['tasks'],
                        predicate: (query) => {
                            const qFilters = (query.queryKey[3] as any)
                            return qFilters?.projectId === projectId && (!qFilters?.departmentId || qFilters.departmentId === deptId)
                        }
                    })
                }
            } finally {
                // Clear per-department loading flags
                setDepartmentOperationLoading((prev) => {
                    const newSet = new Set(prev)
                    changed.forEach((id) => newSet.delete(id))
                    return newSet
                })
            }

            toast({
                title: "Success",
                description: `Project departments updated successfully (${updatedDepartments.length} departments selected)`,
            })
            return true
        } catch (error: any) {
            const isRateLimit =
                error?.statusCode === 429 ||
                (typeof error?.error === "string" && error.error.includes("Too many requests")) ||
                (typeof error?.message === "string" && error.message.includes("Too many requests"))
            const retryAfter = error?.retryAfter || (error?.headers?.["retry-after"] ?? error?.headers?.["Retry-After"])

            if (isRateLimit && retryCount < maxRetries) {
                const waitTime = retryAfter ? Number.parseInt(retryAfter) * 1000 : Math.pow(2, retryCount) * 1000
                console.log(`Rate limited, retrying in ${waitTime}ms (attempt ${retryCount + 1}/${maxRetries})`)
                await new Promise((resolve) => setTimeout(resolve, waitTime))
                return applyUpdatedDepartments(updatedDepartments, retryCount + 1)
            }

            try {
                console.error("Error applying updated departments:", JSON.stringify(error, null, 2))
            } catch (e) {
                console.error("Error applying updated departments:", error)
            }

            // Provide better error message to user
            let errorMessage = "Failed to persist department changes"
            if (error?.message) {
                errorMessage = error.message
            } else if (error?.error) {
                errorMessage = error.error
            }

            toast({
                variant: "destructive",
                title: "Error",
                description: errorMessage,
            })

            if (project?.departmentIds) {
                const reverted: DepartmentSelection[] = project.departmentIds.map((id: any) => ({
                    departmentId: String(id),
                    additionalInfo: "",
                }))
                setSelectedDepartments(reverted)
                categorizationForm.setValue("departmentIds", project.departmentIds)
            }
            return false
        } finally {
            setLoading(false)
            setModalLoading(false)
        }
    }


    const handleDepartmentToggle = useCallback(async (deptId: string, remove: boolean) => {
        // guard
        if (!projectId) return
        setModalLoading(true)
        setDepartmentOperationLoading((prev) => {
            const newSet = new Set(prev)
            newSet.add(deptId)
            return newSet
        })
        try {
            const current = categorizationForm.getValues('departmentIds') || []
            const normalized = current.map(String)
            let newList: string[]
            if (remove) {
                newList = normalized.filter((id) => id !== deptId)
            } else {
                newList = Array.from(new Set([...normalized, deptId]))
            }
            await applyUpdatedDepartments(newList)
        } finally {
            setModalLoading(false)
            setDepartmentOperationLoading((prev) => {
                const newSet = new Set(prev)
                newSet.delete(deptId)
                return newSet
            })
        }
    }, [applyUpdatedDepartments, projectId])
    const handleDeleteTask = async (taskId: string) => {
        const result = await Swal.fire({
            customClass: {
                popup: "swal-bg",
                title: "swal-title",
                htmlContainer: "swal-content",
            },
            title: "Are you sure?",
            text: "You won't be able to revert this!",
            icon: "warning",
            showCancelButton: true,
            confirmButtonColor: "#d33",
            cancelButtonColor: "#3085d6",
            confirmButtonText: "Yes, delete it!",
        })

        if (result.isConfirmed) {
            try {
                await deleteTask(taskId)
                // Don't refresh all tasks, just update query cache for affected department
                const taskToDelete = tasks.find(t => t._id?.toString() === taskId)
                if (taskToDelete) {
                    // Invalidate only the query for this specific department to trigger minimal refetch
                    await queryClient.invalidateQueries({
                        queryKey: ['tasks'],
                        predicate: (query) => {
                            const qFilters = (query.queryKey[3] as any)
                            return qFilters?.departmentId === taskToDelete.departmentId?.toString()
                        }
                    })
                }
                if (onProjectUpdate) {
                    onProjectUpdate()
                }

                toast({
                    title: "Success",
                    description: "Task deleted successfully",
                })
            } catch (error) {
                console.error("Error deleting task:", error)
                toast({
                    variant: "destructive",
                    title: "Error",
                    description: "Failed to delete task",
                })
            }
        }
    }

    const handleRestoreTask = async (taskId: string) => {
        const result = await Swal.fire({
            customClass: {
                popup: "swal-bg",
                title: "swal-title",
                htmlContainer: "swal-content",
            },
            title: "Restore Task?",
            text: "Are you sure you want to restore this task?",
            icon: "question",
            showCancelButton: true,
            showConfirmButton: true,
            confirmButtonText: "Yes, Restore",
            cancelButtonText: "No",
            confirmButtonColor: "#10b981",
        })

        if (result.isConfirmed) {
            try {
                await restoreTask(taskId)
                // Invalidate queries
                const taskToRestore = tasks.find(t => t._id?.toString() === taskId)
                if (taskToRestore) {
                    await queryClient.invalidateQueries({
                        queryKey: ['tasks'],
                        predicate: (query) => {
                            const qFilters = (query.queryKey[3] as any)
                            return qFilters?.departmentId === taskToRestore.departmentId?.toString()
                        }
                    })
                }
                if (onProjectUpdate) {
                    onProjectUpdate()
                }

                toast({
                    title: "Success",
                    description: "Task restored successfully",
                })
            } catch (error) {
                console.error("Error restoring task:", error)
                toast({
                    variant: "destructive",
                    title: "Error",
                    description: "Failed to restore task",
                })
            }
        }
    }

    // Inline update handlers for status, priority, due date, and assignee
    const handleInlineStatusChange = useCallback(async (taskId: string, newStatus: string) => {
        const task = tasks.find(t => t._id?.toString() === taskId)
        if (!task) throw new Error("Task not found")

        // Optimistic update
        const previousTasks = tasks
        dispatch(setTasks(tasks.map(t => t._id?.toString() === taskId ? { ...t, status: newStatus } : t)))

        try {
            await updateTask(taskId, { status: newStatus as "pending" | "in-progress" | "completed" | "on-hold" | "cancelled" | "closed" })

            // Invalidate task query for this department
            await queryClient.invalidateQueries({
                queryKey: ['tasks'],
                predicate: (query) => {
                    const qFilters = (query.queryKey[3] as any)
                    return qFilters?.departmentId === task.departmentId?.toString()
                }
            })

            if (onProjectUpdate) onProjectUpdate()
        } catch (error) {
            // Rollback optimistic update
            dispatch(setTasks(previousTasks))
            throw error
        }
    }, [tasks, updateTask, dispatch, queryClient, onProjectUpdate])

    const handleInlinePriorityChange = useCallback(async (taskId: string, newPriority: string) => {
        const task = tasks.find(t => t._id?.toString() === taskId)
        if (!task) throw new Error("Task not found")

        // Optimistic update
        const previousTasks = tasks
        dispatch(setTasks(tasks.map(t => t._id?.toString() === taskId ? { ...t, priority: newPriority } : t)))

        try {
            await updateTask(taskId, { priority: newPriority as "low" | "medium" | "high" | "urgent" })

            // Invalidate task query for this department
            await queryClient.invalidateQueries({
                queryKey: ['tasks'],
                predicate: (query) => {
                    const qFilters = (query.queryKey[3] as any)
                    return qFilters?.departmentId === task.departmentId?.toString()
                }
            })

            if (onProjectUpdate) onProjectUpdate()
        } catch (error) {
            // Rollback optimistic update
            dispatch(setTasks(previousTasks))
            throw error
        }
    }, [tasks, updateTask, dispatch, queryClient, onProjectUpdate])

    const handleInlineDueDateChange = useCallback(async (taskId: string, newDueDate: string) => {
        const task = tasks.find(t => t._id?.toString() === taskId)
        if (!task) throw new Error("Task not found")

        // Optimistic update
        const previousTasks = tasks
        dispatch(setTasks(tasks.map(t => t._id?.toString() === taskId ? { ...t, dueDate: newDueDate } : t)))

        try {
            await updateTask(taskId, { dueDate: new Date(newDueDate).toISOString() })

            // Invalidate task query for this department
            await queryClient.invalidateQueries({
                queryKey: ['tasks'],
                predicate: (query) => {
                    const qFilters = (query.queryKey[3] as any)
                    return qFilters?.departmentId === task.departmentId?.toString()
                }
            })

            if (onProjectUpdate) onProjectUpdate()
        } catch (error) {
            // Rollback optimistic update
            dispatch(setTasks(previousTasks))
            throw error
        }
    }, [tasks, updateTask, dispatch, queryClient, onProjectUpdate])

    const handleInlineAssigneeChange = useCallback(async (taskId: string, newAssigneeId: string) => {
        const task = tasks.find(t => t._id?.toString() === taskId)
        if (!task) throw new Error("Task not found")

        // Optimistic update
        const previousTasks = tasks
        dispatch(setTasks(tasks.map(t => t._id?.toString() === taskId ? { ...t, assigneeId: newAssigneeId } : t)))

        try {
            await updateTask(taskId, { assigneeId: newAssigneeId || undefined })

            // Invalidate task query for this department
            await queryClient.invalidateQueries({
                queryKey: ['tasks'],
                predicate: (query) => {
                    const qFilters = (query.queryKey[3] as any)
                    return qFilters?.departmentId === task.departmentId?.toString()
                }
            })

            if (onProjectUpdate) onProjectUpdate()
        } catch (error) {
            // Rollback optimistic update
            dispatch(setTasks(previousTasks))
            throw error
        }
    }, [tasks, updateTask, dispatch, queryClient, onProjectUpdate])

    const tasksByDepartment = useMemo(() => {
        let departmentsToUse: DepartmentSelection[] = []

        const formDepartmentIds = categorizationForm.getValues("departmentIds") || []
        if (formDepartmentIds.length > 0) {
            departmentsToUse = formDepartmentIds.map((deptId: any) => ({ departmentId: String(deptId), additionalInfo: "" }))
        } else if (selectedDepartments.length > 0) {
            departmentsToUse = selectedDepartments
        } else if (project?.departmentIds && Array.isArray(project.departmentIds) && project.departmentIds.length > 0) {
            departmentsToUse = project.departmentIds.map((deptId: any) => ({ departmentId: String(deptId), additionalInfo: "" }))
        } else if (project?.departments && Array.isArray(project.departments) && project.departments.length > 0) {
            const departmentIds = project.departments.map((dept: any) =>
                typeof dept === "string" ? dept : dept._id || dept.id,
            )
            departmentsToUse = departmentIds.map((deptId: any) => ({ departmentId: String(deptId), additionalInfo: "" }))
        } else if (tasks.length > 0 && projectId) {
            const taskDepartmentIds = [
                ...new Set(
                    tasks
                        .filter((task) => task.projectId?.toString() === projectId.toString() && task.departmentId)
                        .map((task) => task.departmentId.toString()),
                ),
            ]
            departmentsToUse = taskDepartmentIds.map((deptId: any) => ({ departmentId: String(deptId), additionalInfo: "" }))
        }

        if (project?.departmentTasks && Array.isArray(project.departmentTasks) && project.departmentTasks.length > 0) {
            const grouped: { [key: string]: any[] } = {}

            project.departmentTasks.forEach((deptTask: any) => {
                const deptId = deptTask.departmentId?.toString()
                if (deptId && deptTask.tasks && Array.isArray(deptTask.tasks)) {
                    grouped[deptId] = deptTask.tasks
                }
            })

            return grouped
        }

        const tasksToUse = tasks

        if (!Array.isArray(tasksToUse) || !projectId || departmentsToUse.length === 0) {
            const grouped: { [key: string]: any[] } = {}
            departmentsToUse.forEach(({ departmentId }: DepartmentSelection) => {
                grouped[departmentId] = []
            })
            return grouped
        }

        try {
            const grouped: { [key: string]: any[] } = {}

            departmentsToUse.forEach(({ departmentId }: DepartmentSelection) => {
                grouped[departmentId] = []
            })

            departmentsToUse.forEach(({ departmentId }: DepartmentSelection) => {
                // obtain any client-side dept filters applied
                const deptFilters = appliedDeptFilters[departmentId] || {}
                grouped[departmentId] = tasksToUse.filter((task) => {
                    if (!task) return false

                    const taskDeptId = task.departmentId?.toString()
                    const taskProjId = task.projectId?.toString()
                    const targetDeptId = departmentId.toString()
                    const targetProjId = projectId.toString()

                    const matchesDepartment = taskDeptId === targetDeptId
                    const matchesProject = taskProjId === targetProjId
                    const isParentTask = !task.parentTaskId

                    if (!(matchesDepartment && matchesProject && isParentTask)) return false

                    // Apply client-side department filters (if present)
                    if (deptFilters) {
                        // search
                        if (deptFilters.search) {
                            const s = String(deptFilters.search).toLowerCase()
                            const title = String(task.title || '').toLowerCase()
                            const desc = String(task.description || '').toLowerCase()
                            if (!title.includes(s) && !desc.includes(s)) return false
                        }
                        if (deptFilters.status && deptFilters.status !== 'all') {
                            if ((task.status || '') !== deptFilters.status) return false
                        }
                        if (deptFilters.priority && deptFilters.priority !== 'all') {
                            if ((task.priority || '') !== deptFilters.priority) return false
                        }
                        if (deptFilters.assigneeId && deptFilters.assigneeId !== 'all') {
                            if (String(task.assigneeId || '') !== String(deptFilters.assigneeId)) return false
                        }
                        if (deptFilters.dueDateFrom) {
                            const from = new Date(deptFilters.dueDateFrom)
                            if (!isNaN(from.getTime())) {
                                if (!task.dueDate || new Date(task.dueDate) < from) return false
                            }
                        }
                        if (deptFilters.dueDateTo) {
                            const to = new Date(deptFilters.dueDateTo)
                            if (!isNaN(to.getTime())) {
                                to.setHours(23, 59, 59, 999)
                                if (!task.dueDate || new Date(task.dueDate) > to) return false
                            }
                        }
                    }

                    return true
                })
            })

            return grouped
        } catch (error) {
            console.error("Error grouping tasks by department:", error)
            const grouped: { [key: string]: any[] } = {}
            departmentsToUse.forEach(({ departmentId }: DepartmentSelection) => {
                grouped[departmentId] = []
            })
            return grouped
        }
    }, [tasks, project?.departmentTasks, projectId, selectedDepartments, project?.departmentIds, watchedDepartmentIds, appliedDeptFilters, users])

    const getTasksByDepartment = useCallback(
        (departmentId: string) => {
            if (!departmentId) return []

            const departmentTasks = tasksByDepartment[departmentId] || []

            return departmentTasks
        },
        [tasksByDepartment],
    )

    const getSubTasks = useCallback(
        (parentTaskId: string) => {
            if (!parentTaskId) return []

            return tasks.filter(
                (task) =>
                    task.parentTaskId?.toString() === parentTaskId && task.projectId?.toString() === projectId?.toString(),
            )
        },
        [tasks, projectId],
    )

    const handleDragStart = useCallback((event: DragStartEvent) => {
        const taskId = String(event?.active?.id || "")
        if (!taskId) return
        const t = tasks.find((tt) => String(tt._id) === taskId)
        setDraggingTask(t || null)
    }, [tasks])

    const handleDragEnd = useCallback(
        async (event: DragEndEvent) => {
            const { active, over } = event
            setDraggingTask(null) // IMMEDIATELY clear dragging task on any drag end

            if (!over) return

            const taskId = String(active.id || "")
            if (!taskId) return

            const overId = String(over.id || "")
            let destDeptId = ""
            let destStatus = ""
            let insertAtIndex = -1

            // Handle column drops vs task drops
            if (overId.includes("::")) {
                const [did, s] = overId.split("::")
                destDeptId = did
                destStatus = s
                // Dropping on column means append to end
                const columnTasks = tasks.filter(t => 
                    (t.departmentId?.toString() || "") === destDeptId && 
                    (t.status || "") === destStatus
                )
                insertAtIndex = columnTasks.length
            } else {
                const overTask = tasks.find((t) => t._id?.toString() === overId)
                if (overTask) {
                    destDeptId = overTask.departmentId?.toString() || ""
                    destStatus = overTask.status || ""
                    // Find insertion index based on the target task
                    const columnTasks = tasks.filter(t => 
                        (t.departmentId?.toString() || "") === destDeptId && 
                        (t.status || "") === destStatus
                    ).sort((a, b) => (a.order || 0) - (b.order || 0))
                    insertAtIndex = columnTasks.findIndex(t => t._id?.toString() === overId)
                    if (insertAtIndex === -1) insertAtIndex = columnTasks.length
                } else {
                    return
                }
            }

            const taskToMove = tasks.find((t) => t._id?.toString() === taskId)
            if (!taskToMove) return

            const sameDept = (taskToMove.departmentId?.toString() || "") === destDeptId
            const sameStatus = (taskToMove.status || "") === destStatus

            // Handle within-column reordering
            if (sameDept && sameStatus) {
                if (!canUpdate("tasks")) {
                    toast({
                        variant: "destructive",
                        title: "Permission denied",
                        description: "You do not have permission to reorder tasks.",
                    })
                    return
                }

                // Get current column tasks in order
                const columnTasks = tasks.filter(t => 
                    (t.departmentId?.toString() || "") === destDeptId && 
                    (t.status || "") === destStatus
                ).sort((a, b) => (a.order || 0) - (b.order || 0))

                const currentIndex = columnTasks.findIndex(t => t._id?.toString() === taskId)
                if (currentIndex === -1 || currentIndex === insertAtIndex) return

                // Reorder the tasks array
                const reorderedTasks = [...columnTasks]
                const [movedTask] = reorderedTasks.splice(currentIndex, 1)
                reorderedTasks.splice(insertAtIndex, 0, movedTask)

                // Assign new order values
                const updatedTasks = reorderedTasks.map((task, index) => ({
                    ...task,
                    order: index + 1
                }))

                // Optimistically update UI
                const prevTasks = tasks.map(t => ({ ...t }))
                const newAllTasks = tasks.map(t => {
                    const updated = updatedTasks.find(ut => ut._id?.toString() === t._id?.toString())
                    return updated || t
                })
                dispatch(setTasks(newAllTasks))

                try {
                    // Send bulk order update using the enhanced hook function
                    const orderUpdates = updatedTasks.map(task => ({
                        id: task._id.toString(),
                        order: task.order
                    }))

                    await bulkOrderUpdate(orderUpdates)
                    toast({ title: "Success", description: "Tasks reordered successfully" })
                } catch (error) {
                    console.error('Error reordering tasks:', error)
                    // Rollback handled by bulkOrderUpdate hook
                    toast({
                        variant: "destructive",
                        title: "Error", 
                        description: "Failed to reorder tasks"
                    })
                }
                return
            }

            if (!canUpdate("tasks")) {
                toast({
                    variant: "destructive",
                    title: "Permission denied",
                    description: "You do not have permission to update tasks.",
                })
                return
            }

            // Declare variables outside try for proper scope
            const sourceDeptId = taskToMove.departmentId?.toString() || ''
            const affectedDeptIds = [...new Set([sourceDeptId, destDeptId].filter(Boolean))]

            try {
                // Cancel ongoing tasks queries to avoid racing with optimistic update
                await queryClient.cancelQueries({ queryKey: ['tasks'] })

                // Optimistically update Redux state immediately
                const optimistic = tasks.map((t) =>
                    String(t._id) === taskId ? { ...t, status: destStatus, departmentId: destDeptId } : t
                )
                dispatch(setTasks(optimistic))

                if (selectedTaskForDetails?._id === taskId) {
                    setSelectedTaskForDetails({ ...selectedTaskForDetails, status: destStatus, departmentId: destDeptId })
                }

                // Patch react-query caches for tasks lists that match this project and affected departments
                const allQueries = queryClient.getQueriesData({ queryKey: ['tasks'] })
                for (const [qKey, qData] of allQueries) {
                    try {
                        if (!Array.isArray(qKey) || qKey[0] !== 'tasks') continue
                        const qFilters = qKey[3] as any
                        if (!qFilters || qFilters.projectId !== projectId) continue
                        if (!qFilters.departmentId || affectedDeptIds.includes(qFilters.departmentId)) {
                            // Update the task in place within the cache
                            queryClient.setQueryData(qKey, (old: any) => {
                                if (!old) return old
                                if (Array.isArray(old)) {
                                    return old.map((t: any) =>
                                        String(t._id) === taskId ? { ...t, status: destStatus, departmentId: destDeptId } : t
                                    )
                                } else if (old.data && Array.isArray(old.data)) {
                                    return {
                                        ...old,
                                        data: old.data.map((t: any) =>
                                            String(t._id) === taskId ? { ...t, status: destStatus, departmentId: destDeptId } : t
                                        )
                                    }
                                }
                                return old
                            })
                            // Update single-task cache
                            queryClient.setQueryData(['tasks', taskId], (old: any) => {
                                if (!old || typeof old !== 'object') return old
                                return { ...old, status: destStatus, departmentId: destDeptId }
                            })
                        }
                    } catch (e) {
                        // Ignore cache update errors
                    }
                }

                // Send API request
                const updateData: any = {}
                if (destDeptId !== (taskToMove.departmentId?.toString() || "")) {
                    updateData.departmentId = destDeptId
                }
                if (destStatus !== (taskToMove.status || "")) {
                    updateData.status = destStatus as "pending" | "in-progress" | "completed"  | "on-hold" | "cancelled" | "closed"  | undefined
                }

                if (Object.keys(updateData).length > 0) {
                    try {
                        const result = await updateTask(taskId, updateData)

                        if (!result) {
                            console.warn("Update task returned no result but no error thrown")
                        }
                    } catch (apiError: any) {
                        console.error("API Update Error Details:", {
                            taskId,
                            updateData,
                            error: apiError?.message || apiError?.error || apiError,
                            status: apiError?.status,
                            response: apiError?.response,
                        })
                        throw apiError
                    }

                    // Invalidate only affected department queries
                    await Promise.all(affectedDeptIds.map(deptId =>
                        queryClient.invalidateQueries({
                            queryKey: ['tasks'],
                            predicate: (query) => {
                                const qFilters = (query.queryKey[3] as any)
                                return qFilters?.projectId === projectId && qFilters?.departmentId === deptId
                            }
                        })
                    ))

                    if (onProjectUpdate) onProjectUpdate()
                    toast({ title: "Success", description: "Task moved successfully" })
                }

                // Clear department loading
                setDepartmentOperationLoading((prev) => {
                    const newSet = new Set(prev)
                    affectedDeptIds.forEach((id) => newSet.delete(id))
                    return newSet
                })

            } catch (error) {
                console.error("Error moving task:", {
                    error,
                    taskId,
                    destDeptId,
                    destStatus,
                    currentStatus: taskToMove?.status,
                    currentDept: taskToMove?.departmentId?.toString(),
                })

                toast({
                    variant: "destructive",
                    title: "Error",
                    description: error instanceof Error ? error.message : "Failed to move task"
                })
            }
        },
        [tasks, projectId, updateTask, canUpdate, onProjectUpdate, toast, dispatch, queryClient, selectedTaskForDetails?._id],
    )

    const departmentsToDisplay = useMemo(() => {
        const formDepartmentIds = categorizationForm.getValues("departmentIds") || []
        if (formDepartmentIds.length > 0) {
            return formDepartmentIds
        } else if (selectedDepartments.length > 0) {
            return selectedDepartmentIds
        } else if (project?.departmentIds && Array.isArray(project.departmentIds)) {
            return project.departmentIds
        }
        return []
    }, [selectedDepartmentIds, project?.departmentIds, watchedDepartmentIds])

    const getDepartmentsToRender = useCallback(() => {
        try {
            const formDepartmentIds = categorizationForm.getValues('departmentIds') || []
            if (Array.isArray(formDepartmentIds) && formDepartmentIds.length > 0) {
                return formDepartmentIds.map((deptId: any) => ({ departmentId: String(deptId), additionalInfo: '' }))
            }
        } catch (e) {
            // ignore
        }
        return selectedDepartments
    }, [categorizationForm, selectedDepartments])

    const openTaskDetails = useCallback((task: any) => {
        if (!task || !task._id) return
        
        // Open modal instantly with current task data
        setSelectedTaskForDetails(task)
        setShowTaskDetails(true)
        
        // Optionally refresh data in background (don't await this)
        queryClient.refetchQueries({ 
            queryKey: ['tasks', String(task._id)], 
            exact: true 
        }).then((result: any) => {
            // Update with fresh data if available
            const refreshedData = result?.[0]?.data || result?.[0]
            if (refreshedData) {
                setSelectedTaskForDetails(refreshedData)
            }
        }).catch((error) => {
            // Silent failure - modal is already open with existing data
            console.log('Background task refresh failed:', error)
        })
    }, [queryClient])

    // When projectId changes (or on mount), load persisted view for this project
    useEffect(() => {
        try {
            const pid = projectId || 'global'
            const saved = typeof window !== 'undefined' ? window.localStorage.getItem(`taskView:${pid}`) : null
            const fallback = typeof window !== 'undefined' ? window.localStorage.getItem(`taskView:global`) : null
            const toUse = saved || fallback
            if (toUse === 'grid' || toUse === 'table' || toUse === 'board') {
                setTaskView(toUse)
            }
        } catch (e) {
            // ignore
        }
    }, [projectId])

    return (
        <div>
            {taskModal.isOpen && (
                <TaskModal
                    isOpen={taskModal.isOpen}
                    mode={taskModal.mode}
                    task={taskModal.task}
                    projectId={projectId}
                    departmentId={taskModal.departmentId}
                    departmentName={taskModal.departmentName}
                    parentTaskId={taskModal.parentTaskId}
                    onClose={closeTaskModal}
                    onSuccess={() => {
                        closeTaskModal()
                        // Only invalidate queries for the affected department
                        if (taskModal.departmentId) {
                            queryClient.invalidateQueries({
                                queryKey: ['tasks'],
                                predicate: (query) => {
                                    const qFilters = (query.queryKey[3] as any)
                                    return qFilters?.projectId === projectId && qFilters?.departmentId === taskModal.departmentId
                                }
                            })
                        }
                        if (onProjectUpdate) onProjectUpdate()
                    }}
                />
            )}

            {showTaskDetails && selectedTaskForDetails && (
                (() => {
                    const selDeptId = String(selectedTaskForDetails?.departmentId || selectedTaskForDetails?.department?._id || "")
                    const deptUsers = users.filter(u => String(u.department?._id) === selDeptId && u.status === 'active')
                    return (
                        <TaskDetailsModal
                            task={selectedTaskForDetails}
                            selectedTask={selectedTaskForDetails}
                            projectId={projectId}
                            getDepartmentName={getDepartmentName}
                            isOpen={showTaskDetails}
                            onClose={() => {
                                setShowTaskDetails(false)
                                setSelectedTaskForDetails(null)
                            }}
                            onTaskUpdate={() => {
                                refreshTasks()
                                if (onProjectUpdate) onProjectUpdate()
                            }}
                            onOpenCreateTaskModal={openCreateTaskModal}
                            onDeleteTask={handleDeleteTask}
                            onRestoreTask={handleRestoreTask}
                            onOpenEditTaskModal={openEditTaskModal}
                            onOpenTaskDetails={openTaskDetails}
                            isActionLoadingForDepartment={isActionLoadingForDepartment}
                            // Inline editing props
                            isActionLoadingForTask={isActionLoadingForTask}
                            canCreate={canCreate}
                            canUpdate={canUpdate}
                            canDelete={canDelete}
                            onStatusChange={handleInlineStatusChange}
                            onPriorityChange={handleInlinePriorityChange}
                            onDueDateChange={handleInlineDueDateChange}
                            onAssigneeChange={handleInlineAssigneeChange}
                            departmentUsers={deptUsers}
                            usersLoading={usersLoading}
                        />
                    )
                })()
            )}

            {departmentModalOpen && (
                <DepartmentManagerModal
                    isOpen={departmentModalOpen}
                    onClose={closeDepartmentModal}
                    projectId={projectId}
                    categorizationForm={categorizationForm}
                    departments={departments}
                    departmentsLoading={departmentsLoading}
                    modalLoading={modalLoading}
                    departmentToAdd={departmentToAdd}
                    setDepartmentToAdd={setDepartmentToAdd}
                    setModalLoading={setModalLoading}
                    selectedDepartments={selectedDepartments}
                    onDepartmentsChange={async (newDepartments: string[]) => {
                        await applyUpdatedDepartments(newDepartments)
                        closeDepartmentModal()
                    }}
                    isDepartmentLoading={(id: string) => departmentOperationLoading.has(id) || isActionLoadingForDepartment?.(id)}
                    departmentOperationLoading={departmentOperationLoading.size > 0}
                    handleDepartmentToggle={handleDepartmentToggle}
                    getDepartmentsToRender={getDepartmentsToRender}
                    getDepartmentName={getDepartmentName}
                />
            )}

            <div className="space-y-4">
                <div className="flex items-center justify-between px-4 py-3 bg-card rounded-lg border">
                    <div className="flex items-center gap-2">
                        <h3 className="text-lg font-semibold flex items-center gap-2">
                            Tasks by Department
                        </h3>
                        {/* toggle filter button goes here  */}
                        <div className="relative" style={{ width: "max-content" }}>
                            <Button
                                ref={globalFilterButtonRef}
                                size="sm"
                                variant={globalFilterOpen ? 'default' : 'ghost'}
                                onClick={() => setGlobalFilterOpen(prev => !prev)}

                                title={globalFilterOpen ? 'Hide Filters' : 'Show Filters'}
                                className="h-8"
                            >
                                {taskLoading ? <InlineLoader size="sm" /> : <Filter className="h-4 w-4" />}
                            </Button>
                            {/* show global active filter count like department filter badges */}
                            {globalFilterCount > 0 && (
                                <Badge
                                    className="text-xs ml-1 absolute"
                                    style={{
                                        top: '-10px',
                                        right: '-12px',
                                        zIndex: 10,
                                        transform: 'none'
                                    }}
                                >
                                    {globalFilterCount}
                                </Badge>
                            )}
                        </div>
                        {(taskLoading || departmentsLoading) && (
                            <div className="flex items-center gap-1">
                                <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
                                <span className="text-xs text-muted-foreground">Loading...</span>
                            </div>
                        )}
                    </div>


                    <div className="flex items-center gap-2">
                        {(tasks.length > 0 && tasks.some(t => t.projectId?.toString() === projectId.toString())) && (
                            <div className="text-xs text-muted-foreground">
                                Total: {tasks.length} Tasks | {departmentsToDisplay.length ? departmentsToDisplay.length : 0} Departments
                            </div>
                        )}
                        <Button variant="outline" size="sm" onClick={openDepartmentModal} disabled={departmentsLoading}>
                            <Building2 className="h-4 w-4" />
                            Manage Departments
                        </Button>

                        <div className="flex items-center gap-1">
                            <Button
                                variant={taskView === "grid" ? "default" : "ghost"}
                                size="sm"
                                className="h-8 w-8 p-1"
                                onClick={() => setTaskViewAndPersist("grid")}
                                title="Grid View"
                            >
                                <Grid3X3 className="h-4 w-4" />
                            </Button>
                            <Button
                                variant={taskView === "table" ? "default" : "ghost"}
                                size="sm"
                                className="h-8 w-8 p-1"
                                onClick={() => setTaskViewAndPersist("table")}
                                title="Table View"
                            >
                                <List className="h-4 w-4" />
                            </Button>
                            <Button
                                variant={taskView === "board" ? "default" : "ghost"}
                                size="sm"
                                className="h-8 w-8 p-1"
                                onClick={() => setTaskViewAndPersist("board")}
                                title="Board View"
                            >
                                <svg
                                    className="h-4 w-4"
                                    viewBox="0 0 24 24"
                                    fill="none"
                                    stroke="currentColor"
                                    strokeWidth="1.5"
                                    strokeLinecap="round"
                                    strokeLinejoin="round"
                                >
                                    <rect x="3" y="3" width="7" height="7" rx="1" />
                                    <rect x="14" y="3" width="7" height="7" rx="1" />
                                    <rect x="14" y="14" width="7" height="7" rx="1" />
                                    <rect x="3" y="14" width="7" height="7" rx="1" />
                                </svg>
                            </Button>
                        </div>
                    </div>
                </div>

                {/* Global Filters */}
                <div className="mt-3">
                    {globalFilterOpen && (
                        <GenericFilter
                            config={globalFilterConfig}
                            values={{
                                search: filters?.search || '',
                                status: (filters as any)?.status ?? 'all',
                                priority: (filters as any)?.priority ?? 'all',
                                assigneeId: (filters as any)?.assigneeId ?? 'all',
                                dueDateFrom: (filters as any)?.dueDateFrom || '',
                                dueDateTo: (filters as any)?.dueDateTo || ''
                            }}
                            onFilterChange={(values) => applyFilters(values)}
                            onReset={resetGlobalFilters}
                            className="mt-2"
                            presentation="dropdown"
                            isOpen={globalFilterOpen}
                            onOpenChange={(open) => setGlobalFilterOpen(open)}
                            anchorRef={globalFilterButtonRef}
                            loading={taskLoading}
                        />
                    )}
                </div>

                {departmentsToDisplay.length === 0 ? (
                    <Card>
                        <CardContent className="pt-8 pb-8">
                            {departmentsLoading || taskLoading ? (
                                <div className="text-center">
                                    <div className="flex justify-center mb-4">
                                        <div className="space-y-3 w-full">
                                            <div className="h-4 bg-muted rounded w-3/4 mx-auto animate-pulse"></div>
                                            <div className="h-4 bg-muted rounded w-1/2 mx-auto animate-pulse"></div>
                                        </div>
                                    </div>
                                    <p className="text-sm text-muted-foreground">Loading departments and tasks...</p>
                                </div>
                            ) : (
                                <div className="text-center">
                                    <Building2 className="h-12 w-12 mx-auto mb-3 text-muted-foreground/50" />
                                    <h3 className="font-medium mb-1">No departments assigned</h3>
                                    <p className="text-sm text-muted-foreground mb-4">Assign departments to this project to get started.</p>
                                    <Button onClick={openDepartmentModal}>
                                        <Plus className="h-4 w-4 mr-2" />
                                        Assign Departments
                                    </Button>
                                </div>
                            )}
                        </CardContent>
                    </Card>
                ) : (
                    departmentsToDisplay.map((departmentId: string) => {
                        const deptRef = deptFilterButtonRefs.current[departmentId] || (deptFilterButtonRefs.current[departmentId] = createRef<HTMLButtonElement>())
                        const departmentName = getDepartmentName(departmentId)
                        const departmentTasks = getTasksByDepartment(departmentId)
                        const isCollapsed = collapsedDepartments.has(departmentId)

                        return (
                            <Card key={departmentId} className="overflow-hidden">
                                <CardHeader
                                    className="py-3 px-4 bg-card/50 border-b cursor-pointer hover:bg-card/80 transition-colors"
                                    onClick={() => toggleDepartmentCollapse(departmentId)}
                                >
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-2">

                                            {isCollapsed ? <ChevronDown className="h-4 w-4" /> : <ChevronUp className="h-4 w-4" />}
                                            <CardTitle className="text-sm font-semibold">{departmentName}</CardTitle>
                                            <Badge variant="secondary" className="text-xs">
                                                {departmentTasks.length}
                                            </Badge>
                                            {(isActionLoadingForDepartment?.(departmentId) || departmentOperationLoading.has(departmentId)) && (
                                                <span className="ml-2 text-xs text-muted-foreground">Updating…</span>
                                            )}
                                            <div className="relative" style={{ width: "max-content" }}>
                                                <Button
                                                    ref={deptRef}
                                                    size="sm"
                                                    variant={deptFilterOpen[departmentId] ? 'default' : 'ghost'}

                                                    onClick={(e) => { e.stopPropagation(); setDeptFilterOpen(prev => ({ ...prev, [departmentId]: !prev[departmentId] })) }}
                                                    className="h-7"
                                                    title="Filter Department Tasks"
                                                >
                                                    {(isActionLoadingForDepartment?.(departmentId) || departmentOperationLoading.has(departmentId)) ? (
                                                        <InlineLoader size="sm" />
                                                    ) : (
                                                        <Filter className="h-4 w-4" />
                                                    )}
                                                </Button>
                                                {(() => {
                                                    const deptCount = appliedDeptFilters[departmentId]
                                                        ? Object.values(appliedDeptFilters[departmentId]).filter(v => v && v !== 'all').length
                                                        : 0
                                                    return deptCount > 0 ? (
                                                        <Badge
                                                            className="text-xs ml-1 absolute"
                                                            style={{
                                                                top: '-10px',
                                                                right: '-12px',
                                                                zIndex: 10,
                                                                transform: 'none'
                                                            }}
                                                        >
                                                            {deptCount}
                                                        </Badge>
                                                    ) : null
                                                })()}
                                            </div>

                                        </div>
                                        <div className="flex items-center gap-2">
                                            {canCreate("tasks") && (
                                                <Button
                                                    size="sm"
                                                    variant="outline"
                                                    onClick={(e) => {
                                                        e.stopPropagation()
                                                        openCreateTaskModal(departmentId, departmentName)
                                                    }}
                                                    className="h-7"
                                                    disabled={isActionLoadingForDepartment?.(departmentId) || departmentOperationLoading.has(departmentId)}
                                                >
                                                    <Plus className="h-3.5 w-3.5 mr-1" />
                                                    New Task
                                                </Button>
                                            )}
                                        </div>
                                    </div>
                                </CardHeader>

                                {!isCollapsed ? (
                                    <CardContent className="p-0">
                                        {deptFilterOpen[departmentId] && (
                                            <GenericFilter
                                                config={getDepartmentFilterConfig(departmentId)}
                                                values={appliedDeptFilters[departmentId] || globalFilterConfig.defaultValues || { status: 'all', priority: 'all', assigneeId: 'all' }}
                                                onFilterChange={(vals) => {
                                                    applyFilters(vals, { departmentId })
                                                }}
                                                onReset={() => {
                                                    setAppliedDeptFilters(prev => {
                                                        const copy = { ...prev }
                                                        delete copy[departmentId]
                                                        return copy
                                                    })
                                                }}
                                                presentation="dropdown"
                                                isOpen={!!deptFilterOpen[departmentId]}
                                                onOpenChange={(open) => setDeptFilterOpen(prev => ({ ...prev, [departmentId]: open }))}
                                                anchorRef={deptRef}
                                                collapsible={false}
                                                loading={Boolean(isActionLoadingForDepartment?.(departmentId) || departmentOperationLoading.has(departmentId))}
                                            />
                                        )}
                                        {departmentTasks.length === 0 && taskView !== "board" ? (
                                            <div className="text-center py-8 px-4 text-muted-foreground">
                                                {isActionLoadingForDepartment?.(departmentId) || departmentOperationLoading.has(departmentId) ? (
                                                    <div className="space-y-3">
                                                        <div className="h-4 bg-muted rounded w-3/4 mx-auto animate-pulse"></div>
                                                        <div className="h-4 bg-muted rounded w-1/2 mx-auto animate-pulse"></div>
                                                    </div>
                                                ) : (
                                                    <div className="flex flex-col items-center">
                                                        <div className="w-12 h-12 rounded-full bg-muted/50 flex items-center justify-center mb-3">
                                                            <CheckSquare className="h-6 w-6 opacity-50" />
                                                        </div>
                                                        <h3 className="font-medium mb-1">No tasks yet</h3>
                                                        <p className="text-sm">Create your first task to get started.</p>
                                                    </div>
                                                )}
                                            </div>
                                        ) : (
                                            <div>
                                                {taskView === "grid" && (
                                                    <TaskGridView
                                                        departmentId={departmentId}
                                                        departmentName={departmentName}
                                                        departmentTasks={departmentTasks}
                                                        collapsedTasks={collapsedTasks}
                                                        canCreate={canCreate}
                                                        canUpdate={canUpdate}
                                                        canDelete={canDelete}
                                                        onOpenCreateTaskModal={openCreateTaskModal}
                                                        onOpenEditTaskModal={openEditTaskModal}
                                                        onDeleteTask={handleDeleteTask}
                                                        onRestoreTask={handleRestoreTask}
                                                        onToggleTaskCollapse={toggleTaskCollapse}
                                                        onSelectTaskForDetails={openTaskDetails}
                                                        getSubTasks={getSubTasks}
                                                        getDepartmentName={getDepartmentName}
                                                        onShowTaskDetails={setShowTaskDetails}
                                                        isActionLoadingForTask={isActionLoadingForTask}
                                                        isActionLoadingForDepartment={isActionLoadingForDepartment}
                                                        onStatusChange={handleInlineStatusChange}
                                                        onPriorityChange={handleInlinePriorityChange}
                                                        onDueDateChange={handleInlineDueDateChange}
                                                        onAssigneeChange={handleInlineAssigneeChange}
                                                        departmentUsers={users.filter(u => u.department?._id === departmentId && u.status === 'active')}
                                                        usersLoading={usersLoading}
                                                    />
                                                )}

                                                {taskView === "table" && (
                                                    <TaskTableView
                                                        departmentId={departmentId}
                                                        departmentName={departmentName}
                                                        departmentTasks={departmentTasks}
                                                        collapsedTasks={collapsedTasks}
                                                        canCreate={canCreate}
                                                        canUpdate={canUpdate}
                                                        canDelete={canDelete}
                                                        onOpenCreateTaskModal={openCreateTaskModal}
                                                        onOpenEditTaskModal={openEditTaskModal}
                                                        onDeleteTask={handleDeleteTask}
                                                        onRestoreTask={handleRestoreTask}
                                                        onToggleTaskCollapse={toggleTaskCollapse}
                                                        onSelectTaskForDetails={openTaskDetails}
                                                        getSubTasks={getSubTasks}
                                                        getDepartmentName={getDepartmentName}
                                                        onShowTaskDetails={setShowTaskDetails}
                                                        isActionLoadingForTask={isActionLoadingForTask}
                                                        isActionLoadingForDepartment={isActionLoadingForDepartment}
                                                        onStatusChange={handleInlineStatusChange}
                                                        onPriorityChange={handleInlinePriorityChange}
                                                        onDueDateChange={handleInlineDueDateChange}
                                                        onAssigneeChange={handleInlineAssigneeChange}
                                                        departmentUsers={users.filter(u => u.department?._id === departmentId && u.status === 'active')}
                                                        usersLoading={usersLoading}
                                                    />
                                                )}

                                                {taskView === "board" && (
                                                    <TaskBoardView
                                                        departmentId={departmentId}
                                                        departmentName={departmentName}
                                                        departmentTasks={departmentTasks}
                                                        canCreate={canCreate}
                                                        canUpdate={canUpdate}
                                                        canDelete={canDelete}
                                                        onOpenCreateTaskModal={openCreateTaskModal}
                                                        onOpenEditTaskModal={openEditTaskModal}
                                                        onDeleteTask={handleDeleteTask}
                                                        onRestoreTask={handleRestoreTask}
                                                        onSelectTaskForDetails={openTaskDetails}
                                                        getDepartmentName={getDepartmentName}
                                                        sensors={sensors}
                                                        onHandleDragStart={handleDragStart}
                                                        onHandleDragEnd={handleDragEnd}
                                                        draggingTask={draggingTask}
                                                        onShowTaskDetails={setShowTaskDetails}
                                                        isActionLoadingForTask={isActionLoadingForTask}
                                                        isActionLoadingForDepartment={isActionLoadingForDepartment}
                                                        onStatusChange={handleInlineStatusChange}
                                                        onPriorityChange={handleInlinePriorityChange}
                                                        onDueDateChange={handleInlineDueDateChange}
                                                        onAssigneeChange={handleInlineAssigneeChange}
                                                        departmentUsers={users.filter(u => u.department?._id === departmentId && u.status === 'active')}
                                                        usersLoading={usersLoading}
                                                    />
                                                )}
                                            </div>
                                        )}
                                    </CardContent>
                                ) : (
                                    <div className="p-4 flex items-center justify-between text-sm text-muted-foreground">
                                        <div>
                                            <span className="font-medium">{departmentTasks.length}</span> {departmentTasks.length === 1 ? 'task' : 'tasks'}
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <Badge variant="secondary" className="bg-primary/10 text-primary text-xs h-5">
                                                {departmentTasks.filter(t => t.status === 'completed').length} done
                                            </Badge>
                                            <Badge variant="outline" className="text-blue-600 border-blue-200 bg-blue-50 dark:bg-blue-950 text-xs h-5">
                                                {departmentTasks.filter(t => t.status === 'in-progress').length} active
                                            </Badge>
                                            <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => toggleDepartmentCollapse(departmentId)}>
                                                <ChevronUp className="h-4 w-4" />
                                            </Button>

                                        </div>
                                    </div>
                                )}
                            </Card>
                        )
                    })
                )}
            </div>
        </div>
    )
})

export default ProjectCategorization
