import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import { Task, TaskFilters, TaskSort, TaskStats, TaskHierarchy } from '@/types'

interface TaskState {
  tasks: Task[]
  selectedTask: Task | null
  loading: boolean
  actionLoading: boolean
  actionLoadingTasks: Record<string, boolean>
  actionLoadingDepartments: Record<string, boolean>
  error: any
  filters: TaskFilters
  sort: TaskSort
  pagination: {
    page: number
    limit: number
    total: number
    pages: number
  }
  stats: TaskStats | null
  hierarchy: TaskHierarchy | null
}

const initialState: TaskState = {
  tasks: [],
  selectedTask: null,
  loading: false,
  actionLoading: false,
  actionLoadingTasks: {},
  actionLoadingDepartments: {},
  error: null,
  filters: {},
  sort: { field: 'createdAt', direction: 'desc' },
  pagination: { page: 1, limit: 50, total: 0, pages: 0 },
  stats: null,
  hierarchy: null,
}

const taskSlice = createSlice({
  name: 'tasks',
  initialState,
  reducers: {
    setTasks: (state, action: PayloadAction<Task[]>) => {
      state.tasks = action.payload
    },
    setSelectedTask: (state, action: PayloadAction<Task | null>) => {
      state.selectedTask = action.payload
    },
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.loading = action.payload
    },
    setActionLoading: (state, action: PayloadAction<boolean>) => {
      state.actionLoading = action.payload
    },
    setActionLoadingForTask: (state, action: PayloadAction<{ id: string; loading: boolean }>) => {
      const { id, loading } = action.payload
      if (loading) state.actionLoadingTasks[id] = true
      else delete state.actionLoadingTasks[id]
    },
    setActionLoadingForDepartment: (state, action: PayloadAction<{ id: string; loading: boolean }>) => {
      const { id, loading } = action.payload
      if (loading) state.actionLoadingDepartments[id] = true
      else delete state.actionLoadingDepartments[id]
    },
    setError: (state, action: PayloadAction<any>) => {
      state.error = action.payload
    },
    clearError: (state) => {
      state.error = null
    },
    setFilters: (state, action: PayloadAction<Partial<TaskFilters>>) => {
      state.filters = { ...state.filters, ...action.payload }
      state.pagination.page = 1
    },
    setSort: (state, action: PayloadAction<TaskSort>) => {
      state.sort = action.payload
    },
    setPagination: (state, action: PayloadAction<Partial<TaskState['pagination']>>) => {
      state.pagination = { ...state.pagination, ...action.payload }
    },
    setHierarchy: (state, action: PayloadAction<TaskHierarchy | null>) => {
      state.hierarchy = action.payload
    },
    resetState: (state) => {
      return initialState
    },
  },
})

export const {
  setTasks,
  setSelectedTask,
  setLoading,
  setActionLoading,
  setActionLoadingForTask,
  setActionLoadingForDepartment,
  setError,
  clearError,
  setFilters,
  setSort,
  setPagination,
  setHierarchy,
  resetState
} = taskSlice.actions

export default taskSlice.reducer
