import { createSlice, PayloadAction } from '@reduxjs/toolkit'

// Milestone interface matching validation schema
export interface Milestone {
  _id: string
  title: string
  description?: string
  projectId: string
  phaseId?: string
  dueDate: Date
  status: 'pending' | 'in-progress' | 'completed' | 'blocked'
  priority: 'low' | 'medium' | 'high' | 'urgent'
  assignedTo?: string[]
  dependencies?: string[]
  progress: number
  tags?: string[]
  attachments?: string[]
  notes?: string
  completedAt?: Date
  createdBy: string
  createdAt: Date
  updatedAt: Date
}

// Filter interface for milestone queries
export interface MilestoneFilters {
  projectId?: string
  phaseId?: string
  status?: string[]
  priority?: string[]
  assignedTo?: string
  search?: string
  dueDate?: {
    from?: Date
    to?: Date
  }
  tags?: string[]
}

// Sort configuration for milestones
export interface MilestoneSort {
  field: 'title' | 'dueDate' | 'status' | 'priority' | 'progress' | 'createdAt' | 'updatedAt'
  direction: 'asc' | 'desc'
}

// Pagination interface
export interface MilestonePagination {
  page: number
  limit: number
  total: number
  totalPages: number
}

// Statistics interface for milestones
export interface MilestoneStats {
  total: number
  pending: number
  inProgress: number
  completed: number
  blocked: number
  overdue: number
  dueThisWeek: number
  dueNextWeek: number
  averageProgress: number
  byPriority: {
    low: number
    medium: number
    high: number
    urgent: number
  }
  byPhase: Record<string, number>
  completionRate: number
  progressTrend: {
    thisWeek: number
    lastWeek: number
    change: number
  }
}

// Milestone slice state interface
export interface MilestoneState {
  milestones: Milestone[]
  selectedMilestone: Milestone | null
  loading: boolean
  actionLoading: boolean
  error: string | null
  filters: MilestoneFilters
  sort: MilestoneSort
  pagination: MilestonePagination
  stats: MilestoneStats | null
}

// Initial state following Department pattern
const initialState: MilestoneState = {
  milestones: [],
  selectedMilestone: null,
  loading: false,
  actionLoading: false,
  error: null,
  filters: {
    projectId: undefined,
    phaseId: undefined,
    status: [],
    priority: [],
    assignedTo: undefined,
    search: '',
    dueDate: {
      from: undefined,
      to: undefined,
    },
    tags: [],
  },
  sort: {
    field: 'dueDate',
    direction: 'asc',
  },
  pagination: {
    page: 1,
    limit: 10,
    total: 0,
    totalPages: 0,
  },
  stats: null,
}

// Milestone slice with reducers following Department pattern
const milestoneSlice = createSlice({
  name: 'milestones',
  initialState,
  reducers: {
    // Entity management
    setMilestones: (state, action: PayloadAction<Milestone[]>) => {
      state.milestones = action.payload
      state.loading = false
      state.error = null
    },

    addMilestone: (state, action: PayloadAction<Milestone>) => {
      state.milestones.push(action.payload)
    },

    updateMilestone: (state, action: PayloadAction<{ id: string; updates: Partial<Milestone> }>) => {
      const index = state.milestones.findIndex(m => m._id === action.payload.id)
      if (index !== -1) {
        state.milestones[index] = { ...state.milestones[index], ...action.payload.updates }
      }
      if (state.selectedMilestone && state.selectedMilestone._id === action.payload.id) {
        state.selectedMilestone = { ...state.selectedMilestone, ...action.payload.updates }
      }
    },

    removeMilestone: (state, action: PayloadAction<string>) => {
      state.milestones = state.milestones.filter(m => m._id !== action.payload)
      if (state.selectedMilestone && state.selectedMilestone._id === action.payload) {
        state.selectedMilestone = null
      }
    },

    setSelectedMilestone: (state, action: PayloadAction<Milestone | null>) => {
      state.selectedMilestone = action.payload
    },

    // Loading states
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.loading = action.payload
      if (action.payload) {
        state.error = null
      }
    },

    setActionLoading: (state, action: PayloadAction<boolean>) => {
      state.actionLoading = action.payload
    },

    // Error handling
    setError: (state, action: PayloadAction<string | null>) => {
      state.error = action.payload
      state.loading = false
      state.actionLoading = false
    },

    clearError: (state) => {
      state.error = null
    },

    // Filters and sorting
    setFilters: (state, action: PayloadAction<Partial<MilestoneFilters>>) => {
      state.filters = { ...state.filters, ...action.payload }
      state.pagination.page = 1 // Reset to first page when filters change
    },

    clearFilters: (state) => {
      state.filters = initialState.filters
      state.pagination.page = 1
    },

    setSort: (state, action: PayloadAction<MilestoneSort>) => {
      state.sort = action.payload
      state.pagination.page = 1 // Reset to first page when sort changes
    },

    // Pagination
    setPagination: (state, action: PayloadAction<Partial<MilestonePagination>>) => {
      state.pagination = { ...state.pagination, ...action.payload }
    },

    // Statistics
    setStats: (state, action: PayloadAction<MilestoneStats | null>) => {
      state.stats = action.payload
    },

    // Bulk operations
    bulkUpdateMilestones: (state, action: PayloadAction<{ ids: string[]; updates: Partial<Milestone> }>) => {
      const { ids, updates } = action.payload
      state.milestones = state.milestones.map(milestone => 
        ids.includes(milestone._id) 
          ? { ...milestone, ...updates }
          : milestone
      )
    },

    bulkDeleteMilestones: (state, action: PayloadAction<string[]>) => {
      state.milestones = state.milestones.filter(m => !action.payload.includes(m._id))
      if (state.selectedMilestone && action.payload.includes(state.selectedMilestone._id)) {
        state.selectedMilestone = null
      }
    },

    // Reorder milestones
    reorderMilestones: (state, action: PayloadAction<{ milestoneId: string; newOrder: number }[]>) => {
      const orderMap = new Map(action.payload.map(item => [item.milestoneId, item.newOrder]))
      state.milestones.sort((a, b) => {
        const orderA = orderMap.get(a._id) ?? Number.MAX_SAFE_INTEGER
        const orderB = orderMap.get(b._id) ?? Number.MAX_SAFE_INTEGER
        return orderA - orderB
      })
    },

    // Reset state
    resetState: (state) => {
      return initialState
    },

    // Quick status updates for milestone management
    updateMilestoneStatus: (state, action: PayloadAction<{ id: string; status: Milestone['status'] }>) => {
      const { id, status } = action.payload
      const milestone = state.milestones.find(m => m._id === id)
      if (milestone) {
        milestone.status = status
        if (status === 'completed' && !milestone.completedAt) {
          milestone.completedAt = new Date()
          milestone.progress = 100
        }
      }
      if (state.selectedMilestone && state.selectedMilestone._id === id) {
        state.selectedMilestone.status = status
        if (status === 'completed' && !state.selectedMilestone.completedAt) {
          state.selectedMilestone.completedAt = new Date()
          state.selectedMilestone.progress = 100
        }
      }
    },

    updateMilestoneProgress: (state, action: PayloadAction<{ id: string; progress: number }>) => {
      const { id, progress } = action.payload
      const milestone = state.milestones.find(m => m._id === id)
      if (milestone) {
        milestone.progress = Math.max(0, Math.min(100, progress))
        if (progress === 100 && milestone.status !== 'completed') {
          milestone.status = 'completed'
          milestone.completedAt = new Date()
        } else if (progress > 0 && milestone.status === 'pending') {
          milestone.status = 'in-progress'
        }
      }
      if (state.selectedMilestone && state.selectedMilestone._id === id) {
        state.selectedMilestone.progress = Math.max(0, Math.min(100, progress))
        if (progress === 100 && state.selectedMilestone.status !== 'completed') {
          state.selectedMilestone.status = 'completed'
          state.selectedMilestone.completedAt = new Date()
        } else if (progress > 0 && state.selectedMilestone.status === 'pending') {
          state.selectedMilestone.status = 'in-progress'
        }
      }
    },
  },
})

// Export actions
export const {
  setMilestones,
  addMilestone,
  updateMilestone,
  removeMilestone,
  setSelectedMilestone,
  setLoading,
  setActionLoading,
  setError,
  clearError,
  setFilters,
  clearFilters,
  setSort,
  setPagination,
  setStats,
  bulkUpdateMilestones,
  bulkDeleteMilestones,
  reorderMilestones,
  resetState,
  updateMilestoneStatus,
  updateMilestoneProgress,
} = milestoneSlice.actions

// Export reducer
export default milestoneSlice.reducer

// Selector helpers for derived state
export const selectMilestonesByStatus = (milestones: Milestone[], status: Milestone['status']) =>
  milestones.filter(milestone => milestone.status === status)

export const selectOverdueMilestones = (milestones: Milestone[]) =>
  milestones.filter(milestone => 
    milestone.status !== 'completed' && 
    new Date(milestone.dueDate) < new Date()
  )

export const selectMilestonesByPriority = (milestones: Milestone[], priority: Milestone['priority']) =>
  milestones.filter(milestone => milestone.priority === priority)

export const selectMilestonesByPhase = (milestones: Milestone[], phaseId: string) =>
  milestones.filter(milestone => milestone.phaseId === phaseId)

export const selectMilestonesByProject = (milestones: Milestone[], projectId: string) =>
  milestones.filter(milestone => milestone.projectId === projectId)

export const selectMilestonesProgress = (milestones: Milestone[]) => {
  if (milestones.length === 0) return 0
  const totalProgress = milestones.reduce((sum, milestone) => sum + milestone.progress, 0)
  return Math.round(totalProgress / milestones.length)
}