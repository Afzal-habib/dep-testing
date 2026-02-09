import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import { Project, ProjectFilters, ProjectSort, ProjectStats } from '@/types'

interface ProjectState {
  projects: Project[]
  selectedProject: Project | null
  loading: boolean
  actionLoading: boolean
  error: any
  filters: ProjectFilters
  sort: ProjectSort
  pagination: {
    page: number
    limit: number
    total: number
    pages: number
  }
  stats: ProjectStats | null
}

const initialState: ProjectState = {
  projects: [],
  selectedProject: null,
  loading: false,
  actionLoading: false,
  error: null,
  filters: {},
  sort: { field: 'createdAt', direction: 'desc' },
  pagination: { page: 1, limit: 10, total: 0, pages: 0 },
  stats: null,
}

const projectSlice = createSlice({
  name: 'projects',
  initialState,
  reducers: {
    setProjects: (state, action: PayloadAction<Project[]>) => {
      state.projects = action.payload
    },
    setSelectedProject: (state, action: PayloadAction<Project | null>) => {
      state.selectedProject = action.payload
    },
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.loading = action.payload
    },
    setActionLoading: (state, action: PayloadAction<boolean>) => {
      state.actionLoading = action.payload
    },
    setError: (state, action: PayloadAction<any>) => {
      state.error = action.payload
    },
    clearError: (state) => {
      state.error = null
    },
    setFilters: (state, action: PayloadAction<Partial<ProjectFilters>>) => {
      state.filters = { ...state.filters, ...action.payload }
      state.pagination.page = 1
    },
    setSort: (state, action: PayloadAction<ProjectSort>) => {
      state.sort = action.payload
    },
    setPagination: (state, action: PayloadAction<Partial<ProjectState['pagination']>>) => {
      state.pagination = { ...state.pagination, ...action.payload }
    },
    setStats: (state, action: PayloadAction<ProjectStats | null>) => {
      state.stats = action.payload
    },
    resetState: (state) => {
      return initialState
    },
  },
})

export const {
  setProjects,
  setSelectedProject,
  setLoading,
  setActionLoading,
  setError,
  clearError,
  setFilters,
  setSort,
  setPagination,
  setStats,
  resetState
} = projectSlice.actions

export default projectSlice.reducer
