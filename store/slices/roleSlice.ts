import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import { Role, RoleFilters, RoleSort } from '@/types'

interface RoleState {
  roles: Role[]
  selectedRole: Role | null
  loading: boolean
  actionLoading: boolean
  error: any
  filters: RoleFilters
  sort: RoleSort
  pagination: {
    page: number
    limit: number
    total: number
    pages: number
  }
  stats: {
    totalRoles: number
    systemRoles: number
    departmentRoles: number
    activeRoles: number
    inactiveRoles: number
    archivedRoles: number
  } | null
}

const initialState: RoleState = {
  roles: [],
  selectedRole: null,
  loading: false,
  actionLoading: false,
  error: null,
  filters: {},
  sort: { field: 'createdAt', direction: 'desc' },
  pagination: { page: 1, limit: 10, total: 0, pages: 0 },
  stats: null,
}

const roleSlice = createSlice({
  name: "roles",
  initialState,
  reducers: {
    setRoles: (state, action: PayloadAction<Role[]>) => {
      state.roles = action.payload
    },
    setSelectedRole: (state, action: PayloadAction<Role | null>) => {
      state.selectedRole = action.payload
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
    setFilters: (state, action: PayloadAction<RoleFilters>) => {
      state.filters = action.payload
      state.pagination.page = 1
    },
    setSort: (state, action: PayloadAction<RoleSort>) => {
      state.sort = action.payload
    },
    setPagination: (state, action: PayloadAction<Partial<RoleState["pagination"]>>) => {
      state.pagination = { ...state.pagination, ...action.payload }
    },
    setStats: (state, action: PayloadAction<RoleState["stats"]>) => {
      state.stats = action.payload
    },
    resetState: (state) => {
      return initialState
    },
  },
})

export const {
  setRoles,
  setSelectedRole,
  setLoading,
  setActionLoading,
  setError,
  clearError,
  setFilters,
  setSort,
  setPagination,
  setStats,
  resetState
} = roleSlice.actions

export default roleSlice.reducer