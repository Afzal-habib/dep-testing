import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import { Department, DepartmentFilters, DepartmentSort } from '@/types'

interface DepartmentState {
  departments: Department[]
  selectedDepartment: Department | null
  loading: boolean
  actionLoading: boolean
  error: any
  filters: DepartmentFilters
  sort: DepartmentSort
  pagination: {
    page: number
    limit: number
    total: number
    pages: number
  }
  stats: {
    totalDepartments: number
    activeDepartments: number
    inactiveDepartments: number
  } | null
}

const initialState: DepartmentState = {
  departments: [],
  selectedDepartment: null,
  loading: false,
  actionLoading: false,
  error: null,
  filters: {},
  sort: { field: 'createdAt', direction: 'desc' },
  pagination: { page: 1, limit: 10, total: 0, pages: 0 },
  stats: null,
}

const departmentSlice = createSlice({
  name: "departments",
  initialState,
  reducers: {
    setDepartments: (state, action: PayloadAction<Department[]>) => {
      state.departments = action.payload
    },
    setSelectedDepartment: (state, action: PayloadAction<Department | null>) => {
      state.selectedDepartment = action.payload
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
    setFilters: (state, action: PayloadAction<DepartmentFilters>) => {
      state.filters = action.payload
      state.pagination.page = 1
    },
    setSort: (state, action: PayloadAction<DepartmentSort>) => {
      state.sort = action.payload
    },
    setPagination: (state, action: PayloadAction<Partial<DepartmentState["pagination"]>>) => {
      state.pagination = { ...state.pagination, ...action.payload }
    },
    setStats: (state, action: PayloadAction<DepartmentState["stats"]>) => {
      state.stats = action.payload
    },
    resetState: (state) => {
      return initialState
    },
  },
})

export const {
  setDepartments,
  setSelectedDepartment,
  setLoading,
  setActionLoading,
  setError,
  clearError,
  setFilters,
  setSort,
  setPagination,
  setStats,
  resetState
} = departmentSlice.actions

export default departmentSlice.reducer