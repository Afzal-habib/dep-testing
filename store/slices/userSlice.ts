import { createSlice, type PayloadAction } from "@reduxjs/toolkit"
import type { User } from "@/types"

export interface UserFilters {
  search?: string;
  role?: string;
  status?: 'active' | 'inactive' | 'suspended' | '';
  department?: string;
}

export interface UserSort {
  field: keyof User;
  direction: 'asc' | 'desc';
}

export interface FetchUsersParams {
  page?: number;
  limit?: number;
  filters?: UserFilters;
  sort?: UserSort;
}

export interface CreateUserData {
  name: string;
  email: string;
  password: string;
  role: string; // Role ID reference
  department: string; // Department ID reference
  phone?: string;
  position?: string;
  status?: 'active' | 'inactive' | 'suspended' | 'deleted';
  bio?: string;
}

export interface UpdateUserData extends Partial<Omit<CreateUserData, 'password'>> {
  _id: string;
}

interface UserState {
  users: User[]
  selectedUser: User | null
  loading: boolean
  actionLoading: boolean
  error: any
  filters: UserFilters
  sort: UserSort
  pagination: {
    page: number
    limit: number
    total: number
    pages: number
  }
  stats: {
    totalUsers: number
    activeUsers: number
    inactiveUsers: number
    suspendedUsers: number
  } | null
}

const initialState: UserState = {
  users: [],
  selectedUser: null,
  loading: false,
  actionLoading: false,
  error: null,
  filters: {},
  sort: {
    field: 'createdAt',
    direction: 'desc'
  },
  pagination: {
    page: 1,
    limit: 30,
    total: 0,
    pages: 0,
  },
  stats: null,
}

const userSlice = createSlice({
  name: "users",
  initialState,
  reducers: {
    setUsers: (state, action: PayloadAction<User[]>) => {
      state.users = action.payload;
    },
    setFilters: (state, action: PayloadAction<UserFilters>) => {
      state.filters = action.payload;
      state.pagination.page = 1; // Reset to first page when filters change
    },
    setSort: (state, action: PayloadAction<UserSort>) => {
      state.sort = action.payload;
    },
    setPagination: (state, action: PayloadAction<Partial<UserState["pagination"]>>) => {
      state.pagination = { ...state.pagination, ...action.payload };
    },
    setSelectedUser: (state, action: PayloadAction<User | null>) => {
      state.selectedUser = action.payload;
    },
    setStats: (state, action: PayloadAction<UserState["stats"]>) => {
      state.stats = action.payload;
    },
    clearError: (state) => {
      state.error = null;
    },
    resetState: (state) => {
      return initialState;
    },
  },
});

export const {
  setUsers,
  setFilters,
  setSort,
  setPagination,
  setSelectedUser,
  setStats,
  clearError,
  resetState
} = userSlice.actions; export default userSlice.reducer;
