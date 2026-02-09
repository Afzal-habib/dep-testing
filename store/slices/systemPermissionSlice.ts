import { createSlice, createAsyncThunk, type PayloadAction } from "@reduxjs/toolkit"

// System Permission interfaces
export interface SystemPermission {
  _id?: string;
  resource: string;
  displayName: string;
  description?: string;
  category: string;
  availableActions: {
    action: string;
    description: string;
    conditions?: string[];
  }[];
  isCore: boolean;
  status: 'active' | 'inactive' | 'archived';
  metadata?: {
    createdBy?: string;
    updatedBy?: string;
    version?: string;
    notes?: string;
  };
  createdAt?: Date;
  updatedAt?: Date;
}

export interface SystemPermissionFilters {
  category?: string;
  resource?: string;
  includeInactive?: boolean;
}

interface SystemPermissionState {
  permissions: SystemPermission[]
  groupedPermissions: Record<string, SystemPermission[]>
  loading: boolean
  error: string | null
  filters: SystemPermissionFilters
}

const initialState: SystemPermissionState = {
  permissions: [],
  groupedPermissions: {},
  loading: false,
  error: null,
  filters: {
    includeInactive: false,
  },
}

// Async thunks
export const fetchSystemPermissions = createAsyncThunk(
  'systemPermissions/fetchSystemPermissions',
  async (filters: SystemPermissionFilters = {}, { rejectWithValue }) => {
    try {
      const queryParams = new URLSearchParams();
      
      if (filters.category) queryParams.append('category', filters.category);
      if (filters.resource) queryParams.append('resource', filters.resource);
      if (filters.includeInactive !== undefined) queryParams.append('includeInactive', filters.includeInactive.toString());

      const response = await fetch(`/api/system-permissions?${queryParams.toString()}`);
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || 'Failed to fetch system permissions');
      }
      
      const data = await response.json();
      return data;
    
    } catch (error: any) {
      return rejectWithValue(error.message);
    }
  }
)

// System Permission slice
const systemPermissionSlice = createSlice({
  name: 'systemPermissions',
  initialState,
  reducers: {
    setFilters: (state, action: PayloadAction<Partial<SystemPermissionFilters>>) => {
      state.filters = { ...state.filters, ...action.payload }
    },
    
    clearError: (state) => {
      state.error = null
    },
    
    resetSystemPermissions: (state) => {
      return initialState
    },
  },
  
  extraReducers: (builder) => {
    // Fetch system permissions
    builder
      .addCase(fetchSystemPermissions.pending, (state) => {
        state.loading = true
        state.error = null
      })
      .addCase(fetchSystemPermissions.fulfilled, (state, action) => {
        state.loading = false
        
        // Handle the API response structure
        const responseData = action.payload
        
        console.log('SystemPermissionSlice: Processing fulfilled action:', {
          hasPermissions: !!responseData.permissions,
          permissionsType: typeof responseData.permissions,
          permissionsKeys: responseData.permissions ? Object.keys(responseData.permissions) : null
        })
        
        if (responseData && responseData.permissions) {
          // API returns grouped permissions, so we need to flatten them for state.permissions
          const flatPermissions: SystemPermission[] = []
          Object.values(responseData.permissions).forEach((categoryPermissions: any) => {
            if (Array.isArray(categoryPermissions)) {
              flatPermissions.push(...categoryPermissions)
            }
          })
          
          console.log('SystemPermissionSlice: Processed permissions:', {
            flatPermissionsCount: flatPermissions.length,
            groupedPermissionsKeys: Object.keys(responseData.permissions)
          })
          
          state.permissions = flatPermissions
          state.groupedPermissions = responseData.permissions
        } else {
          console.log('SystemPermissionSlice: No permissions found in response, using fallback')
          // Fallback for old API structure or empty response
          const permissions = Array.isArray(responseData) ? responseData : []
          state.permissions = permissions
          
          // Group permissions by category for old structure
          state.groupedPermissions = permissions.reduce((acc: Record<string, SystemPermission[]>, permission: SystemPermission) => {
            if (!acc[permission.category]) {
              acc[permission.category] = []
            }
            acc[permission.category].push(permission)
            return acc
          }, {})
        }
      })
      .addCase(fetchSystemPermissions.rejected, (state, action) => {
        state.loading = false
        state.error = action.payload as string || 'Failed to fetch system permissions'
      })
  },
})

export const {
  setFilters,
  clearError,
  resetSystemPermissions,
} = systemPermissionSlice.actions

export default systemPermissionSlice.reducer