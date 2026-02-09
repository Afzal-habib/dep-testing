"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import { useToast } from "@/hooks/use-toast";
import { useAppSelector } from "@/hooks/redux";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import DataTable from "@/components/shared/data-table";
import PageHeader from "@/components/shared/page-header";
import CustomModal from "@/components/shared/custom-modal";
import GenericFilter, { FilterConfig } from "@/components/shared/generic-filter";
import { cn } from "@/lib/utils";
import { handleAPIError } from "@/lib/utils/api-client";
import Swal from 'sweetalert2'
import {
  Users,
  UserCheck,
  UserX,
  AlertTriangle,
  Trash2,
} from "lucide-react";
import type { ColumnDef, ActionMenuItem } from "@/components/shared/data-table";
import type { Role, User } from "@/types";
import type { UserFilters, UserSort } from "@/store/slices/userSlice";
import { useDepartments } from "@/hooks/use-departments";
import { useRoles } from "@/hooks/use-roles";
import { useUsers } from "@/hooks/use-users";
import { useNavigation } from "@/components/providers/navigation-provider";
import GenericReportExporter from "@/components/shared/GenericReportExporter";
import { STATUS_COLORS } from '@/lib/colorConstants';



export default function UsersPage() {
  const router = useRouter();
  const { toast } = useToast();
  const { navigateTo, isNavigating } = useNavigation()

  // Permission checks
  const { allDepartments } = useDepartments();
  const { roles, allRoles, fetchRoles } = useRoles();
  const {
    users: hookUsers,
    selectedUser: hookSelectedUser,
    loading: hookLoading,
    actionLoading: hookActionLoading,
    error: hookError,
    deleteUser,
    restoreUser,
    setFilters,
    setSort,
    setPagination,
    setSelectedUser,
    clearError,
    fetchUsers, // ✅ Add this
  } = useUsers();

  // Redux state for filters, sort, pagination (these are managed by Redux for persistence)
  const {
    filters,
    sort,
    pagination,
    stats,
  } = useAppSelector((state) => state.users);

  // Use hook data and loading states
  const users = hookUsers;
  const selectedUser = hookSelectedUser;
  const loading = hookLoading;
  const actionLoading = hookActionLoading;
  const error = hookError;

  // Local UI state
  const [isQuickViewOpen, setIsQuickViewOpen] = useState(false);
  const [isFilterExpanded, setIsFilterExpanded] = useState(false);
  const [availableRoles, setAvailableRoles] = useState<Array<{ value: string, label: string }>>(allRoles);
  const [availableDepartments, setAvailableDepartments] = useState<Array<{ value: string, label: string }>>([]);
  const [activeTab, setActiveTab] = useState('overview');
  console.log("users list 76", users);
  console.log('stats are: ', stats);
  // setAvailableRoles(roles)

  // Filter configuration
  const filterConfig: FilterConfig = useMemo(() => ({
    fields: [
      {
        key: 'search',
        label: 'Search',
        type: 'text',
        placeholder: 'Search by name or email...',
        cols: 12, // Full width on mobile, will be responsive in GenericFilter
        mdCols: 6, // Half width on medium screens
        lgCols: 3, // Quarter width on large screens
      },
      {
        key: 'role',
        label: 'Role',
        type: 'select',
        searchable: true,
        placeholder: 'All Roles',
        cols: 12, // Full width on mobile
        mdCols: 6, // Half width on medium screens
        lgCols: 3, // Quarter width on large screens
        options: [
          { value: 'all', label: 'All Roles' },
          ...availableRoles,
        ],
      },
      {
        key: 'status',
        label: 'Status',
        type: 'select',
        searchable: true,
        placeholder: 'All Statuses',
        cols: 12, // Full width on mobile
        mdCols: 6, // Half width on medium screens
        lgCols: 3, // Quarter width on large screens
        options: [
          { value: 'all', label: 'All Statuses' },
          { value: 'active', label: 'Active' },
          { value: 'inactive', label: 'Inactive' },
          { value: 'suspended', label: 'Suspended' },
          { value: 'deleted', label: 'Deleted' },
        ],
      },
      {
        key: 'department',
        label: 'Department',
        type: 'select',
        searchable: true,
        placeholder: 'All Departments',
        cols: 12, // Full width on mobile
        mdCols: 6, // Half width on medium screens
        lgCols: 3, // Quarter width on large screens
        options: [
          { value: 'all', label: 'All Departments' },
          ...availableDepartments,
        ],
      },
    ],
    defaultValues: {
      search: '',
      role: 'all',
      status: 'all',
      department: 'all',
    },
  }), [availableRoles, availableDepartments]);

  // Map Redux filters to UI filters (convert empty strings to 'all' for selects)
  const uiFilters = useMemo(() => ({
    search: filters.search || '',
    role: filters.role || 'all',
    status: filters.status || 'all',
    department: filters.department || 'all',
  }), [filters]);


  // Filter handlers
  const handleFilterChange = useCallback((newFilters: Record<string, any>) => {
    // Convert 'all' values back to empty strings for the API
    const processedFilters = {
      search: newFilters.search || '',
      role: newFilters.role === 'all' ? '' : newFilters.role || '',
      status: newFilters.status === 'all' ? '' : newFilters.status || '',
      department: newFilters.department === 'all' ? '' : newFilters.department || '',
    };

    setFilters(processedFilters);
  }, [setFilters]);

  const handleFilterReset = useCallback(() => {
    const resetFilters: UserFilters = {
      search: '',
      role: '',
      status: '',
      department: '',
    };
    setFilters(resetFilters);
  }, [setFilters]);

  // Sort handlers
  const handleSort = useCallback((field: keyof User, direction: "asc" | "desc") => {
    const userSort: UserSort = {
      field,
      direction,
    };
    setSort(userSort);
  }, [setSort]);

  // Pagination handlers
  const handlePageChange = useCallback((page: number) => {
    setPagination({ page });
  }, [setPagination]);

  const handlePageSizeChange = useCallback((limit: number) => {
    setPagination({ limit, page: 1 });
  }, [setPagination]);

  // Fetch available departments for filter
  const fetchAvailableDepartments = useCallback(async () => {
    try {
      // Use allDepartments from the hook instead of fetching
      const currentAllDepartments = allDepartments;
      if (currentAllDepartments && currentAllDepartments.length > 0) {
        const departmentOptions = currentAllDepartments.map((dept: any) => ({
          value: dept._id,
          label: dept.name,
        })) || [];
        setAvailableDepartments(departmentOptions);
      }
    } catch (error) {
      console.error('Failed to fetch departments for filter:', error);
      handleAPIError(error, "Failed to load departments for filtering");
    }
  }, []); // Remove allDepartments from dependencies to prevent infinite re-runs


  // Update available departments when allDepartments changes
  useEffect(() => {
    if (allDepartments && allDepartments.length > 0) {
      const departmentOptions = allDepartments.map((dept: any) => ({
        value: dept._id,
        label: dept.name,
      })) || [];
      setAvailableDepartments(departmentOptions);
    }
  }, [allDepartments]);

  // Update available roles when allRoles changes
  useEffect(() => {
    if (allRoles && allRoles.length > 0) {
      const roleOptions = allRoles.map((role: any) => ({
        value: role._id,
        label: role.displayName || role.name,
      })) || [];
      setAvailableRoles(roleOptions);
    }
  }, [allRoles]);

  // User actions
  const handleViewUser = useCallback((user: User) => {
    setSelectedUser(user);
    setIsQuickViewOpen(true);
  }, [setSelectedUser]);

  const handleEditUser = useCallback((user: User) => {
    navigateTo(`/users/edit/${user._id}`);
  }, [navigateTo]);

  const handleDeleteUser = useCallback(async (user: User) => {
    const result = await Swal.fire({
      customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
      title: `Delete ${user.name}?`,
      text: "Are you sure you want to delete this user?",
      icon: "error",
      showCancelButton: true,
      showConfirmButton: true,
      confirmButtonText: "Yes, Delete",
      cancelButtonText: "No",
      confirmButtonColor: "#dc2626",
    });

    if (result.isConfirmed) {
      // Show simple loading with SweetAlert's built-in loader
      Swal.fire({
        customClass: {
          popup: 'swal-bg',
          title: 'swal-title',
          htmlContainer: 'swal-content',
        },
        title: 'Deleting...',
        text: 'Please wait while we delete the user.',
        allowOutsideClick: false,
        allowEscapeKey: false,
        showConfirmButton: false,
        didOpen: () => {
          Swal.showLoading();
        }
      });

      try {
        await deleteUser(user._id as string);

        // Refetch users to update the list with the new status
        await fetchUsers();

        // Show success message
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Deleted!",
          text: "User has been deleted successfully.",
          icon: "success",
          timer: 2000,
          showConfirmButton: false
        });

        toast({
          title: "Success",
          description: "User deleted successfully.",
          variant: "default",
        });
      } catch (error: any) {
        // Show error message
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Error!",
          text: error.error,
          icon: "error",
          confirmButtonText: "OK"
        });

        handleAPIError(error, "Failed to delete user. Please try again.");
      }
    }

  }, [deleteUser, toast]);


  const handleRestoreUser = useCallback(async (user: User) => {
    const result = await Swal.fire({
      customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
      title: `Restore ${user.name}?`,
      text: "Are you sure you want to restore this user?",
      icon: "question",
      showCancelButton: true,
      showConfirmButton: true,
      confirmButtonText: "Yes, Restore",
      cancelButtonText: "No",
      confirmButtonColor: "#10b981",
    });

    if (result.isConfirmed) {
      // Show simple loading with SweetAlert's built-in loader
      Swal.fire({
        customClass: {
          popup: 'swal-bg',
          title: 'swal-title',
          htmlContainer: 'swal-content',
        },
        title: 'Restoring...',
        text: 'Please wait while we restore the user.',
        allowOutsideClick: false,
        allowEscapeKey: false,
        showConfirmButton: false,
        didOpen: () => {
          Swal.showLoading();
        }
      });

      try {
        await restoreUser(user._id as string);

        // Refetch users to update the list with the new status
        await fetchUsers();

        // Show success message
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Restored!",
          text: "User has been restored successfully.",
          icon: "success",
          timer: 2000,
          showConfirmButton: false
        });

        toast({
          title: "Success",
          description: "User restored successfully.",
          variant: "default",
        });
      } catch (error: any) {
        // Show error message
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Error!",
          text: error.error,
          icon: "error",
          confirmButtonText: "OK"
        });

        handleAPIError(error, "Failed to restore user. Please try again.");
      }
    }

  }, [restoreUser, toast]);


  // Table columns configuration
  const columns: ColumnDef<User>[] = [
    {
      key: 'name',
      label: 'Name',
      sortable: true,
      render: (value, row) => (
        <div className="flex items-center space-x-3">
          {row.avatar ? (
            <img
              src={row.avatar}
              alt={row.name}
              className="w-8 h-8 rounded-full object-cover"
            />
          ) : (
            <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
              <span className="text-sm font-medium text-primary">
                {row.name.charAt(0).toUpperCase()}
              </span>
            </div>
          )}
          <div>
            <div className="font-medium">{value}</div>
            <div className="text-sm text-muted-foreground">{row.email}</div>
          </div>
        </div>
      ),
    },
    {
      key: 'role',
      label: 'Role',
      sortable: true,
      render: (value, row) => {
        // Handle both populated and non-populated role data
        const roleData = typeof value === 'object' && value !== null ? value : null;
        const roleName = roleData?.displayName || roleData?.name || value || 'No Role';
        const hierarchyLevel = roleData?.hierarchyLevel;

        const roleColors = {
          admin: 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300 border-red-200 dark:border-red-800',
          manager: 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-300 border-blue-200 dark:border-blue-800',
          hr: 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300 border-green-200 dark:border-green-800',
          finance: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-300 border-yellow-200 dark:border-yellow-800',
          sales: 'bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-300 border-purple-200 dark:border-purple-800',
          user: 'bg-muted text-muted-foreground border-border',
        };

        // Determine color based on hierarchy level if available
        let colorClass = roleColors.user;
        if (hierarchyLevel >= 9) colorClass = roleColors.admin;
        else if (hierarchyLevel >= 6) colorClass = roleColors.manager;
        else if (hierarchyLevel >= 3) colorClass = roleColors.hr;

        return (
          <div className="flex items-center space-x-1">
            <Badge className={`${colorClass} border`}>
              {roleName}
            </Badge>
            {hierarchyLevel && (
              <span className="text-xs text-muted-foreground">
                L{hierarchyLevel}
              </span>
            )}
          </div>
        );
      },
    },
    {
      key: 'status',
      label: 'Status',
      sortable: true,
      render: (value) => {
        return (
          <Badge className={`${STATUS_COLORS[value as keyof typeof STATUS_COLORS] || STATUS_COLORS.inactive} border`}>
            {value.charAt(0).toUpperCase() + value.slice(1)}
          </Badge>
        );
      },
    },
    {
      key: 'department',
      label: 'Department',
      sortable: true,
      render: (value) => {
        // Handle both populated and non-populated department data
        const deptData = typeof value === 'object' && value !== null ? value : null;
        const deptName = deptData?.name || value || '-';
        const deptStatus = deptData?.status;

        if (deptName === '-') return deptName;

        return (
          <div className="flex items-center space-x-1">
            <span>{deptName}</span>
            {deptStatus === 'inactive' && (
              <Badge variant="secondary" className="text-xs">
                Inactive
              </Badge>
            )}
          </div>
        );
      },
    },
    {
      key: 'emailVerified',
      label: 'Verified',
      render: (value) => (
        <div className="flex items-center space-x-1">
          {value ? (
            <UserCheck className="w-4 h-4 text-green-500" />
          ) : (
            <UserX className="w-4 h-4 text-gray-400" />
          )}
        </div>
      ),
    },
    {
      key: 'lastLogin',
      label: 'Last Login',
      sortable: true,
      render: (value) => {
        if (!value) return 'Never';
        return new Date(value).toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'short',
          day: 'numeric'
        });
      },
    },
    {
      key: 'createdAt',
      label: 'Created',
      sortable: true,
      render: (value) => new Date(value).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      }),
    },
  ];

  // Stats cards data
  const statsCards = stats ? [
    {
      title: "Total Users",
      value: stats.totalUsers,
      icon: <Users className="w-4 h-4" />,
      color: "text-blue-600"
    },
    {
      title: "Active Users",
      value: stats.activeUsers,
      icon: <UserCheck className="w-4 h-4" />,
      color: "text-green-600"
    },
    {
      title: "Inactive Users",
      value: stats.inactiveUsers,
      icon: <UserX className="w-4 h-4" />,
      color: "text-gray-600"
    },
    {
      title: "Deleted",
      value: (stats as any).deletedUsers || 0,
      icon: <Trash2 className="w-4 h-4" />,
      color: "text-red-800"
    },
  ] : [];

  return (
    <div>
      <PageHeader
        title="Users"
        subtitle="Manage system users and their permissions"
        onAddClick={() => navigateTo('/users/add')}
        showFilterButton={true}
        hasActiveFilters={Object.values(uiFilters).some(v => v && v !== 'all' && v !== '')}

        isFilterExpanded={isFilterExpanded}
        onFilterToggle={() => {
          setIsFilterExpanded(!isFilterExpanded);
        }}

        activeFiltersCount={Object.values(uiFilters).filter(v => v && v !== 'all' && v !== '').length}

        filterText="Filter Users"
        addButtonText="Add User"
        showRefreshButton={true}
        onRefresh={() => {
          handleFilterReset();
          fetchUsers(); // ✅ This will refetch the data
        }}
        isRefreshing={loading}
        actions={
          <GenericReportExporter
            moduleName="users"
            data={users}
            onExportComplete={(result) => {
              if (result.success) {
                toast({
                  title: "Success",
                  description: result.message,
                  variant: "default",
                });
              } else {
                toast({
                  title: "Error",
                  description: result.message,
                  variant: "destructive",
                });
              }
            }}
          />
        }
      >
        {
          isFilterExpanded && (
            <GenericFilter
              config={filterConfig}
              values={uiFilters}
              onFilterChange={handleFilterChange}
              loading={loading}
            />
          )
        }
      </PageHeader>

      {/* Filters and Table */}
      <DataTable
        data={users}
        columns={columns}
        totalCount={pagination.total}
        pageSize={pagination.limit}
        currentPage={pagination.page}
        onPageChange={handlePageChange}
        onPageSizeChange={handlePageSizeChange}
        onSort={handleSort}
        sortColumn={sort.field}
        sortDirection={sort.direction}
        loading={loading}
        emptyMessage="No users found"
        resourceName="users"
        onView={handleViewUser}
        onDelete={handleDeleteUser}
        onRestore={handleRestoreUser}
        enablePermissionChecking={true}
        statsCards={statsCards} // Add this prop
      />

      {/* Quick View Modal */}
      <CustomModal
        isOpen={isQuickViewOpen}
        onClose={() => setIsQuickViewOpen(false)}
        title="User Details"
        modalSize="lg"
      >
        {selectedUser && (
          <div className="space-y-4">
            {/* Tab Navigation */}
            <div className="border-b border-border">
              <nav className="flex" aria-label="Tabs">
                {[{
                  id: 'overview', name: 'Overview'
                },
                { id: 'permissions', name: 'Permissions' },
                { id: 'activity', name: 'Activity' }
                ].map((tab) => (
                  <div className="flex-1" key={tab.id}>
                    <button
                      onClick={() => setActiveTab(tab.id)}
                      className={cn(
                        "w-full text-center whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm  transition-colors",
                        activeTab === tab.id
                          ? "border-primary text-primary"
                          : "border-transparent text-muted-foreground hover:text-foreground hover:border-border"
                      )}
                    >
                      {tab.name}
                    </button>
                  </div>
                ))}
              </nav>
            </div>

            {/* Tab Content */}
            <div className="mt-4">
              {/* Overview Tab */}
              {activeTab === 'overview' && (
                <div className="space-y-4">
                  {/* Personal Info */}
                  <div className="flex items-center space-x-4">
                    {selectedUser.avatar ? (
                      <img
                        src={selectedUser.avatar}
                        alt={selectedUser.name}
                        className="w-16 h-16 rounded-full object-cover"
                      />
                    ) : (
                      <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
                        <span className="text-xl font-medium text-primary">
                          {selectedUser.name.charAt(0).toUpperCase()}
                        </span>
                      </div>
                    )}
                    <div>
                      <h3 className="text-lg font-semibold">{selectedUser.name}</h3>
                      <p className="text-muted-foreground">{selectedUser.email}</p>
                    </div>
                  </div>

                  {/* User Details Grid */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Role</label>
                      <p className="mt-1">
                        {typeof selectedUser.role === 'string'
                          ? selectedUser.role
                          : selectedUser.role?.name || 'Not specified'
                        }
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Status</label>
                      <p className="mt-1">{selectedUser.status}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Department</label>
                      <p className="mt-1">
                        {typeof selectedUser.department === 'string'
                          ? selectedUser.department
                          : selectedUser.department?.name || 'Not specified'
                        }
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Position</label>
                      <p className="mt-1">{selectedUser.position || 'Not specified'}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Email Verified</label>
                      <p className="mt-1">{selectedUser.emailVerified ? 'Yes' : 'No'}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Last Login</label>
                      <p className="mt-1">
                        {selectedUser.lastLogin
                          ? new Date(selectedUser.lastLogin).toLocaleString()
                          : 'Never'
                        }
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Permissions Tab */}
              {activeTab === 'permissions' && (
                <div className="space-y-4">
                  <div className="text-center py-2">
                    <h4 className="text-lg font-medium">{selectedUser.name} Permissions</h4>
                    {/* <p className="text-muted-foreground text-sm mb-1">
                      Permissions granted through the user's assigned role
                    </p> */}
                  </div>

                  {
                    Array.isArray((selectedUser.role as Role)?.permissions) && (selectedUser.role as Role)?.permissions.length > 0 ? (
                      <div className="space-y-3">
                        {(selectedUser.role as Role)?.permissions.map(permission => (
                          <div key={permission.resource} className="px-6 py-2 bg-primary/5 rounded-lg border border-primary/20">
                            <div className="flex items-center justify-between">
                              <div>
                                <span className="font-medium capitalize text-foreground block mb-2">
                                  {permission.resource.replace(/_/g, ' ')}
                                </span>
                                <div className="flex gap-2 flex-wrap">
                                  {Array.isArray(permission.actions) && permission.actions.map(action => (
                                    <Badge key={action} variant="default" className="text-xs">
                                      {action}
                                    </Badge>
                                  ))}
                                </div>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center py-8">
                        <div className="w-16 h-16 mx-auto bg-muted rounded-full flex items-center justify-center mb-4">
                          <span className="text-2xl">🔒</span>
                        </div>
                        <p className="text-muted-foreground">No permissions assigned</p>
                        <p className="text-sm text-muted-foreground mt-1">
                          This user doesn't have any permissions through their role
                        </p>
                      </div>
                    )}
                </div>
              )
              }

              {/* Activity Tab */}
              {activeTab === 'activity' && (
                <div className="space-y-4">
                  <div className="text-center py-4">
                    <h4 className="text-lg font-medium mb-2">User Activity</h4>
                    <p className="text-muted-foreground text-sm mb-4">
                      Recent activity and login history
                    </p>
                  </div>

                  <div className="space-y-3">
                    {/* Account Creation */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className="w-8 h-8 rounded-full bg-green-100 dark:bg-green-900/20 flex items-center justify-center">
                        <span className="text-green-600 text-sm">✓</span>
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Account Created</p>
                        <p className="text-xs text-muted-foreground">
                          {new Date(selectedUser.createdAt as any).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'long',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit'
                          })}
                        </p>
                      </div>
                    </div>

                    {/* Last Login */}
                    {selectedUser.lastLogin && (
                      <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                        <div className="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/20 flex items-center justify-center">
                          <span className="text-blue-600 text-sm">🔑</span>
                        </div>
                        <div className="flex-1">
                          <p className="text-sm font-medium">Last Login</p>
                          <p className="text-xs text-muted-foreground">
                            {new Date(selectedUser.lastLogin).toLocaleDateString('en-US', {
                              year: 'numeric',
                              month: 'long',
                              day: 'numeric',
                              hour: '2-digit',
                              minute: '2-digit'
                            })}
                          </p>
                        </div>
                      </div>
                    )}

                    {/* Email Verification Status */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className={cn(
                        "w-8 h-8 rounded-full flex items-center justify-center",
                        selectedUser.emailVerified
                          ? "bg-green-100 dark:bg-green-900/20"
                          : "bg-yellow-100 dark:bg-yellow-900/20"
                      )}>
                        <span className={cn(
                          "text-sm",
                          selectedUser.emailVerified ? "text-green-600" : "text-yellow-600"
                        )}>
                          {selectedUser.emailVerified ? "✓" : "⚠"}
                        </span>
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">
                          Email {selectedUser.emailVerified ? 'Verified' : 'Not Verified'}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {selectedUser.emailVerified
                            ? 'Email address has been verified'
                            : 'Email verification required'
                          }
                        </p>
                      </div>
                    </div>

                    {/* Account Status */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className={cn(
                        "w-8 h-8 rounded-full flex items-center justify-center",
                        selectedUser.status === 'active'
                          ? "bg-green-100 dark:bg-green-900/20"
                          : selectedUser.status === 'suspended'
                            ? "bg-red-100 dark:bg-red-900/20"
                            : "bg-gray-100 dark:bg-gray-900/20"
                      )}>
                        <span className={cn(
                          "text-sm",
                          selectedUser.status === 'active'
                            ? "text-green-600"
                            : selectedUser.status === 'suspended'
                              ? "text-red-600"
                              : "text-gray-600"
                        )}>
                          {selectedUser.status === 'active' ? '●' : selectedUser.status === 'suspended' ? '⊘' : '○'}
                        </span>
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium capitalize">
                          Account {selectedUser.status}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Current account status
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Actions Footer */}
            <div className="flex justify-end space-x-3 pt-4 border-t border-border">
              <Button
                variant="outline"
                onClick={() => setIsQuickViewOpen(false)}
              >
                Close
              </Button>
            </div>
          </div>
        )}
      </CustomModal>
    </div>
  );
}