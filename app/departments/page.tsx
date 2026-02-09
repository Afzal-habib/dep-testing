"use client";

import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { useRouter } from "next/navigation";
import { useAppSelector } from "@/hooks/redux";
import { Department, DepartmentFilters, FilterConfig } from "@/types";
import PageHeader from "@/components/shared/page-header";
import DataTable, { ColumnDef, HtmlTextRenderer } from "@/components/shared/data-table";
import GenericFilter from "@/components/shared/generic-filter";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import CustomModal from "@/components/shared/custom-modal";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Building2, AlertTriangle, Users, Calendar, Settings } from "lucide-react";
import { cn } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import { usePermissions } from "@/hooks/use-permissions";
import { useDepartments } from "@/hooks/use-departments";
import { handleAPIError } from "@/lib/utils/api-client";
import Swal from 'sweetalert2';
import { useNavigation } from "@/components/providers/navigation-provider";
import GenericReportExporter from "@/components/shared/GenericReportExporter";
import { STATUS_COLORS } from '@/lib/colorConstants';

export default function DepartmentsPage() {
  const router = useRouter();
  const { toast } = useToast();
  const { canCreate } = usePermissions();
  const { navigateTo, isNavigating } = useNavigation()

  // Local state
  const [isFilterExpanded, setIsFilterExpanded] = useState(false);
  const [isQuickViewOpen, setIsQuickViewOpen] = useState(false);
  const [selectedDepartmentForView, setSelectedDepartmentForView] = useState<Department | null>(null);
  const [activeTab, setActiveTab] = useState('overview');

  const {
    departments: hookDepartments,
    loading: hookLoading,
    actionLoading: hookActionLoading,
    error: hookError,
    fetchDepartments,
    deleteDepartment,
    restoreDepartment,
    setFilters,
    setSort,
    setPagination,
    clearError,
    setSelectedDepartment
  } = useDepartments();

  // Redux state for filters, sort, pagination (these are managed by Redux for persistence)
  const {
    filters,
    sort,
    pagination,
    stats,
  } = useAppSelector((state) => state.departments);

  // Use hook data and loading states
  const departments = hookDepartments;
  const loading = hookLoading;
  const error = hookError;

  // Filter configuration
  const filterConfig: FilterConfig = useMemo(() => ({
    fields: [
      {
        key: 'search',
        label: 'Search',
        type: 'text',
        placeholder: 'Search departments...',
        cols: 12, // Full width on mobile
        mdCols: 4, // Larger width on medium screens
        lgCols: 4, // Larger width on large screens
      },
      {
        key: 'status',
        label: 'Status',
        type: 'select',
        searchable: true,
        placeholder: 'All Statuses',
        cols: 12, // Full width on mobile
        mdCols: 4, // Smaller width on medium screens
        lgCols: 4, // Smaller width on large screens
        options: [
          { value: 'all', label: 'All Statuses' },
          { value: 'active', label: 'Active' },
          { value: 'inactive', label: 'Inactive' },
        ],
      },
      {
        key: 'category',
        label: 'Category',
        type: 'select',
        searchable: true,
        placeholder: 'All Categories',
        cols: 12, // Full width on mobile
        mdCols: 4, // Smaller width on medium screens
        lgCols: 4, // Smaller width on large screens
        options: [
          { value: 'all', label: 'All Categories' },
          { value: 'sales', label: 'Sales' },
          { value: 'support', label: 'Support' },
          { value: 'it', label: 'IT' },
          { value: 'management', label: 'Management' },
        ],
      },
    ],
    defaultValues: {
      search: '',
      status: 'all',
    },
  }), []);

  // Map Redux filters to UI filters (convert empty strings to 'all' for selects)
  const uiFilters = useMemo(() => ({
    search: filters.search || '',
    status: filters.status || 'all',
    category: filters.category || 'all',
  }), [filters.search, filters.status, filters.category]);

  // Filter handlers - Updated to match clients/leads page pattern
  const handleFilterChange = useCallback((newFilters: Record<string, any>) => {
    // Convert 'all' values back to empty strings for the API
    const departmentFilters: DepartmentFilters = {
      search: newFilters.search || '',
      status: newFilters.status === 'all' ? '' : (newFilters.status || ''),
      category: newFilters.category === 'all' ? '' : (newFilters.category || ''),
    };
    setFilters(departmentFilters);
  }, [setFilters]);

  const handleFilterReset = useCallback(() => {
    const defaultFilters: DepartmentFilters = {
      search: '',
      status: '',
      category: '',
    };
    setFilters(defaultFilters);
  }, [setFilters]);

  // Table columns configuration
  const columns: ColumnDef<Department>[] = [
    {
      key: 'name',
      label: 'Department Name',
      sortable: true,
      render: (value, row) => (
        <div className="flex items-center space-x-3">
          <div className="flex-shrink-0">
            <div className="w-10 h-10 bg-primary/10 rounded-lg flex items-center justify-center">
              <Building2 className="h-5 w-5 text-primary" />
            </div>
          </div>
          <div className="flex flex-col">
            <span className="font-medium text-foreground">{value}</span>
            <span className="text-sm text-muted-foreground">
              Category: {row.category || 'N/A'}
            </span>
          </div>
        </div>
      ),
    },
    {
      key: 'description',
      label: 'Description',
      sortable: false,
      render: (value) => (
        <div className="max-w-xs">
          <HtmlTextRenderer
            content={value}
            maxLength={120}
            className="line-clamp-3"
            fallbackText="No description"
            showFallback={true}
            renderAsHtml={true}
            truncateHtml={true}
          />
        </div>
      ),
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
      key: 'createdAt',
      label: 'Created',
      sortable: true,
      render: (value) => new Date(value).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      }),
    },
    {
      key: 'updatedAt',
      label: 'Last Updated',
      sortable: true,
      render: (value) => new Date(value).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      }),
    },
  ];

  // Event handlers
  const handleSort = useCallback((field: keyof Department, direction: "asc" | "desc") => {
    setSort({ field, direction });
  }, [setSort]);

  const handlePageChange = useCallback((page: number) => {
    setPagination({ page });
  }, [setPagination]);

  const handlePageSizeChange = useCallback((limit: number) => {
    setPagination({ limit, page: 1 });
  }, [setPagination]);

  const handleViewDepartment = useCallback((department: Department) => {
    setSelectedDepartmentForView(department);
    setIsQuickViewOpen(true);
    setActiveTab('overview');
  }, []);

  const handleDeleteDepartment = useCallback(async (department: Department) => {
    const result = await Swal.fire({
      customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
      title: `Delete ${department.name}?`,
      text: "Are you sure you want to delete this department?",
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
        text: 'Please wait while we delete the department.',
        allowOutsideClick: false,
        allowEscapeKey: false,
        showConfirmButton: false,
        didOpen: () => {
          Swal.showLoading();
        }
      });

      try {
        await deleteDepartment(department._id as string);

        // Show success message
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Deleted!",
          text: "Department has been deleted successfully.",
          icon: "success",
          timer: 2000,
          showConfirmButton: false
        });

        toast({
          title: "Success",
          description: "Department deleted successfully.",
          variant: "default",
        });

        fetchDepartments();
      } catch (err: any) {
        // Show error message
        console.log('Delete Department Error:', err);
        const errorMessage = err.error?.message || err.error || err.message || "Failed to delete department. Please try again.";
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Error!",
          text: errorMessage,
          icon: "error",
          confirmButtonText: "OK"
        });

        handleAPIError(err, "Failed to delete department. Please try again.");
      }
    }
  }, [deleteDepartment, toast, fetchDepartments]);

  const handleRestoreDepartment = useCallback(async (department: Department) => {
    const result = await Swal.fire({
      customClass: {
        popup: 'swal-bg',
        title: 'swal-title',
        htmlContainer: 'swal-content',
      },
      title: `Restore ${department.name}?`,
      text: "Are you sure you want to restore this department?",
      icon: "question",
      showCancelButton: true,
      showConfirmButton: true,
      confirmButtonText: "Yes, Restore",
      cancelButtonText: "No",
      confirmButtonColor: "#10b981",
    });

    if (result.isConfirmed) {
      Swal.fire({
        customClass: {
          popup: 'swal-bg',
          title: 'swal-title',
          htmlContainer: 'swal-content',
        },
        title: 'Restoring...',
        text: 'Please wait while we restore the department.',
        allowOutsideClick: false,
        allowEscapeKey: false,
        showConfirmButton: false,
        didOpen: () => {
          Swal.showLoading();
        }
      });

      try {
        await restoreDepartment(department._id as string);

        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Restored!",
          text: "Department has been restored successfully.",
          icon: "success",
          timer: 2000,
          showConfirmButton: false
        });

        toast({
          title: "Success",
          description: "Department restored successfully.",
          variant: "default",
        });

        fetchDepartments();
      } catch (error: any) {
        Swal.fire({
          customClass: {
            popup: 'swal-bg',
            title: 'swal-title',
            htmlContainer: 'swal-content',
          },
          title: "Error!",
          text: error.error?.message || error.error || error.message || "Failed to restore department. Please try again.",
          icon: "error",
          confirmButtonText: "OK"
        });
        handleAPIError(error, "Failed to restore department. Please try again.");
      }
    }
  }, [restoreDepartment, toast, fetchDepartments]);

  // Refs to track previous values and prevent unnecessary calls
  const prevParamsRef = useRef<string>('')

  // Memoize filters and sort to prevent unnecessary re-renders
  const memoizedFilters = useMemo(() => ({
    search: filters.search,
    status: filters.status,
    category: filters.category
  }), [filters.search, filters.status, filters.category])

  const memoizedSort = useMemo(() => ({
    field: sort.field,
    direction: sort.direction
  }), [sort.field, sort.direction])

  const memoizedPagination = useMemo(() => ({
    page: pagination.page,
    limit: pagination.limit
  }), [pagination.page, pagination.limit])

  // Fetch departments effect - only when parameters actually change
  useEffect(() => {
    // Create a key from current parameters
    const currentParamsKey = JSON.stringify({
      page: memoizedPagination.page,
      limit: memoizedPagination.limit,
      search: memoizedFilters.search,
      status: memoizedFilters.status,
      category: memoizedFilters.category,
      sortField: memoizedSort.field,
      sortDirection: memoizedSort.direction
    })

    // Only fetch if parameters have changed
    if (currentParamsKey !== prevParamsRef.current) {
      prevParamsRef.current = currentParamsKey

      fetchDepartments({
        page: memoizedPagination.page,
        limit: memoizedPagination.limit,
        filters: memoizedFilters,
        sort: memoizedSort,
      })
    }
  }, [memoizedPagination.page, memoizedPagination.limit, memoizedFilters.search, memoizedFilters.status,memoizedFilters.category, memoizedSort.field, memoizedSort.direction, fetchDepartments])

  // Error handling effect
  useEffect(() => {
    if (error) {
      toast({
        title: "Error",
        description: error,
        variant: "destructive",
      });
      clearError?.();
    }
  }, [error, toast, clearError])

  // Clear error when component unmounts
  useEffect(() => {
    return () => {
      clearError?.();
    };
  }, [clearError]);

  // Stats display
  const statsCards = stats ? [
    {
      title: "Total Departments",
      value: stats.totalDepartments,
      icon: <Building2 className="h-8 w-8 text-muted-foreground" />,
      color: "text-muted-foreground"
    },
    {
      title: "Active",
      value: stats.activeDepartments,
      icon: (
        <div className="h-8 w-8 bg-green-100 rounded-full flex items-center justify-center">
          <div className="h-3 w-3 bg-green-600 rounded-full" />
        </div>
      ),
      color: "text-green-600"
    },
    {
      title: "Inactive",
      value: stats.inactiveDepartments,
      icon: (
        <div className="h-8 w-8 bg-gray-100 rounded-full flex items-center justify-center">
          <div className="h-3 w-3 bg-gray-600 rounded-full" />
        </div>
      ),
      color: "text-gray-600"
    },
  ] : [];



  return (
    <div className="space-y-6">
      <PageHeader
        title="Departments"
        subtitle="Manage organizational departments"
        onAddClick={() => navigateTo("/departments/add")}
        addButtonText="Add Department"
        showAddButton={canCreate("departments")}

        // Filter functionality - Updated to match clients/leads page
        showFilterButton={true}
        hasActiveFilters={Object.values(uiFilters).some(v => v && v !== 'all' && v !== '')}
        isFilterExpanded={isFilterExpanded}
        onFilterToggle={() => {
          setIsFilterExpanded(!isFilterExpanded);
        }}
        activeFiltersCount={Object.values(uiFilters).filter(v => v && v !== 'all' && v !== '').length}
        filterText="Filter Departments"

        // Refresh functionality
        showRefreshButton={true}
        onRefresh={handleFilterReset}
        isRefreshing={loading}

        actions={
          <GenericReportExporter
            moduleName="departments"
            data={departments}
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
        {/* Generic Filter - Updated to match clients/leads page */}
        {isFilterExpanded && (
          <GenericFilter
            config={filterConfig}
            values={uiFilters}
            onFilterChange={handleFilterChange}
            onReset={handleFilterReset}
            loading={loading}
          />
        )}
      </PageHeader>

      {/* Error Display */}
      {error && (
        <Alert variant="destructive" className="border-destructive bg-destructive/10">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription className="text-destructive-foreground">{error.error?.message || error.error || error.message || 'An error occurred'}</AlertDescription>
        </Alert>
      )}

      <div className="space-y-4">
        {/* Data Table */}
        <DataTable
          data={departments}
          columns={columns}
          loading={loading}
          totalCount={pagination.total}
          pageSize={pagination.limit}
          currentPage={pagination.page}
          onPageChange={handlePageChange}
          onPageSizeChange={handlePageSizeChange}
          onSort={handleSort}
          sortColumn={sort.field}
          sortDirection={sort.direction}
          emptyMessage="No departments found"
          resourceName="departments"
          onView={handleViewDepartment}
          onDelete={handleDeleteDepartment}
          onRestore={handleRestoreDepartment}
          enablePermissionChecking={true}
          statsCards={statsCards}
        />
      </div>

      {/* Quick View Modal */}
      <CustomModal
        isOpen={isQuickViewOpen}
        onClose={() => setIsQuickViewOpen(false)}
        title="Department Details"
        modalSize="lg"
      >
        {selectedDepartmentForView && (
          <div className="space-y-4">
            {/* Tab Navigation */}
            <div className="border-b border-border">
              <nav className="flex" aria-label="Tabs">
                {[{
                  id: 'overview', name: 'Overview'
                },
                { id: 'users', name: 'Users' },
                { id: 'activity', name: 'Activity' }
                ].map((tab) => (
                  <div className="flex-1" key={tab.id}>
                    <button
                      onClick={() => setActiveTab(tab.id)}
                      className={cn(
                        "w-full text-center whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm transition-colors",
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
                  {/* Department Header */}
                  <div className="flex items-center space-x-4">
                    <div className="w-16 h-16 bg-primary/10 rounded-lg flex items-center justify-center">
                      <Building2 className="h-8 w-8 text-primary" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold">{selectedDepartmentForView.name}</h3>
                      <p className="text-muted-foreground">Department</p>
                    </div>
                  </div>

                  {/* Department Details Grid */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Name</label>
                      <p className="mt-1">{selectedDepartmentForView.name}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Category</label>
                      <p className="mt-1">{selectedDepartmentForView.category}</p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Status</label>
                      <div className="mt-1">
                        <Badge className={cn(
                          "border",
                          selectedDepartmentForView.status === 'active'
                            ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300 border-green-200 dark:border-green-800'
                            : 'bg-muted text-muted-foreground border-border'
                        )}>
                          {selectedDepartmentForView.status?.charAt(0).toUpperCase() + selectedDepartmentForView.status?.slice(1)}
                        </Badge>
                      </div>
                    </div>
                    <div className="col-span-2">
                      <label className="text-sm font-medium text-muted-foreground">Description</label>
                      <div className="mt-1">
                        {selectedDepartmentForView.description ? (
                          <HtmlTextRenderer
                            content={selectedDepartmentForView.description}
                            maxLength={300}
                            className="text-sm text-foreground"
                            fallbackText="No description provided"
                            showFallback={true}
                            renderAsHtml={true}
                            truncateHtml={false}
                          />
                        ) : (
                          <p className="text-sm text-muted-foreground italic">No description provided</p>
                        )}
                      </div>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Created</label>
                      <p className="mt-1">
                        {new Date(selectedDepartmentForView.createdAt as any).toLocaleDateString('en-US', {
                          year: 'numeric',
                          month: 'long',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit'
                        })}
                      </p>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-muted-foreground">Last Updated</label>
                      <p className="mt-1">
                        {new Date(selectedDepartmentForView.updatedAt as any).toLocaleDateString('en-US', {
                          year: 'numeric',
                          month: 'long',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit'
                        })}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Users Tab */}
              {activeTab === 'users' && (
                <div className="space-y-4">
                  <div className="text-center py-4">
                    <h4 className="text-lg font-medium mb-2">Department Users</h4>
                    <p className="text-muted-foreground text-sm mb-4">
                      Users assigned to this department
                    </p>
                  </div>

                  <div className="space-y-3">
                    {/* Department Status for Users */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className={cn(
                        "w-8 h-8 rounded-full flex items-center justify-center",
                        selectedDepartmentForView.status === 'active'
                          ? "bg-green-100 dark:bg-green-900/20"
                          : "bg-gray-100 dark:bg-gray-900/20"
                      )}>
                        <span className={cn(
                          "text-sm",
                          selectedDepartmentForView.status === 'active' ? "text-green-600" : "text-gray-600"
                        )}>
                          {selectedDepartmentForView.status === 'active' ? '✓' : '○'}
                        </span>
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Department Status</p>
                        <p className="text-xs text-muted-foreground">
                          {selectedDepartmentForView.status === 'active'
                            ? 'Active - Users can be assigned to this department'
                            : 'Inactive - Not available for new user assignments'
                          }
                        </p>
                      </div>
                    </div>

                    {/* User Assignment Info */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/20 flex items-center justify-center">
                        <Users className="h-4 w-4 text-blue-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">User Assignment</p>
                        <p className="text-xs text-muted-foreground">
                          Users in this department will have department-specific permissions and access
                        </p>
                      </div>
                    </div>

                    {/* Department Hierarchy */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className="w-8 h-8 rounded-full bg-purple-100 dark:bg-purple-900/20 flex items-center justify-center">
                        <Building2 className="h-4 w-4 text-purple-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Department Structure</p>
                        <p className="text-xs text-muted-foreground">
                          Part of the organizational structure for managing users and permissions
                        </p>
                      </div>
                    </div>

                    {/* Management Note */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className="w-8 h-8 rounded-full bg-orange-100 dark:bg-orange-900/20 flex items-center justify-center">
                        <Settings className="h-4 w-4 text-orange-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Management</p>
                        <p className="text-xs text-muted-foreground">
                          Department settings can be managed through the department management interface
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Activity Tab */}
              {activeTab === 'activity' && (
                <div className="space-y-4">
                  <div className="text-center py-4">
                    <h4 className="text-lg font-medium mb-2">Department Activity</h4>
                    <p className="text-muted-foreground text-sm mb-4">
                      Recent activity and important events
                    </p>
                  </div>

                  <div className="space-y-3">
                    {/* Department Creation */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/20 flex items-center justify-center">
                        <Building2 className="h-4 w-4 text-blue-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Department Created</p>
                        <p className="text-xs text-muted-foreground">
                          {new Date(selectedDepartmentForView.createdAt as any).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'long',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit'
                          })}
                        </p>
                      </div>
                    </div>

                    {/* Status Information */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className={cn(
                        "w-8 h-8 rounded-full flex items-center justify-center",
                        selectedDepartmentForView.status === 'active'
                          ? "bg-green-100 dark:bg-green-900/20"
                          : "bg-gray-100 dark:bg-gray-900/20"
                      )}>
                        <span className={cn(
                          "text-sm",
                          selectedDepartmentForView.status === 'active' ? "text-green-600" : "text-gray-600"
                        )}>
                          {selectedDepartmentForView.status === 'active' ? '●' : '○'}
                        </span>
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium capitalize">
                          Department {selectedDepartmentForView.status}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Current department status
                        </p>
                      </div>
                    </div>

                    {/* Last Update */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className="w-8 h-8 rounded-full bg-purple-100 dark:bg-purple-900/20 flex items-center justify-center">
                        <Calendar className="h-4 w-4 text-purple-600" />
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Last Updated</p>
                        <p className="text-xs text-muted-foreground">
                          {new Date(selectedDepartmentForView.updatedAt as any).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'long',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit'
                          })}
                        </p>
                      </div>
                    </div>

                    {/* Department Information */}
                    <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                      <div className="w-8 h-8 rounded-full bg-yellow-100 dark:bg-yellow-900/20 flex items-center justify-center">
                        <span className="text-yellow-600 text-sm">📋</span>
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium">Department Info</p>
                        <p className="text-xs text-muted-foreground">
                          {selectedDepartmentForView.description ? 'Has description and details' : 'Basic department setup'}
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