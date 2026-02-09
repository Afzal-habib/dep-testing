"use client";

import React, { useState, useMemo } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Card } from "@/components/ui/card";
import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  MoreVertical,
  Grid3X3,
  List,
  Eye,
  Edit,
  Trash2,
  Copy,
  Download,
  Archive,
  RotateCcw,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { TableLoader } from "../ui/loader";
import { usePermissions } from "@/hooks/use-permissions";
import { useRouter } from "next/navigation";
import { useNavigation } from "../providers/navigation-provider";

export interface ColumnDef<T> {
  key: keyof T;
  label: string;
  sortable?: boolean;
  render?: (value: any, row: T) => React.ReactNode;
  className?: string;
  width?: string;
}

export interface ActionMenuItem<T> {
  label: string | ((row: T) => string);
  icon: React.ReactNode;
  onClick: (row: T) => void;
  variant?: "default" | "destructive";
  disabled?: (row: T) => boolean;
  requiredPermission?: {
    resource: string;
    action: string;
    condition?: string;
  };
  requiresCreate?: boolean;
  requiresRead?: boolean;
  requiresUpdate?: boolean;
  requiresDelete?: boolean;
  hasPermission?: (row: T) => boolean;
  hideIfNoPermission?: boolean;
  hideIf?: (row: T) => boolean;
}

// Simplified interface - no need for explicit enabled flags for edit/delete
export interface GenericActionConfig {
  view?: {
    enabled?: boolean; // Optional - defaults to true
    label?: string;
    onClick?: (row: any) => void;
  };
  edit?: {
    enabled?: boolean; // Optional - defaults to true if user has permission
    label?: string;
    route?: string; // e.g., "/users/edit" - will append /{id}
    onClick?: (row: any) => void;
  };
  delete?: {
    enabled?: boolean; // Optional - defaults to true if user has permission
    label?: string;
    onClick?: (row: any) => void;
    confirmTitle?: string;
    confirmMessage?: string;
  };
  restore?: {
    enabled?: boolean; // Optional - defaults to true if user has permission
    label?: string;
    onClick?: (row: any) => void;
  };
  duplicate?: {
    enabled?: boolean; // Must be explicitly enabled
    label?: string;
    onClick?: (row: any) => void;
  };
  archive?: {
    enabled?: boolean; // Must be explicitly enabled
    label?: string;
    onClick?: (row: any) => void;
  };
  export?: {
    enabled?: boolean; // Must be explicitly enabled
    label?: string;
    onClick?: (row: any) => void;
  };
  custom?: ActionMenuItem<any>[];
}

export interface DataTableProps<T> {
  data: T[];
  columns: ColumnDef<T>[];
  loading?: boolean;
  totalCount?: number;
  NoOfCards?: number;
  pageSize?: number;
  currentPage?: number;
  onPageChange?: (page: number) => void;
  onPageSizeChange?: (pageSize: number) => void;
  onSort?: (column: keyof T, direction: "asc" | "desc") => void;
  sortColumn?: keyof T;
  sortDirection?: "asc" | "desc";
  showViewToggle?: boolean;
  defaultView?: "table" | "grid";
  onViewChange?: (view: "table" | "grid") => void;
  onRowClick?: (row: T) => void;
  className?: string;
  emptyMessage?: string;
  gridRenderItem?: (item: T, index: number) => React.ReactNode;

  // Generic action system
  resourceName?: string; // e.g., "users", "departments"
  actions?: GenericActionConfig; // Generic action configuration
  customActions?: ActionMenuItem<T>[]; // Additional custom actions
  enablePermissionChecking?: boolean;
  showActionsIfNoPermission?: boolean;

  // Event handlers for generic actions
  onView?: (row: T) => void;
  onEdit?: (row: T) => void;
  onDelete?: (row: T) => void;
  onDuplicate?: (row: T) => void;
  onArchive?: (row: T) => void;
  onExport?: (row: T) => void;
  onRestore?: (row: T) => void;

  // Legacy support
  showQuickView?: boolean;
  onQuickView?: (row: T) => void;

  // Stats cards for summary information
  statsCards?: Array<{
    title: string;
    value: any;
    icon?: React.ReactNode;
    color?: string;
  }>;
}

const DataTable = <T extends Record<string, any>>({
  data,
  columns,
  loading = false,
  totalCount = 0,
  NoOfCards = 4,
  pageSize = 5,
  currentPage = 1,
  onPageChange,
  onPageSizeChange,
  onSort,
  sortColumn,
  sortDirection,
  showViewToggle = true,
  defaultView = "table",
  onViewChange,
  onRowClick,
  className,
  emptyMessage = "No data available",
  gridRenderItem,
  resourceName,
  actions,
  customActions = [],
  enablePermissionChecking = true,
  showActionsIfNoPermission = false,
  onView,
  onEdit,
  onDelete,
  onDuplicate,
  onArchive,
  onExport,
  onRestore,
  showQuickView = false,
  onQuickView,
  statsCards, // Add this
}: DataTableProps<T>) => {
  const [currentView, setCurrentView] = useState<"table" | "grid">(defaultView);
  const router = useRouter();
  const { navigateTo, isNavigating } = useNavigation()

  // Get permissions hook
  const { canCreate, canRead, canUpdate, canDelete, hasPermission } = usePermissions();

  const totalPages = Math.ceil(totalCount / pageSize);
  const startItem = (currentPage - 1) * pageSize + 1;
  const endItem = Math.min(currentPage * pageSize, totalCount);

  // Generic action handlers
  const handleGenericEdit = (row: T) => {
    if (actions?.edit?.onClick) {
      actions.edit.onClick(row);
    } else if (actions?.edit?.route && row._id) {
      navigateTo(`${actions.edit.route}/${row._id}`);
    } else if (onEdit) {
      onEdit(row);
    } else if (resourceName && row._id) {
      navigateTo(`/${resourceName}/edit/${row._id}`);
    }
  };

  // Enhanced view handler that provides fallback behavior
  const handleGenericView = (row: T) => {
    if (actions?.view?.onClick) {
      actions.view.onClick(row);
    } else if (onView) {
      onView(row);
    } else if (onQuickView) {
      onQuickView(row);
    } else {
      // Default fallback - could navigate to detail view or show a toast
      console.log('View action triggered for:', row);
      // Optional: Default navigation
      if (resourceName && row._id) {
        navigateTo(`/${resourceName}/${row._id}`);
      }
    }
  };

  const handleGenericDelete = (row: T) => {
    if (actions?.delete?.onClick) {
      actions.delete.onClick(row);
    } else if (onDelete) {
      onDelete(row);
    }
  };

  const handleGenericDuplicate = (row: T) => {
    if (actions?.duplicate?.onClick) {
      actions.duplicate.onClick(row);
    } else if (onDuplicate) {
      onDuplicate(row);
    }
  };

  const handleGenericArchive = (row: T) => {
    if (actions?.archive?.onClick) {
      actions.archive.onClick(row);
    } else if (onArchive) {
      onArchive(row);
    }
  };

  const handleGenericExport = (row: T) => {
    if (actions?.export?.onClick) {
      actions.export.onClick(row);
    } else if (onExport) {
      onExport(row);
    }
  };

  const handleGenericRestore = (row: T) => {
    if (onRestore) {
      onRestore(row);
    }
  };

  // Build generic actions with internal permission checking
  const buildGenericActions = useMemo((): ActionMenuItem<T>[] => {
    const genericActions: ActionMenuItem<T>[] = [];

    // View action - ALWAYS enabled by default
    const viewEnabled = actions?.view?.enabled !== false;
    const hasViewHandler = showQuickView || onQuickView || actions?.view?.onClick || onView;

    if (viewEnabled || hasViewHandler) {
      genericActions.push({
        label: actions?.view?.label || "View",
        icon: <Eye className="h-4 w-4" />,
        onClick: handleGenericView,
        requiresRead: true,
        hideIfNoPermission: true,
      });
    }

    // Edit action - Check permissions internally
    if (actions?.edit?.enabled !== false && // Not explicitly disabled
      (!resourceName || canUpdate(resourceName))) { // Has permission if resourceName provided
      genericActions.push({
        label: actions?.edit?.label || "Edit",
        icon: <Edit className="h-4 w-4" />,
        onClick: handleGenericEdit,
        requiresUpdate: true,
        hideIfNoPermission: true,
        hideIf: (row: T) => (row as any).status === 'deleted',
      });
    }

    // Delete action - Check permissions internally
    if (actions?.delete?.enabled !== false && // Not explicitly disabled
      (!resourceName || canDelete(resourceName))) { // Has permission if resourceName provided
      genericActions.push({
        label: actions?.delete?.label || "Delete",
        icon: <Trash2 className="h-4 w-4" />,
        onClick: handleGenericDelete,
        variant: "destructive" as const,
        requiresDelete: true,
        hideIfNoPermission: true,
        hideIf: (row: T) => (row as any).status === 'deleted',
      });
    }

    // Restore action - Only show for deleted items
    if (actions?.restore?.enabled !== false && // Not explicitly disabled
      (!resourceName || canUpdate(resourceName))) { // Has permission if resourceName provided
      genericActions.push({
        label: actions?.restore?.label || "Restore",
        icon: <RotateCcw className="h-4 w-4" />,
        onClick: actions?.restore?.onClick || handleGenericRestore,
        requiresUpdate: true,
        hideIfNoPermission: true,
        hideIf: (row: T) => (row as any).status !== 'deleted',
      });
    }

    // Duplicate action
    if (actions?.duplicate?.enabled &&
      (!resourceName || canCreate(resourceName))) {
      genericActions.push({
        label: actions?.duplicate?.label || "Duplicate",
        icon: <Copy className="h-4 w-4" />,
        onClick: handleGenericDuplicate,
        requiresCreate: true,
        hideIfNoPermission: true,
      });
    }

    // Archive action
    if (actions?.archive?.enabled &&
      (!resourceName || canUpdate(resourceName))) {
      genericActions.push({
        label: actions?.archive?.label || "Archive",
        icon: <Archive className="h-4 w-4" />,
        onClick: handleGenericArchive,
        requiresUpdate: true,
        hideIfNoPermission: true,
      });
    }

    // Export action
    if (actions?.export?.enabled &&
      (!resourceName || canRead(resourceName))) {
      genericActions.push({
        label: actions?.export?.label || "Export",
        icon: <Download className="h-4 w-4" />,
        onClick: handleGenericExport,
        requiresRead: true,
        hideIfNoPermission: true,
      });
    }

    return genericActions;
  }, [actions, showQuickView, onQuickView, onView, onRestore, resourceName, canCreate, canRead, canUpdate, canDelete]);

  // Combine all actions
  const allActions = useMemo((): ActionMenuItem<T>[] => {
    // Clone generic actions
    const generic = [...buildGenericActions];

    // Find indices for "Edit" and "Delete"
    const editIdx = generic.findIndex(a =>
      typeof a.label === "string" ? a.label.toLowerCase() === "edit" : false
    );
    const deleteIdx = generic.findIndex(a =>
      typeof a.label === "string" ? a.label.toLowerCase() === "delete" : false
    );

    // Insert custom actions after "Edit" (or after "View" if "Edit" not found)
    let insertIdx = editIdx !== -1 ? editIdx + 1 : 1;
    // But before "Delete" if "Delete" exists and would be before insertIdx
    if (deleteIdx !== -1 && deleteIdx < insertIdx) {
      insertIdx = deleteIdx;
    }

    // Gather all custom actions
    const custom = actions?.custom ?? [];
    const legacyCustom = customActions ?? [];
    const allCustom = [...custom, ...legacyCustom];

    // Insert custom actions at the calculated index
    generic.splice(insertIdx, 0, ...allCustom);

    return generic;
  }, [buildGenericActions, actions?.custom, customActions]);

  // Enhanced permission checking function
  const checkActionPermission = (action: ActionMenuItem<T>, row: T): { hasPermission: boolean; isDisabled: boolean } => {
    // First check if action is disabled by row-specific logic
    const isRowDisabled = action.disabled ? action.disabled(row) : false;

    if (!enablePermissionChecking) {
      return { hasPermission: true, isDisabled: isRowDisabled };
    }

    // Custom permission check function takes precedence
    if (action.hasPermission) {
      const customCheck = action.hasPermission(row);
      return { hasPermission: customCheck, isDisabled: isRowDisabled || !customCheck };
    }

    // Check specific permission requirement
    if (action.requiredPermission) {
      const { resource, action: permAction, condition } = action.requiredPermission;
      const permitted = hasPermission(resource, permAction, condition);
      return { hasPermission: permitted, isDisabled: isRowDisabled || !permitted };
    }

    // Check simple permission flags with resource name
    if (resourceName) {
      if (action.requiresCreate && !canCreate(resourceName)) {
        return { hasPermission: false, isDisabled: true };
      }
      if (action.requiresRead && !canRead(resourceName)) {
        return { hasPermission: false, isDisabled: true };
      }
      if (action.requiresUpdate && !canUpdate(resourceName)) {
        return { hasPermission: false, isDisabled: true };
      }
      if (action.requiresDelete && !canDelete(resourceName)) {
        return { hasPermission: false, isDisabled: true };
      }
    }

    return { hasPermission: true, isDisabled: isRowDisabled };
  };

  // Filter actions based on permissions
  const getFilteredActions = (row: T): ActionMenuItem<T>[] => {
    return allActions.filter(action => {
      const { hasPermission: permitted } = checkActionPermission(action, row);

      // Hide action if no permission and hideIfNoPermission is true (default)
      if (!permitted && (action.hideIfNoPermission !== false)) {
        return false;
      }

      // Hide action if hideIf condition is met
      if (action.hideIf && action.hideIf(row)) {
        return false;
      }

      return true;
    });
  };

  const handleViewChange = (view: "table" | "grid") => {
    setCurrentView(view);
    onViewChange?.(view);
  };

  const handleSort = (column: keyof T) => {
    if (!onSort) return;

    const newDirection =
      sortColumn === column && sortDirection === "asc" ? "desc" : "asc";
    onSort(column, newDirection);
  };

  const renderSortIcon = (column: keyof T) => {
    if (sortColumn !== column) {
      return <ArrowUpDown className="h-4 w-4 ml-2 text-muted-foreground" />;
    }
    return sortDirection === "asc" ?
      <ArrowUp className="h-4 w-4 ml-2" /> :
      <ArrowDown className="h-4 w-4 ml-2" />;
  };

  // Render action dropdown with permission checks
  const renderActionDropdown = (row: T, inGrid = false) => {
    const filteredActions = getFilteredActions(row);

    if (filteredActions.length === 0) {
      return null;
    }

    return (
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            className={cn(
              inGrid ? "h-8 w-8 p-0" : "h-8 w-8 p-0"
            )}
            onClick={(e) => e.stopPropagation()}
          >
            <MoreVertical className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          {filteredActions.map((action, actionIndex) => {
            const { hasPermission: permitted, isDisabled } = checkActionPermission(action, row);

            return (
              <DropdownMenuItem
                key={actionIndex}
                onSelect={(e) => {
                  e.stopPropagation();
                  if (isDisabled) {
                    e.preventDefault();
                    return;
                  }
                  action.onClick(row);
                }}
                disabled={isDisabled}
                className={cn(
                  action.variant === "destructive" ? "text-destructive" : "",
                  isDisabled ? "opacity-50 cursor-not-allowed pointer-events-none" : "",
                  !permitted && showActionsIfNoPermission ? "opacity-50" : ""
                )}
              >
                {action.icon}
                <span>{typeof action.label === 'function' ? action.label(row) : action.label}</span>
                {!permitted && showActionsIfNoPermission && (
                  <span className="ml-auto text-xs text-muted-foreground">(No permission)</span>
                )}
              </DropdownMenuItem>
            );
          })}
        </DropdownMenuContent>
      </DropdownMenu>
    );
  };

  // Default grid item renderer with permission-aware actions
  const defaultGridItem = (item: T, index: number) => (
    <Card
      key={index}
      className="p-4 cursor-pointer hover:shadow-md transition-shadow"
      onClick={() => onRowClick?.(item)}
    >
      <div className="space-y-2">
        {columns.slice(0, 3).map((column) => (
          <div key={String(column.key)} className="flex justify-between">
            <span className="text-sm text-muted-foreground">{column.label}:</span>
            <span className="text-sm font-medium">
              {column.render ? column.render(item[column.key], item) : String(item[column.key])}
            </span>
          </div>
        ))}
        {allActions.length > 0 && (
          <div className="flex justify-end pt-2">
            {renderActionDropdown(item, true)}
          </div>
        )}
      </div>
    </Card>
  );

  if (loading) {
    return (
      <div className={cn("space-y-4", className)}>
        <TableLoader NoOfCards={NoOfCards} rows={pageSize} columns={columns.length} />
      </div >
    );
  }

  return (
    <div className={cn("space-y-4", className)}>
      {/* Stats Cards - Add this section before existing content */}
      {statsCards && statsCards.length > 0 && (
        <div className="grid grid-flow-col auto-cols-fr gap-4">
          {statsCards.map((stat, index) => (
            <div key={index} className="bg-card rounded-lg border p-4 flex-1">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">{stat.title}</p>
                  <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
                </div>
                {stat.icon && (
                  <div className={stat.color}>
                    {stat.icon}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="flex justify-between items-center">
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground">Records per page:</span>
          <select
            value={pageSize}
            onChange={(e) => onPageSizeChange?.(Number(e.target.value))}
            className="h-8 px-2 bg-background border border-border rounded text-sm"
          >
            <option value={5}>5</option>
            <option value={10}>10</option>
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
        </div>
        {/* View Toggle */}
        {showViewToggle && (
          <div className="flex justify-end">
            <div className="flex items-center bg-muted rounded-md">
              <Button
                variant={currentView === "table" ? "default" : "ghost"}
                size="sm"
                onClick={() => handleViewChange("table")}
                className="h-8 w-8 p-1"
              >
                <List className="h-4 w-4" />
              </Button>
              <Button
                variant={currentView === "grid" ? "default" : "ghost"}
                size="sm"
                onClick={() => handleViewChange("grid")}
                className="h-8 w-8 p-1"
              >
                <Grid3X3 className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Content */}
      {data.length === 0 ? (
        <div className="text-center py-12">
          <p className="text-muted-foreground">{emptyMessage}</p>
        </div>
      ) : currentView === "table" ? (
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                {columns.map((column) => (
                  <TableHead
                    key={String(column.key)}
                    className={cn(column.className)}
                    style={{ width: column.width }}
                  >
                    {column.sortable ? (
                      <button
                        className="flex items-center hover:text-foreground transition-colors"
                        onClick={() => handleSort(column.key)}
                      >
                        {column.label}
                        {renderSortIcon(column.key)}
                      </button>
                    ) : (
                      column.label
                    )}
                  </TableHead>
                ))}
                {allActions.length > 0 && (
                  <TableHead className="w-[50px]">Actions</TableHead>
                )}
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((row, index) => (
                <TableRow
                  key={index}
                  className={cn(
                    onRowClick ? "cursor-pointer hover:bg-muted/50" : ""
                  )}
                  onClick={() => onRowClick?.(row)}
                >
                  {columns.map((column) => (
                    <TableCell
                      key={String(column.key)}
                      className={cn(column.className)}
                    >
                      {column.render
                        ? column.render(row[column.key], row)
                        : String(row[column.key])
                      }
                    </TableCell>
                  ))}
                  {allActions.length > 0 && (
                    <TableCell>
                      {renderActionDropdown(row)}
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {data.map((item, index) =>
            gridRenderItem ? gridRenderItem(item, index) : defaultGridItem(item, index)
          )}
        </div>
      )}

      {/* Pagination */}
      {totalCount > 0 && (
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="text-sm text-muted-foreground">
            Showing {startItem} to {endItem} of {totalCount} entries
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1">
              <Button
                variant="outline"
                size="sm"
                onClick={() => onPageChange?.(1)}
                disabled={currentPage === 1}
                className="h-8 w-8 p-0"
              >
                <ChevronsLeft className="h-4 w-4" />
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onPageChange?.(currentPage - 1)}
                disabled={currentPage === 1}
                className="h-8 w-8 p-0"
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>

              <span className="text-sm px-3">
                Page {currentPage} of {totalPages}
              </span>

              <Button
                variant="outline"
                size="sm"
                onClick={() => onPageChange?.(currentPage + 1)}
                disabled={currentPage === totalPages}
                className="h-8 w-8 p-0"
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onPageChange?.(totalPages)}
                disabled={currentPage === totalPages}
                className="h-8 w-8 p-0"
              >
                <ChevronsRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DataTable;

// Re-export HtmlTextRenderer for convenience
export { default as HtmlTextRenderer } from './html-text-renderer';
export type { HtmlTextRendererProps } from './html-text-renderer';