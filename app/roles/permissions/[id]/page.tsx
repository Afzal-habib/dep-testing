"use client";

import { useState, useEffect } from "react";
import { useRouter, useParams } from "next/navigation";
import { useRoles } from "@/hooks/use-roles";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { PermissionSelector } from "@/components/roles/permission-selector";
import { Save, ArrowLeft, AlertTriangle, Shield, Crown, Users } from "lucide-react";
import type { Permission } from "@/types";
import PageHeader from "@/components/shared/page-header";
import { FormLoader } from "@/components/ui/loader";
import { useNavigation } from "@/components/providers/navigation-provider";

export default function RolePermissionsPage() {
  const router = useRouter();
  const params = useParams();
  const { toast } = useToast();
  const roleId = params?.id as string;

  const { navigateTo, isNavigating } = useNavigation()

  const {
    roles,
    selectedRole,
    loading,
    error,
    fetchRoles,
    updateRolePermissions,
    fetchRoleById,
    setSelectedRole,
    clearError,
  } = useRoles();

  const [selectedPermissions, setSelectedPermissions] = useState<Permission[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);

  // Load data on mount (stable dependency on fetchRoles)
  useEffect(() => {
    const loadData = async () => {
      try {
        fetchRoles();
      } catch (error) {
        toast({
          title: "Error",
          description: "Failed to load role data",
          variant: "destructive",
        });
      }
    };

    loadData();
    // Intentionally depend only on fetchRoles (stable via useCallback in the hook)
  }, [fetchRoles]);

  // Load specific role data and fetch individual role if needed
  useEffect(() => {
    if (!roleId) return;

    const loadRoleData = async () => {
      try {
        // First check if role exists in the current roles array
        let role = roles.find((r) => r._id === roleId);

        // If not found in the current array, fetch it individually
        if (!role && roles.length > 0) {
          const response = await fetchRoleById(roleId);
          if (response && (response as any).success && (response as any).data) {
            role = (response as any).data;
          }
        }

        if (role) {
          // Only update selectedRole if it's different to avoid re-render loops
          if (!selectedRole || selectedRole._id !== role._id) {
            setSelectedRole(role);

            // Ensure permissions is always an array and properly structured
            const rolePermissions = Array.isArray(role.permissions) ? role.permissions : [];

            // Validate permission structure
            const validPermissions = rolePermissions.filter((permission: Permission) =>
              permission &&
              typeof permission === 'object' &&
              permission.resource &&
              Array.isArray(permission.actions)
            );

            console.log('Role permissions loaded:', {
              roleId,
              roleName: role.name,
              permissionsCount: validPermissions.length,
              permissions: validPermissions
            });

            setSelectedPermissions(validPermissions);
            setHasChanges(false);
          }
        } else {
          // Role not found, redirect back
          toast({
            title: "Error",
            description: "Role not found",
            variant: "destructive",
          });
          navigateTo("/roles");
        }
      } catch (error) {
        console.error('Error loading role data:', error);
        toast({
          title: "Error",
          description: "Failed to load role data",
          variant: "destructive",
        });
      }
    };

    loadRoleData();
    // Depend on roleId and roles; include stable callbacks. Avoid router to prevent unnecessary re-runs.
  }, [roleId, roles, fetchRoleById, setSelectedRole, selectedRole, navigateTo, toast]);

  // Handle permission changes
  const handlePermissionChange = (permissions: Permission[]) => {
    // Ensure we always work with an array
    const validPermissions = Array.isArray(permissions) ? permissions : [];
    setSelectedPermissions(validPermissions);

    // Check if there are changes
    const originalPermissions = Array.isArray(selectedRole?.permissions) ? selectedRole.permissions : [];
    const hasChanges = JSON.stringify(validPermissions) !== JSON.stringify(originalPermissions);
    setHasChanges(hasChanges);
  };

  // Handle form submission
  const handleSave = async () => {

    try {
      // Validate that we have a selected role
      if (!selectedRole) {
        toast({
          title: "Error",
          description: "No role selected",
          variant: "destructive",
        });
        return;
      }

      // Validate that we have permissions selected
      const validPermissions = Array.isArray(selectedPermissions) ? selectedPermissions : [];

      if (validPermissions.length === 0) {
        toast({
          title: "Validation Error",
          description: "Please select at least one permission for this role",
          variant: "destructive",
        });
        return;
      }

      // Validate permission structure
      const invalidPermissions = validPermissions.filter(permission =>
        !permission.resource || !Array.isArray(permission.actions) || permission.actions.length === 0
      );

      if (invalidPermissions.length > 0) {
        toast({
          title: "Validation Error",
          description: "Some permissions are invalid. Please review your selections.",
          variant: "destructive",
        });
        return;
      }

      setIsSubmitting(true);

      console.log('Updating role permissions:', {
        roleId: selectedRole._id,
        roleName: selectedRole.name,
        permissionsCount: validPermissions.length,
        permissions: validPermissions
      });

      if (!selectedRole._id) {
        throw new Error("Role ID is required");
      }

      const result = await updateRolePermissions(selectedRole._id, validPermissions);

      if (result.type === 'roles/updateRolePermissions/fulfilled') {
        toast({
          title: "Success",
          description: `Role permissions updated successfully. ${validPermissions.length} permission${validPermissions.length !== 1 ? 's' : ''} configured.`,
        });

        setHasChanges(false);

        // Refresh the roles data to ensure updated permission counts are shown
        try {
          await fetchRoles();
        } catch (refreshError) {
          console.warn('Failed to refresh roles data:', refreshError);
        }

        // Wait a bit before redirecting to allow user to see the success message
        setTimeout(() => {
          navigateTo("/roles");
        }, 1500);
      } else {
        throw new Error(result.payload || 'Failed to update role permissions');
      }
    } catch (error: any) {
      console.error('Error updating role permissions:', error);
      toast({
        title: "Error",
        description: error.message || "Failed to update role permissions",
        variant: "destructive",
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancel = () => {
    if (hasChanges) {
      if (confirm("You have unsaved changes. Are you sure you want to leave?")) {
        navigateTo("/roles");
      }
    } else {
      navigateTo("/roles");
    }
  };

  // Loading state
  if (loading || !selectedRole) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Manage Role Permissions"
          subtitle="Loading role data..."
          showAddButton={false}
        />
        <FormLoader fields={1} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        title="Manage Role Permissions"
        subtitle={`Configure permissions for: ${selectedRole.displayName}`}
        showAddButton={false}
        actions={
          <Button
            variant="outline"
            onClick={handleCancel}
            disabled={isSubmitting}
            className="gap-2"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Roles
          </Button>
        }
      />

      {/* Role Info Card */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <CardTitle className="flex items-center gap-2">
                {selectedRole.isSystemRole ? (
                  <Crown className="h-5 w-5 text-yellow-600" />
                ) : (
                  <Shield className="h-5 w-5 text-blue-600" />
                )}
                {selectedRole.displayName}
              </CardTitle>
              <p className="text-sm text-muted-foreground">
                {selectedRole.description || "No description provided"}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant={selectedRole.status === 'active' ? "default" : "secondary"}>
                {selectedRole.status === 'active' ? "Active" : selectedRole.status === 'inactive' ? "Inactive" : "Archived"}
              </Badge>
              <Badge variant="outline">
                Level {selectedRole.hierarchyLevel}
              </Badge>
              {selectedRole.isSystemRole && (
                <Badge variant="secondary" className="bg-yellow-100 text-yellow-800">
                  System Role
                </Badge>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="text-sm font-medium text-muted-foreground">Department</label>
              <div className="mt-1">
                {selectedRole.isSystemRole ? (
                  <Badge variant="secondary" className="bg-yellow-100 text-yellow-800">
                    System-wide
                  </Badge>
                ) : (
                  <span className="text-sm">
                    {typeof selectedRole.departmentDetails === 'object' && selectedRole.departmentDetails
                      ? selectedRole.departmentDetails.name
                      : "N/A"}
                  </span>
                )}
              </div>
            </div>
            <div>
              <label className="text-sm font-medium text-muted-foreground">Current Permissions</label>
              <div className="mt-1 flex items-center gap-2">
                <Users className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm">
                  {selectedPermissions.length} permission{selectedPermissions.length !== 1 ? 's' : ''}
                </span>
              </div>
            </div>
            <div>
              <label className="text-sm font-medium text-muted-foreground">Max Users</label>
              <div className="mt-1">
                <span className="text-sm">
                  {selectedRole.maxUsers ? `${selectedRole.maxUsers} users` : "Unlimited"}
                </span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Error Alert */}
      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            {error}
            <Button
              variant="outline"
              size="sm"
              onClick={clearError}
              className="ml-2"
            >
              Dismiss
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {/* Super Admin Protection Warning */}
      {(selectedRole.name === 'super_admin') && (
        <Alert className="border-amber-200 bg-amber-50">
          <AlertTriangle className="h-4 w-4 text-amber-600" />
          <AlertDescription className="text-amber-800">
            <strong>Protected Role:</strong> Super Administrator permissions cannot be modified to maintain system security.
            This role has ALL PERMISSIONS by default.
          </AlertDescription>
        </Alert>
      )}

      {/* Permissions Configuration */}
      <PermissionSelector
        selectedPermissions={selectedPermissions}
        onPermissionsChange={handlePermissionChange}
        disabled={
          isSubmitting ||
          selectedRole.name === 'super_admin'
        }
      />

      {/* Actions */}
      <div className="flex items-center justify-between pt-6 border-t">
        <div className="flex items-center gap-2">
          {hasChanges && (
            <Badge variant="outline" className="bg-blue-50 text-blue-700 border-blue-200">
              Unsaved Changes
            </Badge>
          )}
        </div>

        <div className="flex gap-3">
          <Button
            variant="outline"
            onClick={handleCancel}
            disabled={isSubmitting}
          >
            Cancel
          </Button>

          <Button
            onClick={handleSave}
            disabled={
              isSubmitting ||
              !hasChanges ||
              selectedPermissions.length === 0 ||
              selectedRole.name === 'super_admin'
            }
            className="gap-2"
          >
            <Save className="h-4 w-4" />
            {isSubmitting ? "Saving..." : "Save Changes"}
          </Button>
        </div>
      </div>
    </div>
  );
}
