"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useSession } from "next-auth/react";
import { useRoles } from "@/hooks/use-roles";
import { useDepartments } from "@/hooks/use-departments";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { ArrowLeft, AlertTriangle } from "lucide-react";
import type { CreateRoleData } from "@/types";
import PageHeader from "@/components/shared/page-header";
import GenericForm from "@/components/shared/generic-form";
import { handleAPIError } from "@/lib/utils/api-client";
import { createRoleFormSchema, CreateRoleFormData } from "@/lib/validations/role";
import { useNavigationLoading } from "@/hooks/use-navigation-loading";
import { useNavigation } from "@/components/providers/navigation-provider";

export default function CreateRolePage() {
  const router = useRouter();
  const { toast } = useToast();
  const { createRole, actionLoading, error, clearError } = useRoles();
  const { departments, allDepartments, fetchDepartments } = useDepartments();
  const { navigateTo } = useNavigation()
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [availableDepartments, setAvailableDepartments] = useState<Array<{ value: string, label: string }>>([]);

  const form = useForm<CreateRoleFormData>({
    resolver: zodResolver(createRoleFormSchema),
    defaultValues: {
      name: "",
      displayName: "",
      description: "",
      department: "",
      hierarchyLevel: 1,
      maxUsers: '', // Use empty string instead of undefined
    },
  });

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

  // Fetch roles and departments for filters on mount
  useEffect(() => {
    if (availableDepartments.length === 0) {
      fetchAvailableDepartments();
    }
  }, [fetchAvailableDepartments]);

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


  // Auto-generate name from display name
  const watchDisplayName = form.watch('displayName');
  useEffect(() => {
    if (watchDisplayName && !form.getValues('name')) {
      const generatedName = watchDisplayName
        .toLowerCase()
        .replace(/[^a-zA-Z0-9\s\-_]/g, '')
        .replace(/\s+/g, '_')
        .substring(0, 50);
      form.setValue('name', generatedName);
    }
  }, [watchDisplayName, form]);

  const handleSubmit = async (data: CreateRoleFormData) => {
    try {
      setIsSubmitting(true);
      clearError();

      // Transform form data to handle number fields properly
      const roleData: CreateRoleData = {
        ...data,
        hierarchyLevel: typeof data.hierarchyLevel === 'string' ? parseInt(data.hierarchyLevel) : (data.hierarchyLevel || 1),
        maxUsers: data.maxUsers && data.maxUsers !== "" ? (typeof data.maxUsers === 'string' ? parseInt(data.maxUsers) : data.maxUsers) : undefined,
        permissions: [], // Will be set later via permissions page
      };


      const result = await createRole(roleData as any);

      toast({
        title: "Success",
        description: "Role created successfully. You can now configure permissions.",
      });

      // Redirect to permissions page for the newly created role
      if (result && result._id) {
        navigateTo(`/roles/permissions/${result._id}`);
      } else {
        navigateTo('/roles');
      }
    } catch (error: any) {
      console.log('error creating role:', error);
      handleAPIError(error, "Failed to create role");
    } finally {
      setIsSubmitting(false);
    }
  };

  const { isNavigating, handleNavigation } = useNavigationLoading();

  const handleCancel = () => {
    handleNavigation("/roles");
  };

  // Define form fields configuration
  const formFields = [
    {
      fields: [
        {
          name: "displayName",
          label: "Display Name",
          type: "text" as const,
          required: true,
          placeholder: "Senior Developer",
          description: "Human-readable name for the role",
          cols: 12,
          mdCols: 6,
          lgCols: 6,
        },
        {
          name: "name",
          label: "Internal Name",
          type: "text" as const,
          required: true,
          placeholder: "senior_developer",
          description: "System identifier (auto-generated)",
          cols: 12,
          mdCols: 6,
          lgCols: 6,
        },
        {
          name: "department",
          label: "Department",
          type: "select" as const,
          searchable: true,
          required: true,
          placeholder: "Select department",
          description: "Department this role belongs to",
          options: [
            { value: 'all', label: 'All Departments' },
            ...availableDepartments,
          ],
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "hierarchyLevel",
          label: "Hierarchy Level",
          type: "select" as const,
          searchable: true,
          required: true,
          placeholder: "Select level",
          description: "Authority level (1-10)",
          options: Array.from({ length: 10 }, (_, i) => i + 1).map((level) => ({
            value: level,
            label: `Level ${level} ${level === 1 ? '(Lowest)' : level === 10 ? '(Highest)' : ''}`,
          })),
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "maxUsers",
          label: "Max Users",
          type: "number" as const,
          placeholder: "Unlimited",
          description: "Maximum users allowed (optional)",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "description",
          label: "Description",
          type: "rich-text" as const,
          placeholder: "Describe the role's responsibilities and scope...",
          description: "Optional description of the role's purpose and responsibilities",
          rows: 3,
          cols: 12,
          mdCols: 12,
          lgCols: 12,
        },
      ]
    }
  ];

  return (
    <div>
      {/* Page Header */}
      <PageHeader
        title="Add New Role"
        subtitle="Create a new role with permissions"
        showAddButton={false}
        actions={
          <Button
            variant="outline"
            onClick={handleCancel}
            disabled={isNavigating}
          >
            <ArrowLeft className={`h-4 w-4 mr-2 ${isNavigating ? 'animate-spin' : ''}`} />
            {isNavigating ? 'Going back...' : 'Back to Roles'}
          </Button>
        }
      />

      {/* Error Alert */}
      {error && (
        <Alert variant="destructive" className="mb-6">
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

      {/* Role Form */}
      <div>
        <GenericForm
          form={form}
          fields={formFields}
          onSubmit={handleSubmit}
          onCancel={handleCancel}
          loading={isSubmitting}
          submitText={isSubmitting ? "Creating..." : "Create Role"}
          cancelText="Cancel"
          gridCols={3}
        />
      </div>
    </div>
  );
}