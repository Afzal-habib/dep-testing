"use client";

import { useState, useEffect } from "react";
import { useRouter, useParams } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useGenericQueryById } from "@/hooks/use-generic-query";
import { useDepartments } from "@/hooks/use-departments";
import PageHeader from "@/components/shared/page-header";
import GenericForm from "@/components/shared/generic-form";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ArrowLeft } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { handleAPIError } from "@/lib/utils/api-client";
import { useNavigationLoading } from "@/hooks/use-navigation-loading";
import { updateDepartmentSchema, UpdateDepartmentData } from '@/lib/validations/department';
import { useNavigation } from "@/components/providers/navigation-provider";

export default function EditDepartmentPage() {
  const router = useRouter();
  const params = useParams();
  const departmentId = params?.id as string;
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
const { navigateTo } = useNavigation()
  // Use generic query to fetch department
  const genericOptions = {
    entityName: 'departments',
    baseUrl: '/api/departments',
    reduxDispatchers: {
      setEntity: (department: any) => { },
    },
  };
  const { data: department, isLoading: departmentLoading, error } = useGenericQueryById(genericOptions, departmentId, !!departmentId);
  console.log(department)

  // Use updateDepartment from the custom hook
  const { updateDepartment, actionLoading } = useDepartments();

  const form = useForm<UpdateDepartmentData>({
    resolver: zodResolver(updateDepartmentSchema),
    defaultValues: {
      name: "",
      description: "",
      category: "it",
      status: "active",
    },
  });

  // Populate form when department data is loaded
  useEffect(() => {
    if (department) {
      form.reset({
        name: department.name,
        description: department.description || "",
        status: department.status,
        category: department.category,
      });
    }
  }, [department, form]);

  // Handle errors
  useEffect(() => {
    if (error) {
      handleAPIError(error, "Failed to load department");
    }
  }, [error]);

  const handleSubmit = async (data: UpdateDepartmentData) => {
    if (!department || !department._id) return;

    setLoading(true);
    try {
      // @ts-ignore
      await updateDepartment(department._id, data);

      toast({
        title: "Success",
        description: "Department updated successfully",
      });

      navigateTo("/departments");
    } catch (error: any) {
      handleAPIError(error, "Failed to update department");
    } finally {
      setLoading(false);
    } 
  };

  const { isNavigating, handleNavigation } = useNavigationLoading();

  const handleCancel = () => {
    handleNavigation("/departments");
  };

  const formFields = [
    {
      fields: [
        {
          name: "name",
          label: "Department Name",
          type: "text" as const,
          required: true,
          placeholder: "Enter department name",
          description: "A unique name for the department",
          cols: 12,
          mdCols: 4,
        },
        {
          name: "category",
          label: "Category",
          type: "select" as const,
          searchable: true,
          required: true,
          options: [
            { value: "sales", label: "Sales" },
            { value: "support", label: "Support" },
            { value: "it", label: "IT" },
            { value: "management", label: "Management" },
          ],
          cols: 12,
          mdCols: 4,
        },
        {
          name: "status",
          label: "Status",
          type: "select" as const,
          searchable: true,
          required: true,
          options: [
            { value: "active", label: "Active" },
            { value: "inactive", label: "Inactive" },
          ],
          cols: 12,
          mdCols: 4,
        },
        {
          name: "description",
          label: "Description",
          type: "rich-text" as const,
          placeholder: "Enter department description (optional)",
          description: "Brief description of the department's purpose and responsibilities",
          cols: 12,
          rows: 6,
        },
      ]
    }
  ];

  // Show loading skeleton while fetching department data
  if (departmentLoading && !department) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Edit Department"
          subtitle="Update department information"
          showAddButton={false}
          actions={
            <Button variant="outline" disabled>
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Departments
            </Button>
          }
        />

        <div className=" space-y-6">
          <div className="space-y-4">
            <div className="space-y-2">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-10 w-full" />
            </div>
            <div className="space-y-2">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-10 w-48" />
            </div>
            <div className="space-y-2">
              <Skeleton className="h-4 w-28" />
              <Skeleton className="h-24 w-full" />
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Show error if department not found
  if (!actionLoading && !department) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Department Not Found"
          subtitle="The requested department could not be found"
          showAddButton={false}
          actions={
            <Button variant="outline" onClick={handleCancel}>
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Departments
            </Button>
          }
        />

        <div className="text-center py-12">
          <p className="text-muted-foreground">
            The department you're looking for doesn't exist or has been deleted.
          </p>
        </div>
      </div>
    );
  }

  if (!department) {
    return null; // Prevent rendering with undefined
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Edit Department"
        subtitle={`Update information for "${department?.name}"`}
        showAddButton={false}
        actions={
          <Button
            variant="outline"
            onClick={handleCancel}
            disabled={isNavigating || loading}
          >
            <ArrowLeft className={`h-4 w-4 mr-2 ${isNavigating ? 'animate-spin' : ''}`} />
            {isNavigating ? 'Going back...' : 'Back to Departments'}
          </Button>
        }
      />

      <div>
        <GenericForm
          form={form}
          fields={formFields}
          onSubmit={handleSubmit}
          onCancel={handleCancel}
          loading={loading}
          submitText="Update Department"
          cancelText="Cancel"
        />
      </div>
    </div>
  );
}