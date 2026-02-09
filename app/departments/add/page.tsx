"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useDepartments } from "@/hooks/use-departments";
import PageHeader from "@/components/shared/page-header";
import GenericForm from "@/components/shared/generic-form";
import { Button } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useNavigationLoading } from "@/hooks/use-navigation-loading";
import { CreateDepartmentData, createDepartmentSchema } from '@/lib/validations/department'
import { handleAPIError } from "@/lib/utils/api-client";
import { useNavigation } from "@/components/providers/navigation-provider";


export default function AddDepartmentPage() {
  const router = useRouter();
  const { createDepartment } = useDepartments();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const { navigateTo } = useNavigation();

  const form = useForm<CreateDepartmentData>({
    resolver: zodResolver(createDepartmentSchema),
    defaultValues: {
      name: "",
      category: "it",
      description: "",
      status: "active",
    },
  });

  const handleSubmit = async (data: CreateDepartmentData) => {
    setLoading(true);
    try {
      const cleanedData: CreateDepartmentData = {
        ...data,
        description: data.description?.trim() || undefined,
      };
      // @ts-ignore
      await createDepartment(cleanedData);

      toast({
        title: "Success",
        description: "Department created successfully",
      });

      navigateTo("/departments");
    } catch (error: any) {
      handleAPIError(error, "Failed to create department")
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

  return (
    <div className="space-y-6">
      <PageHeader
        title="Add New Department"
        subtitle="Create a new department in your organization"
        showAddButton={false}
        actions={
          <Button
            variant="outline"
            onClick={handleCancel}
            disabled={isNavigating}
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
          submitText="Create Department"
          cancelText="Cancel"
        />
      </div>
    </div>
  );
}