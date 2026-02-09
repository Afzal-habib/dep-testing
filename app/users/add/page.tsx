"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useUsers } from "@/hooks/use-users";
import { handleAPIError } from "@/lib/utils/api-client";
import { parseAPIError } from "@/lib/utils/error-handler";
import PageHeader from "@/components/shared/page-header";
import GenericForm from "@/components/shared/generic-form";
import { Button } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useNavigationLoading } from "@/hooks/use-navigation-loading";
import { useDepartments } from "@/hooks/use-departments";
import { useRoles } from "@/hooks/use-roles";
import { createUserSchema, type CreateUserData } from "@/lib/validations/user";
import type { Role, Department } from "@/types";
import { useNavigation } from "@/components/providers/navigation-provider";

export default function AddUserPage() {
  const router = useRouter();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const { navigateTo } = useNavigation()

  const [fetchingRoles, setFetchingRoles] = useState(false);

  // Use users hook for CRUD operations
  const { createUser } = useUsers();

  // Department and role management
  const { departments, fetchDepartments, loading: departmentsLoading } = useDepartments();
  const { fetchRolesByDepartment, loading: rolesLoading } = useRoles();

  // Available roles based on selected department
  const [availableRoles, setAvailableRoles] = useState<Role[]>([]);
  const [selectedDepartment, setSelectedDepartment] = useState<string>("");

  // Use ref to track if departments are already being fetched
  const departmentsFetched = useRef(false);
  const currentDepartmentRef = useRef<string>("");

  const form = useForm<CreateUserData>({
    resolver: zodResolver(createUserSchema),
    defaultValues: {
      name: "",
      email: "",
      password: "",
      phone: "",
      role: "",
      department: "",
      position: "",
      status: "active",
      bio: "",
      // Address Information
      address: {
        street: "",
        city: "",
        state: "",
        zipCode: "",
        country: "",
      },
    },
  });

  // Load departments only once on mount
  useEffect(() => {
    if (!departmentsFetched.current) {
      departmentsFetched.current = true;
      fetchDepartments();
    }
  }, []); // Empty dependency array

  // Handle department change and fetch related roles
  const handleDepartmentChange = useCallback(async (departmentId: string) => {
    // Prevent duplicate calls
    if (departmentId === currentDepartmentRef.current || fetchingRoles) {
      return;
    }

    currentDepartmentRef.current = departmentId;
    setSelectedDepartment(departmentId);
    form.setValue("role", ""); // Reset role selection
    setAvailableRoles([]); // Clear previous roles

    if (!departmentId) {
      return;
    }

    setFetchingRoles(true);
    try {
      const departmentRole = await fetchRolesByDepartment(departmentId);
      if (departmentRole) {
        let roles = departmentRole;
        // Handle different response formats
        if (Array.isArray(roles)) {
          setAvailableRoles(roles);
        } else {
          console.error("Unexpected response format for roles:", roles);
          toast({
            title: "Error",
            description: "Failed to fetch roles for this department",
            variant: "destructive",
          });
          setAvailableRoles([]);
        }
      }
    } catch (error) {
      console.error("Error fetching roles:", error);
      toast({
        title: "Network Error",
        description: "Failed to connect to the server. Please try again.",
        variant: "destructive",
      });
      setAvailableRoles([]);
    } finally {
      setFetchingRoles(false);
    }
  }, [form, toast]);

  // Watch department field changes - Fixed to prevent infinite loops
  useEffect(() => {
    const subscription = form.watch((value, { name, type }) => {
      if (name === "department" && type === "change") {
        const newDepartmentId = value.department || "";
        if (newDepartmentId !== currentDepartmentRef.current) {
          handleDepartmentChange(newDepartmentId);
        }
      }
    });

    return () => subscription.unsubscribe();
  }, [form, handleDepartmentChange]);

  const handleSubmit = async (data: CreateUserData) => {
    setLoading(true);
    try {
      // Transform form data to API format with nested address structure
      const cleanedData: CreateUserData = {
        ...data,
        // Address
        address: data.address ? {
          street: data.address.street?.trim() || undefined,
          city: data.address.city?.trim() || undefined,
          state: data.address.state?.trim() || undefined,
          zipCode: data.address.zipCode?.trim() || undefined,
          country: data.address.country?.trim() || undefined,
        } : undefined,
      };
      
      console.log("Submitting user data: 131", cleanedData);
      await createUser(cleanedData);
      toast({
        title: "Success",
        description: "User created successfully",
      });
      navigateTo("/users");
    } catch (error: any) {
      const parsedError = parseAPIError(error);
      console.log('parsedError', error);
      if (parsedError.isValidationError && parsedError.validationErrors) {
        // Set field errors on the form
        parsedError.validationErrors.forEach((validationError: any) => {
          if (validationError.field) {
            form.setError(validationError.field, {
              type: 'manual',
              message: validationError.message
            });
          }
        });
        // Also show a general toast

        const current_api_error = error?.details?.validationErrors
        for (const err in current_api_error as [] || []) {
          toast({
            title: "Validation Error",
            description: current_api_error[err] || "Please correct the highlighted errors and try again.",
            variant: "destructive",
          });
        }
      } else {
        handleAPIError(error, 'Failed to create user');
      }
    } finally {
      setLoading(false);
    }
  };

  const { isNavigating, handleNavigation } = useNavigationLoading();

  const handleCancel = () => {
    handleNavigation("/users");
  };

  const formFields = [
    {
      subform_title: "Personal Information",
      fields: [
        {
          name: "name",
          label: "Full Name",
          type: "text" as const,
          required: true,
          placeholder: "Enter full name",
          cols: 12,
          mdCols: 6,
          lgCols: 6,
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
            { value: "suspended", label: "Suspended" },
          ],
          cols: 12,
          mdCols: 6,
          lgCols: 6,
        },
        {
          name: "email",
          label: "Email Address",
          type: "email" as const,
          required: true,
          placeholder: "Enter email address",
          cols: 12,
          mdCols: 6,
          lgCols: 6,
        },
        {
          name: "password",
          label: "Password",
          type: "password" as const,
          required: true,
          placeholder: "Enter password (min 8 chars with uppercase, lowercase, number)",
          cols: 12,
          mdCols: 6,
          lgCols: 6,
        },
      ]
    },
    
    {
      subform_title: "Role & Department",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "department",
          label: "Department",
          type: "select" as const,
          searchable: true,
          required: true,
          placeholder: "Select department first",
          loading: departmentsLoading,
          options: departments.map(dept => ({
            value: dept._id!,
            label: dept.name,
          })),
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "role",
          label: "Role",
          type: "select" as const,
          searchable: true,
          required: true,
          placeholder: selectedDepartment ? (fetchingRoles ? "Loading roles..." : "Select role") : "Select department first",
          disabled: !selectedDepartment || fetchingRoles,
          loading: fetchingRoles,
          options: availableRoles.map(role => ({
            value: role._id!,
            label: `${role.displayName} (Level ${role.hierarchyLevel})`,
          })),
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "position",
          label: "Position",
          type: "text" as const,
          placeholder: "Enter position/title",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "bio",
          label: "Bio",
          type: "rich-text" as const,
          placeholder: "Enter user bio (optional)",
          cols: 12,
          mdCols: 12,
          lgCols: 12,
        },
      ]
    },
    {
      subform_title: "Contact Information",
      collapse: true,
      defaultOpen: false,
      fields: [
        {
          name: "phone",
          label: "Phone Number",
          type: "text" as const,
          placeholder: "Enter phone number",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "address.street",
          label: "Street Address",
          type: "text" as const,
          placeholder: "Enter street address",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "address.city",
          label: "City",
          type: "text" as const,
          placeholder: "Enter city",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "address.state",
          label: "State/Province",
          type: "text" as const,
          placeholder: "Enter state or province",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "address.country",
          label: "Country",
          type: "text" as const,
          placeholder: "Enter country",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
        {
          name: "address.zipCode",
          label: "ZIP/Postal Code",
          type: "text" as const,
          placeholder: "Enter ZIP or postal code",
          cols: 12,
          mdCols: 6,
          lgCols: 4,
        },
      ]
    }
  ];

  return (
    <div>
      {/* Page Header */}
      <PageHeader
        title="Add New User"
        subtitle="Create a new user account with roles and permissions"
        showAddButton={false}
        actions={
          <Button
            variant="outline"
            onClick={handleCancel}
            disabled={isNavigating}
          >
            <ArrowLeft className={`h-4 w-4 mr-2 ${isNavigating ? 'animate-spin' : ''}`} />
            {isNavigating ? 'Going back...' : 'Back to Users'}
          </Button>
        }
      />

      {/* User Form */}
      <div>
        <GenericForm
          form={form}
          fields={formFields}
          onSubmit={handleSubmit}
          onCancel={handleCancel}
          loading={loading}
          submitText="Create User"
          cancelText="Cancel"
          gridCols={2}
        />
      </div>
    </div>
  );
}