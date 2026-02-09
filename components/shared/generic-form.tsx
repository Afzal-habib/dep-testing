"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import { createPortal } from "react-dom";
import { UseFormReturn } from "react-hook-form";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Plus, X } from "lucide-react";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { InlineLoader } from "../ui/loader";
import { cn } from "@/lib/utils";
import { Label } from "../ui/label";
import { Separator } from "@radix-ui/react-dropdown-menu";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@radix-ui/react-collapsible";
import { ChevronDown } from "lucide-react";
import RichTextEditor from "./rich-text-editor";

export interface FormFieldConfig {
  name: string;
  label: string;
  type: "text" | "email" | "url" | "password" | "number" | "textarea" | "rich-text" | "select" | "multi-select" | "checkbox" | "switch" | "date" | "array-input" | "array-object";
  placeholder?: string;
  description?: string;
  options?: { label: string; value: string | number }[];
  defaultValue?: string | number | boolean | string[]; // Default value for the field
  required?: boolean;
  disabled?: boolean;
  loading?: boolean; // Added loading state for async operations
  searchable?: boolean; // Enable search functionality for select fields
  className?: string;
  rows?: number; // for textarea
  cols?: number; // Grid columns out of 12 for mobile (default)
  smCols?: number; // Small screens (640px+)
  mdCols?: number; // Medium screens (768px+)
  lgCols?: number; // Large screens (1024px+)
  xlCols?: number; // Extra large screens (1280px+)
  fields?: FormFieldConfig[]; // Nested fields for array-object type
}

export interface SubFormConfig {
  subform_title?: string;
  fields: FormFieldConfig[];
  collapse?: boolean;
  defaultOpen?: boolean;
};

export interface GenericFormProps {
  form: UseFormReturn<any>;
  // fields: FormFieldConfig[];
  fields: SubFormConfig[];
  onSubmit: (data: any) => void;
  loading?: boolean;
  submitText?: string;
  cancelText?: string;
  onCancel?: () => void;
  className?: string;
  gridCols?: 1 | 2 | 3; // @deprecated - use individual field column configuration instead
  showCancel?: boolean;
  children?: React.ReactNode;
}

// SearchableSelect Component
interface SearchableSelectProps {
  options?: { label: string; value: string | number }[];
  value?: string;
  onValueChange: (value: string) => void;
  placeholder?: string;
  disabled?: boolean;
  loading?: boolean;
  defaultValue?: string;
  // When used inside the generic filter 'dropdown' presentation, set this so the portal receives attributes that prevent closing the parent filter
  inFilterDropdown?: boolean;
}

const SearchableSelect: React.FC<SearchableSelectProps> = ({
  options = [],
  value,
  onValueChange,
  placeholder = "Select an option",
  disabled = false,
  loading = false,
  defaultValue
  , inFilterDropdown = false
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [dropdownPosition, setDropdownPosition] = useState<'bottom' | 'top'>('bottom');
  const containerRef = useRef<HTMLDivElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const filteredOptions = options.filter(option =>
    option.label.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const selectedOption = options.find(option => String(option.value) === (value === '__$EMPTY$__' ? '' : value));

  const handleSelect = (optionValue: string) => {
    // Map sentinel back to empty string for consumers that expect ''
    if (optionValue === '__$EMPTY$__') {
      onValueChange('');
    } else {
      onValueChange(optionValue);
    }
    setIsOpen(false);
    setSearchQuery("");
  };

  const calculatePosition = () => {
    if (!containerRef.current) return;

    const rect = containerRef.current.getBoundingClientRect();
    const dropdownHeight = 300; // Approximate max height
    const spaceBelow = window.innerHeight - rect.bottom;
    const spaceAbove = rect.top;

    // Use bottom if there's enough space, otherwise use top if there's more space above
    setDropdownPosition(spaceBelow >= dropdownHeight || spaceBelow >= spaceAbove ? 'bottom' : 'top');
  };

  const handleToggle = () => {
    if (!isOpen) {
      calculatePosition();
    }
    setIsOpen(!isOpen);
  };

  // Handle outside clicks, escape key, and scroll events
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        containerRef.current &&
        !containerRef.current.contains(event.target as Node) &&
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false);
        setSearchQuery("");
      }
    };

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsOpen(false);
        setSearchQuery("");
      }
    };

    const handleScroll = () => {
      if (isOpen && containerRef.current) {
        calculatePosition();
      }
    };

    const handleResize = () => {
      if (isOpen) {
        setIsOpen(false);
        setSearchQuery("");
      }
    };

    if (isOpen) {
      document.addEventListener("mousedown", handleClickOutside);
      document.addEventListener("keydown", handleEscape);
      window.addEventListener("scroll", handleScroll, true);
      window.addEventListener("resize", handleResize);
    }

    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleEscape);
      window.removeEventListener("scroll", handleScroll, true);
      window.removeEventListener("resize", handleResize);
    };
  }, [isOpen]);

  const renderDropdown = () => {
    if (!isOpen || !containerRef.current) return null;

    const rect = containerRef.current.getBoundingClientRect();
    const dropdownStyle: React.CSSProperties = {
      position: 'fixed',
      left: rect.left,
      width: rect.width,
      zIndex: 999999,
      ...(dropdownPosition === 'bottom'
        ? { top: rect.bottom + 4 }
        : { bottom: window.innerHeight - rect.top + 4 }
      )
    };

    return createPortal(
      <div
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: 999999,
          pointerEvents: 'none'
        }}
        data-filter-portal={inFilterDropdown ? 'true' : undefined}
      >
        {/* Backdrop */}
        <div
          className="fixed inset-0"
          style={{
            zIndex: 999998,
            pointerEvents: 'auto'
          }}
          onClick={() => setIsOpen(false)}
        />
        {/* Dropdown */}
        <div
          ref={dropdownRef}
          className={cn("rounded-md border border-border bg-background text-foreground shadow-xl", inFilterDropdown ? 'z-[999999]' : '')}
          style={{
            ...dropdownStyle,
            pointerEvents: 'auto',
            zIndex: 999999
          }}
        >
          <div className="p-2">
            <Input
              placeholder="Search options..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-8"
              autoFocus
            />
          </div>
          <div className="max-h-60 overflow-y-auto">
            {loading ? (
              <div className="flex items-center justify-center p-4">
                <InlineLoader size="sm" />
                <span className="ml-2 text-sm text-muted-foreground">Loading options...</span>
              </div>
            ) : filteredOptions.length > 0 ? (
              filteredOptions.map((option) => {
                const displayValue = String(option.value) === '' ? '__$EMPTY$__' : String(option.value);
                return (
                  <div
                    key={displayValue}
                    className={cn(
                      "cursor-pointer px-3 py-2 text-sm hover:bg-accent hover:text-accent-foreground",
                      displayValue === value && "bg-accent text-accent-foreground"
                    )}
                    onClick={() => handleSelect(displayValue)}
                  >
                    {option.label}
                  </div>
                );
              })
            ) : (
              <div className="p-4 text-center text-sm text-muted-foreground">
                No options found
              </div>
            )}
          </div>
        </div>
      </div>,
      document.body
    );
  };

  return (
    <div className="relative" ref={containerRef}>
      <Button
        type="button"
        variant="outline"
        role="combobox"
        aria-expanded={isOpen}
        className="w-full justify-between text-left"
        disabled={disabled}
        onClick={handleToggle}
      >
        <span className="truncate flex-1 text-left">
          {selectedOption?.label || placeholder}
        </span>
        <svg
          className={cn("ml-2 h-4 w-4 shrink-0 opacity-50 transition-transform", isOpen && "rotate-180")}
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <polyline points="6,9 12,15 18,9"></polyline>
        </svg>
      </Button>

      {renderDropdown()}
    </div>
  );
};

const GenericForm: React.FC<GenericFormProps> = ({
  form,
  fields,
  onSubmit,
  loading = false,
  submitText = "Submit",
  cancelText = "Cancel",
  onCancel,
  className,
  gridCols = 1, // @deprecated - keeping for backward compatibility
  showCancel = true,
}) => {
  const gridClasses = {
    1: "grid-cols-1",
    2: "grid-cols-1 md:grid-cols-2",
    3: "grid-cols-1 md:grid-cols-2 lg:grid-cols-3",
  };

  // State for collapsible sections - use defaultOpen or true by default
  const [openSections, setOpenSections] = useState<boolean[]>(
    fields.map(field => field.defaultOpen !== false)
  );

  // State for array input new items
  const [arrayInputs, setArrayInputs] = useState<Record<string, string>>({});

  const toggleSection = (index: number) => {
    setOpenSections(prev => prev.map((open, i) => i === index ? !open : open));
  };

  // Array input handlers
  const addArrayItem = (fieldName: string) => {
    const newItem = arrayInputs[fieldName]?.trim();
    if (newItem) {
      const current = form.getValues(fieldName) || [];
      form.setValue(fieldName, [...current, newItem]);
      setArrayInputs(prev => ({ ...prev, [fieldName]: '' }));
    }
  };

  const removeArrayItem = (fieldName: string, item: string) => {
    const current = form.getValues(fieldName) || [];
    form.setValue(fieldName, current.filter((i: string) => i !== item));
  };

  const handleArrayInputChange = (fieldName: string, value: string) => {
    setArrayInputs(prev => ({ ...prev, [fieldName]: value }));
  };

  const handleArrayInputKeyPress = (fieldName: string, e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addArrayItem(fieldName);
    }
  };

  // Array-object handlers
  const addArrayObjectItem = (fieldName: string, fields: FormFieldConfig[]) => {
    const current = form.getValues(fieldName) || [];
    const newItem: Record<string, any> = {};

    // Initialize with default values based on field types
    fields.forEach(field => {
      switch (field.type) {
        case 'select':
          newItem[field.name] = field.defaultValue || (field.options?.[0]?.value) || '';
          break;
        case 'number':
          newItem[field.name] = field.defaultValue || 0;
          break;
        case 'checkbox':
          newItem[field.name] = field.defaultValue || false;
          break;
        default:
          newItem[field.name] = field.defaultValue || '';
      }
    });

    form.setValue(fieldName, [...current, newItem], {
      shouldDirty: true,
      shouldValidate: true,
      shouldTouch: true
    });
  };

  const removeArrayObjectItem = (fieldName: string, index: number) => {
    const current = form.getValues(fieldName) || [];
    const updated = current.filter((_: any, i: number) => i !== index);
    form.setValue(fieldName, updated, {
      shouldDirty: true,
      shouldValidate: true,
      shouldTouch: true
    });
  };

  const updateArrayObjectItem = (fieldName: string, index: number, itemFieldName: string, value: any) => {
    const current = form.getValues(fieldName) || [];
    const updatedItems = [...current];
    if (updatedItems[index]) {
      updatedItems[index] = { ...updatedItems[index], [itemFieldName]: value };
      form.setValue(fieldName, updatedItems, {
        shouldDirty: true,
        shouldValidate: true,
        shouldTouch: true
      });
    }
  };

  const renderField = (field: FormFieldConfig) => {
    // Build responsive column classes
    const cols = field.cols || 12; // Default to full width on mobile
    const smCols = field.smCols;
    const mdCols = field.mdCols;
    const lgCols = field.lgCols;
    const xlCols = field.xlCols;

    const colClasses = [
      `col-span-${Math.min(12, Math.max(1, cols))}`, // Base mobile class
      smCols && `sm:col-span-${Math.min(12, Math.max(1, smCols))}`,
      mdCols && `md:col-span-${Math.min(12, Math.max(1, mdCols))}`,
      lgCols && `lg:col-span-${Math.min(12, Math.max(1, lgCols))}`,
      xlCols && `xl:col-span-${Math.min(12, Math.max(1, xlCols))}`,
    ].filter(Boolean).join(' ');

    return (
      <FormField
        key={field.name}
        control={form.control}
        name={field.name}
        render={({ field: formField }) => (
          <FormItem className={cn(colClasses, field.className)}>
            {field.type !== "array-object" && (
              <FormLabel className={field.required ? "after:content-['*'] after:ml-0.5 after:text-destructive" : ""}>
                {field.label}
              </FormLabel>
            )}
            <FormControl>
              {(() => {
                switch (field.type) {
                  case "textarea":
                    return (
                      <Textarea
                        placeholder={field.placeholder}
                        disabled={field.disabled || loading}
                        rows={field.rows || 3}
                        defaultValue={field.defaultValue ? String(field.defaultValue) : undefined}
                        {...formField}
                      />
                    );

                  case "rich-text":
                    return (
                      <RichTextEditor
                        value={formField.value || ''}
                        onChange={formField.onChange}
                        placeholder={field.placeholder}
                        disabled={field.disabled || loading}
                        height={field.rows ? `${field.rows * 30}px` : '150px'}
                      />
                    );

                  case "select":
                    return field.searchable ? (
                      <SearchableSelect
                        options={field.options}
                        value={(formField.value === '' ? '__$EMPTY$__' : formField.value) || (field.defaultValue === '' ? '__$EMPTY$__' : (field.defaultValue ? String(field.defaultValue) : undefined))}
                        onValueChange={(val) => {
                          if (val === '__$EMPTY$__') formField.onChange(''); else formField.onChange(val);
                        }}
                        placeholder={field.placeholder || "Select an option"}
                        disabled={field.disabled || loading || field.loading}
                        loading={field.loading}
                        defaultValue={(field.defaultValue === '' ? '__$EMPTY$__' : (field.defaultValue ? String(field.defaultValue) : undefined))}
                      />
                    ) : (
                      <Select
                        onValueChange={(val) => {
                          // Map our internal empty sentinel back to an empty string to
                          // maintain backward compatibility where code uses '' to indicate 'no selection' or 'all'.
                          if (val === '__$EMPTY$__') {
                            formField.onChange('');
                          } else {
                            formField.onChange(val);
                          }
                        }}
                        value={(formField.value === '' ? '__$EMPTY$__' : formField.value) || (field.defaultValue === '' ? '__$EMPTY$__' : (field.defaultValue ? String(field.defaultValue) : undefined))}
                        disabled={field.disabled || loading || field.loading}
                        defaultValue={(field.defaultValue === '' ? '__$EMPTY$__' : (field.defaultValue ? String(field.defaultValue) : undefined))}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder={field.placeholder || "Select an option"} />
                          {field.loading && <InlineLoader size="sm" className="ml-2" />}
                        </SelectTrigger>
                        <SelectContent>
                          {field.loading ? (
                            <div className="flex items-center justify-center p-2">
                              <InlineLoader size="sm" />
                              <span className="ml-2 text-sm text-muted-foreground">Loading options...</span>
                            </div>
                          ) : (
                            field.options?.map((option) => {
                              const displayValue = String(option.value) === '' ? '__$EMPTY$__' : String(option.value);
                              return (
                                <SelectItem key={displayValue} value={displayValue}>
                                  {option.label}
                                </SelectItem>
                              );
                            })
                          )}
                        </SelectContent>
                      </Select>
                    );

                  case "multi-select":
                    return (
                      <div className="space-y-2">
                        <Label className="text-sm font-medium">{field.label}</Label>
                        {field.options?.map((option) => (
                          <div key={option.value} className="flex items-center space-x-2">
                            <Checkbox
                              checked={(formField.value || field.defaultValue || []).includes(String(option.value))}
                              onCheckedChange={(checked) => {
                                const currentValue = formField.value || field.defaultValue || [];
                                if (checked) {
                                  formField.onChange([...currentValue, String(option.value)]);
                                } else {
                                  formField.onChange(currentValue.filter((v: string) => v !== String(option.value)));
                                }
                              }}
                              disabled={field.disabled || loading}
                            />
                            <label className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">
                              {option.label}
                            </label>
                          </div>
                        ))}
                      </div>
                    );

                  case "switch":
                    return (
                      <div className="flex items-center space-x-2">
                        <Switch
                          checked={formField.value}
                          onCheckedChange={formField.onChange}
                          disabled={field.disabled || loading}
                        />
                        <label className="text-sm font-medium">
                          {field.description || field.label}
                        </label>
                      </div>
                    );

                  case "date":
                    return (
                      <Input
                        type="date"
                        disabled={field.disabled || loading}
                        {...formField}
                        style={{display:'block'}}
                      />
                    );

                  case "array-input":
                    return (
                      <div className="space-y-2">
                        <div className="flex gap-2">
                          <Input
                            value={arrayInputs[field.name] || ''}
                            onChange={(e) => handleArrayInputChange(field.name, e.target.value)}
                            placeholder={field.placeholder || `Add ${field.label.toLowerCase()}...`}
                            disabled={field.disabled || loading}
                            onKeyPress={(e) => handleArrayInputKeyPress(field.name, e)}
                          />
                          <Button
                            type="button"
                            onClick={() => addArrayItem(field.name)}
                            size="sm"
                            disabled={field.disabled || loading || !arrayInputs[field.name]?.trim()}
                          >
                            <Plus className="h-4 w-4" />
                          </Button>
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {(form.watch(field.name) || []).map((item: string, index: number) => (
                            <Badge key={index} variant="secondary" className="flex items-center gap-1">
                              {item}
                              <button
                                type="button"
                                onClick={() => removeArrayItem(field.name, item)}
                                className="ml-1 hover:bg-red-100 rounded-full p-0.5"
                                disabled={field.disabled || loading}
                              >
                                <X className="h-3 w-3" />
                              </button>
                            </Badge>
                          ))}
                        </div>
                      </div>
                    );

                  case "array-object":
                    return (
                      <div className="space-y-4">
                        <div className="flex justify-between items-center">
                          <span className="text-sm font-medium">{field.label}</span>
                          <Button
                            type="button"
                            onClick={() => addArrayObjectItem(field.name, field.fields || [])}
                            size="sm"
                            disabled={field.disabled || loading}
                          >
                            <Plus className="h-4 w-4 mr-2" />
                            Add {field.label.slice(0, -1) || 'Item'}
                          </Button>
                        </div>

                        <div className="space-y-4">
                          {(form.watch(field.name) || []).map((item: any, index: number) => (
                            <div key={index} className="border rounded-lg p-4 space-y-4 relative">
                              <div className="absolute top-2 right-2">
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => removeArrayObjectItem(field.name, index)}
                                  disabled={field.disabled || loading}
                                  className="h-8 w-8 p-0 hover:bg-red-50 hover:text-red-600"
                                >
                                  <X className="h-4 w-4" />
                                </Button>
                              </div>

                              <div className="grid grid-cols-12 gap-3">
                                {(field.fields || []).map((subField) => {
                                  // Build responsive column classes for sub-fields
                                  const cols = subField.cols || 12;
                                  const smCols = subField.smCols;
                                  const mdCols = subField.mdCols;
                                  const lgCols = subField.lgCols;
                                  const xlCols = subField.xlCols;

                                  const colClasses = [
                                    `col-span-${Math.min(12, Math.max(1, cols))}`,
                                    smCols && `sm:col-span-${Math.min(12, Math.max(1, smCols))}`,
                                    mdCols && `md:col-span-${Math.min(12, Math.max(1, mdCols))}`,
                                    lgCols && `lg:col-span-${Math.min(12, Math.max(1, lgCols))}`,
                                    xlCols && `xl:col-span-${Math.min(12, Math.max(1, xlCols))}`,
                                  ].filter(Boolean).join(' ');

                                  return (
                                    <div key={subField.name} className={cn("space-y-2", colClasses)}>
                                      <Label className={subField.required ? "after:content-['*'] after:ml-0.5 after:text-destructive" : ""}>
                                        {subField.label}
                                      </Label>

                                      {subField.type === 'select' ? (
                                        <Select
                                          value={item[subField.name] || ''}
                                          onValueChange={(value) => updateArrayObjectItem(field.name, index, subField.name, value)}
                                          disabled={subField.disabled || loading}
                                        >
                                          <SelectTrigger>
                                            <SelectValue placeholder={subField.placeholder || `Select ${subField.label.toLowerCase()}`} />
                                          </SelectTrigger>
                                          <SelectContent>
                                            {(subField.options || []).map((option) => (
                                              <SelectItem key={option.value} value={String(option.value)}>
                                                {option.label}
                                              </SelectItem>
                                            ))}
                                          </SelectContent>
                                        </Select>
                                      ) : subField.type === 'date' ? (
                                        <Input
                                          type="date"
                                          value={item[subField.name] || ''}
                                          onChange={(e) => updateArrayObjectItem(field.name, index, subField.name, e.target.value)}
                                          disabled={subField.disabled || loading}
                                          style={{display:'block'}}
                                        />
                                      ) : subField.type === 'number' ? (
                                        <Input
                                          type="number"
                                          value={item[subField.name] || ''}
                                          onChange={(e) => updateArrayObjectItem(field.name, index, subField.name, parseFloat(e.target.value) || 0)}
                                          placeholder={subField.placeholder}
                                          disabled={subField.disabled || loading}
                                        />
                                      ) : subField.type === 'textarea' ? (
                                        <Textarea
                                          value={item[subField.name] || ''}
                                          onChange={(e) => updateArrayObjectItem(field.name, index, subField.name, e.target.value)}
                                          placeholder={subField.placeholder}
                                          disabled={subField.disabled || loading}
                                          rows={subField.rows || 3}
                                        />
                                      ) : (
                                        <Input
                                          type="text"
                                          value={item[subField.name] || ''}
                                          onChange={(e) => updateArrayObjectItem(field.name, index, subField.name, e.target.value)}
                                          placeholder={subField.placeholder}
                                          disabled={subField.disabled || loading}
                                        />
                                      )}

                                      {subField.description && (
                                        <p className="text-xs text-muted-foreground">{subField.description}</p>
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                          ))}

                          {(form.watch(field.name) || []).length === 0 && (
                            <div className="text-center py-8 text-muted-foreground">
                              No {field.label.toLowerCase()} added yet. Click the button above to add one.
                            </div>
                          )}
                        </div>
                      </div>
                    );

                  default:
                    return (
                      <Input
                        type={field.type}
                        placeholder={field.placeholder}
                        disabled={field.disabled || loading}
                        defaultValue={field.defaultValue ? String(field.defaultValue) : undefined}
                        {...formField}
                        autoComplete={field.type === "email" || field.type === "password" ? "new-password" : "off"}
                      />
                    );
                }
              })()}
            </FormControl>
            {field.description && field.type !== "checkbox" && field.type !== "switch" && (
              <p className="text-xs text-muted-foreground">{field.description}</p>
            )}
            <FormMessage />
          </FormItem>
        )}
      />
    );
  };

  const { formState } = form;
  const { isSubmitting } = formState;

  // Wrap submit with trigger() to ensure validation runs and prevents submission
  // in case handleSubmit is bypassed or misbehaving in some contexts.
  const submitHandler = useCallback(async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    // Explicitly trigger validation for all fields
    const isValid = await form.trigger();
    if (!isValid) {
      // If there are validation errors, focus the first invalid field
      const firstError = Object.keys(form.formState.errors)[0];
      if (firstError) {
        try {
          form.setFocus(firstError as any);
        } catch (err) {
          // ignore focus errors
        }
      }
      return;
    }

    // Now call onSubmit directly with the form data
    const data = form.getValues();
    onSubmit(data);
  }, [form, onSubmit]);

  return (
    <Form {...form}>
      <form onSubmit={submitHandler} className={cn("space-y-3", className)}>
        {/* Check if any field has custom column configuration */}
        {fields.flatMap((subform) => subform.fields).some(field => field.cols || field.smCols || field.mdCols || field.lgCols || field.xlCols) ? (
          // Use 12-column grid when fields have custom column configuration
          <div className="w-full">
            {
              fields.map((field, index) => (
                <div key={index} className="grid grid-cols-12 gap-3">
                  {field.subform_title && (
                    <div className="col-span-12">
                      {field.collapse ? (
                        <Collapsible open={openSections[index]} onOpenChange={() => toggleSection(index)}>
                          <CollapsibleTrigger asChild>
                            <button
                              type="button"
                              className={cn(
                                "flex items-center justify-between w-full px-4 py-2 text-left bg-gradient-to-r from-card to-card/50 border border-border/50 rounded-tl-md rounded-tr-md shadow-sm hover:shadow-lg hover:border-primary/30  transition-all duration-300 ease-in-out group backdrop-blur-sm",
                                openSections[index] ? "border-primary/40 shadow-md" : ""
                              )}
                            >
                              <div className="flex items-center gap-4">
                                <div className={cn(
                                  "flex-shrink-0 w-3 h-3 rounded-full transition-all duration-300 shadow-sm",
                                  openSections[index] ? "bg-primary shadow-primary/50 scale-110" : "bg-muted-foreground/60 shadow-muted-foreground/30"
                                )} />
                                <div className="flex flex-col">
                                  <Label className="font-semibold text-lg text-foreground group-hover:text-primary transition-colors duration-200">
                                    {field.subform_title}
                                  </Label>
                                  <span className="text-sm text-muted-foreground group-hover:text-primary/70 transition-colors duration-200">
                                    {openSections[index] ? "Click to collapse" : "Click to expand"}
                                  </span>
                                </div>
                              </div>
                              <div className="flex items-center gap-2">
                                <div className={cn(
                                  "flex items-center justify-center w-8 h-8 rounded-full transition-all duration-300",
                                  openSections[index] ? "bg-primary/20 rotate-180" : "bg-muted/50"
                                )}>
                                  <ChevronDown className={cn(
                                    "h-4 w-4 transition-all duration-300 group-hover:scale-110",
                                    openSections[index] ? "text-primary rotate-180" : "text-muted-foreground group-hover:text-primary"
                                  )} />
                                </div>
                              </div>
                            </button>
                          </CollapsibleTrigger>
                          <CollapsibleContent className="overflow-hidden data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down">
                            <div className="p-4 bg-card/30 border border-border/30 rounded-bl-md rounded-br-md backdrop-blur-sm">
                              <div className="grid grid-cols-12 gap-3">
                                {field.fields.map(renderField)}
                              </div>
                            </div>
                          </CollapsibleContent>
                        </Collapsible>
                      ) : (
                        <div className="flex items-center gap-4 py-2 border-b">
                          <div className="flex flex-col">
                            <Label className="font-semibold text-lg text-foreground">{field.subform_title}</Label>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                  {!field.collapse && field.fields.map(renderField)}
                  {field.subform_title && !field.collapse && (
                    <div className="col-span-12 border-b my-6" />
                  )}
                  {field.collapse && (
                    <div className="col-span-12 mb-1" />
                  )}
                </div>
              ))
            }
          </div>
        ) : (
          // Fallback to old grid system for backward compatibility
          <div className={cn("grid gap-3", gridClasses[gridCols])}>
            {
              fields.map((field, index) => (
                <div key={index} className="col-span-12">
                  {field.subform_title && (
                    field.collapse ? (
                      <Collapsible open={openSections[index]} onOpenChange={() => toggleSection(index)}>
                        <CollapsibleTrigger asChild>
                          <button
                            type="button"
                            className={cn(
                              "flex items-center justify-between w-full px-6 py-4 text-left bg-gradient-to-r from-card to-card/50 border border-border/50 rounded-md shadow-sm hover:shadow-lg hover:border-primary/30 hover:from-primary/5 hover:to-primary/10 transition-all duration-300 ease-in-out group backdrop-blur-sm mb-4",
                              openSections[index] ? "shadow-md" : ""
                            )}
                          >
                            <div className="flex items-center gap-4">
                              <div className={cn(
                                "flex-shrink-0 w-3 h-3 rounded-full transition-all duration-300 shadow-sm",
                                openSections[index] ? "bg-primary shadow-primary/50 scale-110" : "bg-muted-foreground/60 shadow-muted-foreground/30"
                              )} />
                              <div className="flex flex-col">
                                <Label className="font-semibold text-lg">
                                  {field.subform_title}
                                </Label>
                                <span className="text-sm text-muted-foreground group-hover:text-primary/70 transition-colors duration-200">
                                  {openSections[index] ? "Click to collapse" : "Click to expand"}
                                </span>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <div className={cn(
                                "flex items-center justify-center w-8 h-8 rounded-full transition-all duration-300",
                                openSections[index] ? "bg-primary/20 rotate-180" : "bg-muted/50"
                              )}>
                                <ChevronDown className={cn(
                                  "h-4 w-4 transition-all duration-300 group-hover:scale-110",
                                  openSections[index] ? "text-primary rotate-180" : "text-muted-foreground group-hover:text-primary"
                                )} />
                              </div>
                            </div>
                          </button>
                        </CollapsibleTrigger>
                        <CollapsibleContent className="overflow-hidden data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down">
                          <div className="mt-2 p-6 bg-card/30 border border-border/30 rounded-md backdrop-blur-sm mb-6">
                            <div className="space-y-4">
                              {field.fields.map(renderField)}
                            </div>
                          </div>
                        </CollapsibleContent>
                      </Collapsible>
                    ) : (
                      <div className="flex items-center gap-4 px-6 py-4 shadow-sm mb-4">
                        <div className="flex-shrink-0 w-3 h-3 rounded-full bg-primary shadow-primary/50" />
                        <div className="flex flex-col">
                          <Label className="font-semibold text-lg text-foreground">{field.subform_title}</Label>
                        </div>
                      </div>
                    )
                  )}
                  {!field.collapse && field.fields.map(renderField)}
                  {field.subform_title && !field.collapse && <Separator className="my-6" />}
                  {field.collapse && <div className="mb-6" />}
                </div>
              ))
            }
          </div>
        )}

        {/* {children} */}

        <div className="flex items-center justify-end gap-3">
          {showCancel && onCancel && (
            <Button
              type="button"
              variant="outline"
              onClick={onCancel}
              disabled={loading}
            >
              {cancelText}
            </Button>
          )}
          <Button type="submit" disabled={loading || isSubmitting}>
            {loading && <InlineLoader className="mr-2" />}
            {submitText}
          </Button>
        </div>
      </form>
    </Form >
  );
};

export default GenericForm;
export { SearchableSelect };