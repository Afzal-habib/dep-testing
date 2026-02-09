"use client";

import React, { useState, useEffect, useRef } from "react";
import { createPortal } from 'react-dom'
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Card, CardContent } from "@/components/ui/card";
import { Filter, X, Search } from "lucide-react";
import { cn } from "@/lib/utils";
import { SearchableSelect } from "./generic-form";

export interface FilterField {
  key: string;
  label: string;
  type: 'text' | 'select' | 'date' | 'number';
  placeholder?: string;
  options?: { value: string; label: string }[];
  cols?: number;
  smCols?: number;
  mdCols?: number;
  lgCols?: number;
  xlCols?: number;
  searchable?: boolean;
}

export interface FilterConfig {
  fields: FilterField[];
  defaultValues?: Record<string, any>;
}

interface GenericFilterProps {
  config: FilterConfig;
  values: Record<string, any>; // These are the applied filters
  onFilterChange: (filters: Record<string, any>) => void; // Called when Search button is clicked
  onReset?: () => void;
  className?: string;
  collapsible?: boolean;
  title?: string;
  loading?: boolean;
  clearText?: string;
  presentation?: 'inline' | 'dropdown';
  isOpen?: boolean;
  onOpenChange?: (open: boolean) => void;
  anchorRef?: React.RefObject<HTMLElement | null>;
}

const GenericFilter: React.FC<GenericFilterProps> = ({
  config,
  values: appliedFilters, // Rename for clarity
  onFilterChange,
  onReset,
  className,
  collapsible = true,
  title = "Filters",
  loading = false,
  clearText = "Clear Filters",
  presentation = 'inline',
  isOpen: controlledIsOpen,
  onOpenChange,
  anchorRef,
}) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const dropdownRef = useRef<HTMLDivElement | null>(null)
  const [positionStyle, setPositionStyle] = useState<React.CSSProperties | null>(null)

  // Local state for form values (not applied until Search is clicked)
  const [formValues, setFormValues] = useState<Record<string, any>>(
    appliedFilters || config.defaultValues || {}
  );

  // Keep local form state in sync with external applied filters
  React.useEffect(() => {
    setFormValues(appliedFilters || config.defaultValues || {});
  }, [appliedFilters, config.defaultValues]);

  const handleFieldChange = (key: string, value: any) => {
    setFormValues(prev => ({ ...prev, [key]: value }));
  };

  const handleSearch = () => {
    // Apply the filters by calling onFilterChange with current form values
    onFilterChange(formValues);
    // Close panel if collapsible
    if (collapsible) setIsExpanded(false);
    if (presentation === 'dropdown') onOpenChange?.(false)
  };

  const handleReset = () => {
    const resetValues = config.defaultValues || {};
    setFormValues(resetValues);
    onFilterChange(resetValues);
    if (onReset) onReset();
    if (collapsible) setIsExpanded(false);
    if (presentation === 'dropdown') onOpenChange?.(false)
  };

  // Check if there are active applied filters (for badges)
  const hasActiveFilters = Object.values(appliedFilters).some(value =>
    value !== '' && value !== null && value !== undefined && value !== 'all'
  );

  // Check if form has been modified from applied filters
  const hasChanges = JSON.stringify(formValues) !== JSON.stringify(appliedFilters);

  // Active filter count for badges
  // const activeCount = Object.values(appliedFilters).filter(v => v && v !== 'all').length;
  const activeCount = Object.values(appliedFilters).filter(v => v && v !== 'all').length;

  const open = typeof controlledIsOpen === 'boolean' ? controlledIsOpen : isExpanded

  useEffect(() => {
    if (presentation !== 'dropdown' || !open) return
    const handleDocDown = (e: MouseEvent) => {
      const target = e.target as Node
      // If the click is inside the rendered dropdown ui, ignore
      if (dropdownRef.current && dropdownRef.current.contains(target)) return
      // If the click is inside the anchor button, ignore
      if (anchorRef?.current && anchorRef.current.contains(target)) return
      // If the click is inside any portal that is marked as part of this filter dropdown (e.g., SelectContent or SearchableSelect portal), ignore
      if ((target as Element).closest && (target as Element).closest('[data-filter-portal]')) return
      onOpenChange?.(false)
    }
    const handleEsc = (e: KeyboardEvent) => { if (e.key === 'Escape') onOpenChange?.(false) }
    document.addEventListener('mousedown', handleDocDown)
    document.addEventListener('keydown', handleEsc)

    // Position computation
    const computePosition = () => {
      const dropdownEl = dropdownRef.current
      const anchorEl = anchorRef?.current
      const margin = 12
      const viewportW = window.innerWidth
      const viewportH = window.innerHeight
      // Default dims
      let width = 420
      if (anchorEl) width = Math.max(320, Math.min(720, Math.max(anchorEl.getBoundingClientRect().width, 420)))
      // Constrain width to viewport
      width = Math.min(width, viewportW - margin * 2)

      // start with anchor left
      let left = anchorEl ? anchorEl.getBoundingClientRect().left : margin
      // If this causes overflow to the right, try aligning to anchor right
      if (left + width > viewportW - margin) {
        left = anchorEl ? anchorEl.getBoundingClientRect().right - width : viewportW - margin - width
      }
      // prevent going off the left edge
      if (left < margin) left = margin

      // Vertical: prefer below anchor, otherwise above
      let top = anchorEl ? anchorEl.getBoundingClientRect().bottom + 8 : 64
      let height = dropdownEl ? dropdownEl.getBoundingClientRect().height : 360
      if (top + height > viewportH - margin) {
        // place above
        top = anchorEl ? anchorEl.getBoundingClientRect().top - height - 8 : Math.max(margin, viewportH - margin - height)
        if (top < margin) top = margin
      }

      setPositionStyle({ left, top, width })
    }

    computePosition()
    window.addEventListener('resize', computePosition)
    window.addEventListener('scroll', computePosition, { capture: true })
    return () => {
      document.removeEventListener('mousedown', handleDocDown)
      document.removeEventListener('keydown', handleEsc)
      window.removeEventListener('resize', computePosition)
      window.removeEventListener('scroll', computePosition, { capture: true })
    }
  }, [presentation, open, dropdownRef, anchorRef, onOpenChange])

  const baseToggleClasses = (extra?: string) => cn(
    "flex items-center gap-2 transition-all duration-200",
    "border-border hover:bg-accent hover:text-accent-foreground",
    hasActiveFilters && "border-primary text-primary hover:border-primary/80",
    extra
  );

  const renderField = (field: FilterField) => {
    const cols = field.cols || 12;
    const smCols = field.smCols;
    const mdCols = field.mdCols;
    const lgCols = field.lgCols;
    const xlCols = field.xlCols;

    const colClasses = [
      `col-span-${Math.min(12, Math.max(1, cols))}`,
      smCols && `sm:col-span-${Math.min(12, Math.max(1, smCols))}`,
      mdCols && `md:col-span-${Math.min(12, Math.max(1, mdCols))}`,
      lgCols && `lg:col-span-${Math.min(12, Math.max(1, lgCols))}`,
      xlCols && `xl:col-span-${Math.min(12, Math.max(1, xlCols))}`,
    ].filter(Boolean).join(' ');

    switch (field.type) {
      case 'text':
        return (
          <div key={field.key} className={cn("space-y-2", colClasses)}>
            <Label htmlFor={field.key} className="text-sm font-medium text-foreground">
              {field.label}
            </Label>
            <div className="relative">
              <Input
                id={field.key}
                type="text"
                placeholder={field.placeholder || `Enter ${field.label.toLowerCase()}`}
                value={formValues[field.key] || ''}
                onChange={(e) => handleFieldChange(field.key, e.target.value)}
                className="bg-background border-border focus:ring-primary pr-8"
              />
              {field.key === 'search' && (
                <Search className="absolute right-2 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              )}
            </div>
          </div>
        );

      case 'select':
        return (
          <div key={field.key} className={cn("space-y-2", colClasses)}>
            <Label htmlFor={field.key} className="text-sm font-medium text-foreground">
              {field.label}
            </Label>
            {field.searchable ? (
              <SearchableSelect
                value={formValues[field.key] || ''}
                onValueChange={(value) => handleFieldChange(field.key, value)}
                options={field.options || []}
                placeholder={field.placeholder || `Select ${field.label.toLowerCase()}`}
                disabled={loading}
                loading={false}
                inFilterDropdown={presentation === 'dropdown'}
              />
            ) : (
              <Select
                value={String(formValues[field.key] || '')}
                onValueChange={(value) => handleFieldChange(field.key, value)}
              >
                <SelectTrigger className="bg-background border-border">
                  <SelectValue placeholder={field.placeholder || `Select ${field.label.toLowerCase()}`} />
                </SelectTrigger>
                <SelectContent data-filter-portal={presentation === 'dropdown' ? 'true' : undefined} className={presentation === 'dropdown' ? 'z-[999999]' : ''}>
                  {field.options?.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>
        );

      case 'date':
        return (
          <div key={field.key} className={cn("space-y-2", colClasses)}>
            <Label htmlFor={field.key} className="text-sm font-medium text-foreground">
              {field.label}
            </Label>
            <Input
              id={field.key}
              type="date"
              value={formValues[field.key] || ''}
              onChange={(e) => handleFieldChange(field.key, e.target.value)}
              className="bg-background border-border focus:ring-primary"
            />
          </div>
        );

      case 'number':
        return (
          <div key={field.key} className={cn("space-y-2", colClasses)}>
            <Label htmlFor={field.key} className="text-sm font-medium text-foreground">
              {field.label}
            </Label>
            <Input
              id={field.key}
              type="number"
              placeholder={field.placeholder || `Enter ${field.label.toLowerCase()}`}
              value={formValues[field.key] || ''}
              onChange={(e) => handleFieldChange(field.key, e.target.value)}
              className="bg-background border-border focus:ring-primary"
            />
          </div>
        );

      default:
        return null;
    }
  };

  // Render dropdown if requested
  if (presentation === 'dropdown') {
    if (!open) return null
    // Initialize with something until measurement completes
    let style: React.CSSProperties = { position: 'fixed', zIndex: 60, left: 12, top: 64, minWidth: 320 }
    if (positionStyle) style = { ...style, ...positionStyle }

    return createPortal(
      <>
        <div onClick={() => onOpenChange?.(false)} className="fixed inset-0 z-50 bg-black/20" />
        <div style={style} ref={dropdownRef} className={cn("pointer-events-auto", className)}>
          <div className="bg-popover border rounded-md p-4 shadow-lg">
          <div className="grid grid-cols-12 gap-4">
            {config.fields.map(renderField)}
          </div>

          <div className="mt-4 flex justify-end gap-2">
            <Button
              variant="default"
              size="sm"
              onClick={handleSearch}
              aria-label="Search Filters"
              className={cn(
                "bg-primary text-primary-foreground hover:bg-primary/90",
                !hasChanges && "opacity-50"
              )}
              disabled={loading}
            >
              <Search className="h-4 w-4 mr-2" />
              Search Filters
            </Button>

            <Button
              variant="outline"
              size="sm"
              onClick={handleReset}
              aria-label="Clear Filters"
              disabled={!hasActiveFilters}
              className={baseToggleClasses()}
            >
              <X className="h-4 w-4 mr-2" />
              {clearText}
              {activeCount > 0 && (
                <span className="ml-1 text-xs bg-primary text-primary-foreground px-1.5 py-0.5 rounded-full">
                  {activeCount}
                </span>
              )}
            </Button>
          </div>
        </div>
      </div>
      </>, document.body
    )
  }

  if (collapsible) {
    return (
      <div className={cn("relative", className)}>
        <Card className="bg-card border-border">
          <CardContent className="p-4">
            <div className="grid grid-cols-12 gap-4">
              {config.fields.map(renderField)}
            </div>

            <div className="mt-4 flex justify-end gap-2">
              <Button
                variant="default"
                size="sm"
                onClick={handleSearch}
                aria-label="Search Filters"
                className={cn(
                  "bg-primary text-primary-foreground hover:bg-primary/90",
                  !hasChanges && "opacity-50"
                )}
                disabled={loading}
              >
                <Search className="h-4 w-4 mr-2" />
                Search Filters
              </Button>

              <Button
                variant="outline"
                size="sm"
                onClick={handleReset}
                aria-label="Clear Filters"
                disabled={!hasActiveFilters}
                className={baseToggleClasses()}
              >
                <X className="h-4 w-4 mr-2" />
                {clearText}
                {activeCount > 0 && (
                  <span className="ml-1 text-xs bg-primary text-primary-foreground px-1.5 py-0.5 rounded-full">
                    {activeCount}
                  </span>
                )}
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return null;
};

export default GenericFilter;