"use client";

import React from "react";
import { Button } from "@/components/ui/button";
import { Filter, X, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";

interface FilterToggleButtonProps {
  hasActiveFilters: boolean;
  isExpanded: boolean;
  onToggle: () => void;
  activeFiltersCount: number;
  filterText?: string;
  clearText?: string;
  className?: string;
}

const FilterToggleButton: React.FC<FilterToggleButtonProps> = ({
  hasActiveFilters,
  isExpanded,
  onToggle,
  activeFiltersCount,
  filterText = "Filter",
  clearText = "Clear Filters",
  className,
}) => {
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={onToggle}
      className={cn(
        "flex items-center gap-2 transition-all duration-200",
        "border-border hover:bg-accent hover:text-accent-foreground",
        hasActiveFilters && "border-primary text-primary hover:border-primary/80",
        className
      )}
    >
      {/* {hasActiveFilters ? (
        <X className="h-4 w-4" />
      ) : ( */}
      <Filter
        className={cn(
          "h-4 w-4 transition-transform duration-200",
          isExpanded && "rotate-180"
        )}
      />
      {filterText}
      {hasActiveFilters && (
        <span className="ml-1 text-xs bg-primary text-primary-foreground px-1.5 py-0.5 rounded-full">
          {activeFiltersCount}
        </span>
      )}
    </Button>
  );
};

export default FilterToggleButton;