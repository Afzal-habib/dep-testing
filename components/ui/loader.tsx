"use client";

import React from "react";
import { cn } from "@/lib/utils";

interface LoaderProps {
  size?: "sm" | "md" | "lg" | "xl";
  variant?: "spinner" | "dots" | "pulse";
  text?: string;
  fullScreen?: boolean;
  className?: string;
}

const sizeClasses = {
  sm: "h-4 w-4",
  md: "h-6 w-6",
  lg: "h-8 w-8",
  xl: "h-12 w-12"
};

const textSizeClasses = {
  sm: "text-sm",
  md: "text-base",
  lg: "text-lg",
  xl: "text-xl"
};

const Spinner: React.FC<{ size: string; className?: string }> = ({ size, className }) => (
  <div
    className={cn(
      "animate-spin rounded-full border-2 border-muted border-t-primary",
      size,
      className
    )}
  />
);

const Dots: React.FC<{ size: string; className?: string }> = ({ size, className }) => {
  const dotSize = size.includes("4") ? "h-1 w-1" :
    size.includes("6") ? "h-1.5 w-1.5" :
      size.includes("8") ? "h-2 w-2" : "h-3 w-3";

  return (
    <div className={cn("flex items-center gap-1", className)}>
      <div className={cn("bg-primary rounded-full animate-bounce", dotSize)} style={{ animationDelay: "0ms" }} />
      <div className={cn("bg-primary rounded-full animate-bounce", dotSize)} style={{ animationDelay: "150ms" }} />
      <div className={cn("bg-primary rounded-full animate-bounce", dotSize)} style={{ animationDelay: "300ms" }} />
    </div>
  );
};

const Pulse: React.FC<{ size: string; className?: string }> = ({ size, className }) => (
  <div
    className={cn(
      "bg-primary rounded-full animate-pulse",
      size,
      className
    )}
  />
);

const Loader: React.FC<LoaderProps> = ({
  size = "md",
  variant = "spinner",
  text,
  fullScreen = false,
  className,
}) => {
  const LoaderComponent = {
    spinner: Spinner,
    dots: Dots,
    pulse: Pulse,
  }[variant];

  const content = (
    <div className={cn(
      "flex flex-col items-center justify-center gap-3",
      fullScreen ? "min-h-screen" : "p-8",
      className
    )}>
      <LoaderComponent size={sizeClasses[size]} />
      {text && (
        <p className={cn(
          "text-muted-foreground font-medium",
          textSizeClasses[size]
        )}>
          {text}
        </p>
      )}
    </div>
  );

  if (fullScreen) {
    return (
      <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center">
        {content}
      </div>
    );
  }

  return content;
};

// Inline loader for buttons, inputs etc
export const InlineLoader: React.FC<{ size?: "sm" | "md"; className?: string }> = ({
  size = "sm",
  className
}) => (
  <Spinner size={sizeClasses[size]} className={className} />
);

// Table loader with skeleton
export const TableLoader: React.FC<{
  rows?: number;
  columns?: number;
  NoOfCards?: number;
  showViewToggle?: boolean;
  showRowsPerPage?: boolean;
  cardsLoader?: boolean;
}> = ({
  rows = 5,
  columns = 4,
  NoOfCards = 4,
  showViewToggle = true,
  showRowsPerPage = true,
  cardsLoader = true
}) => (
    <div className="space-y-4">
      {cardsLoader && (
        <CardLoader cards={NoOfCards} height="h-16" />

      )}
      {/* Header controls */}
      {(showViewToggle || showRowsPerPage) && (
        <div className="flex items-center justify-between">
          {/* Left side - Records per page */}
          <div className="flex items-center space-x-2">
            {showRowsPerPage && (
              <>
                <div className="h-4 bg-muted rounded animate-pulse w-20"></div>
                <div className="h-8 bg-muted rounded animate-pulse w-16"></div>
              </>
            )}
          </div>

          {/* Right side - View toggle */}
          <div className="flex items-center space-x-2">
            {showViewToggle && (
              <div className="flex bg-muted rounded animate-pulse h-8 w-20"></div>
            )}
          </div>
        </div>
      )}

      {/* Table skeleton */}
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full">
          <thead>
            <tr>
              {Array.from({ length: columns }).map((_, j) => (
                <th key={j} className="border-b border-muted p-2">
                  <div className="h-6 bg-muted rounded animate-pulse w-full"></div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: rows }).map((_, i) => (
              <tr key={i}>
                {Array.from({ length: columns }).map((_, j) => (
                  <td key={j} className="border-b border-muted p-2">
                    <div className="h-12 bg-muted rounded animate-pulse w-full"></div>
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

// Card loader with skeleton
export const CardLoader: React.FC<{
  cards?: number;
  height?: string;
  width?: string;
}> = ({
  cards = 4,
  height = "h-24",
  width = "w-full"
}) => {
    return (
      <div className={cn(" space-y-4 grid grid-flow-col auto-cols-fr gap-4")}>
        {Array.from({ length: cards }).map((_, i) => (
          <div key={i} className={cn("bg-muted rounded-lg animate-pulse", height, width)}>
            <div className="p-4 space-y-3">
              {/* Card header */}
              <div className="h-4 bg-muted-foreground/20 rounded w-3/4"></div>
              {/* Card content lines */}
              <div className="space-y-2">
                <div className="h-3 bg-muted-foreground/20 rounded"></div>
                <div className="h-3 bg-muted-foreground/20 rounded w-5/6"></div>
              </div>
              {/* Card footer */}
              <div className="h-3 bg-muted-foreground/20 rounded w-1/2"></div>
            </div>
          </div>
        ))}
      </div>
    );
  };

// Form loader with skeleton
export const FormLoader: React.FC<{
  fields?: number;
  columns?: 1 | 2 | 3 | 4 | 6 | 12;
  showTitle?: boolean;
  showButtons?: boolean;
}> = ({
  fields = 6,
  columns = 2,
  showTitle = true,
  showButtons = true
}) => {
    const gridCols = {
      1: "grid-cols-1",
      2: "grid-cols-2",
      3: "grid-cols-3",
      4: "grid-cols-4",
      6: "grid-cols-6",
      12: "grid-cols-12"
    };

    return (
      <div className="space-y-6">
        {/* Form title */}
        {showTitle && (
          <div className="space-y-2">
            <div className="h-6 bg-muted rounded animate-pulse w-1/3"></div>
            <div className="h-4 bg-muted rounded animate-pulse w-2/3"></div>
          </div>
        )}

        {/* Form fields */}
        <div className={cn("grid gap-4", gridCols[columns])}>
          {Array.from({ length: fields }).map((_, i) => (
            <div key={i} className="space-y-2">
              {/* Field label */}
              <div className="h-4 bg-muted rounded animate-pulse w-1/2"></div>
              {/* Field input */}
              <div className="h-10 bg-muted rounded animate-pulse w-full"></div>
            </div>
          ))}
        </div>

        {/* Form buttons */}
        {showButtons && (
          <div className="flex justify-end space-x-3 pt-4">
            <div className="h-10 bg-muted rounded animate-pulse w-20"></div>
            <div className="h-10 bg-primary/20 rounded animate-pulse w-24"></div>
          </div>
        )}
      </div>
    );
  };

export default Loader;