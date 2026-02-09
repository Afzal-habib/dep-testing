"use client";

import React, { ReactNode, useEffect } from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

interface CustomModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  modalSize?: "sm" | "md" | "lg" | "xl" | "full";
  children: ReactNode;
  actions?: ReactNode;
  headerActions?: ReactNode;
  className?: string;
  showCloseButton?: boolean;
  position?: "center" | "top-center" | "top-right" | "inline-top-right";
}

const modalSizes = {
  sm: "max-w-md",
  md: "max-w-lg",
  lg: "max-w-2xl",
  xl: "max-w-4xl",
  full: "max-w-7xl"
};

const CustomModal: React.FC<CustomModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
  actions,
  headerActions,
  modalSize = "md",
  className,
  showCloseButton = true,
  position = "center",
}) => {
  // Handle escape key
  useEffect(() => {
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape" && isOpen && position !== "top-right") {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener("keydown", handleEscape);
      // Prevent body scroll when modal is open (except inline or top-right positions)
      if (position !== "inline-top-right" && position !== "top-right") {
        document.body.style.overflow = "hidden";
      }
    }

    return () => {
      document.removeEventListener("keydown", handleEscape);
      document.body.style.overflow = "unset";
    };
  }, [isOpen, onClose, position]);

  if (!isOpen) return null;

  if (position === "inline-top-right") {
    return (
      <div className="relative">
        <div
          className={cn(
            "relative w-full mt-3 bg-background border border-border rounded-lg shadow-lg transform transition-all duration-300 scale-100 opacity-100",
            "animate-in fade-in-0 zoom-in-95 slide-in-from-bottom-2",
            modalSizes[modalSize],
            className
          )}
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between p-4 border-b border-border">
            <h3
              id="modal-title"
              className="text-lg font-semibold text-foreground"
            >
              {title}
            </h3>
            {showCloseButton && (
              <button
                onClick={onClose}
                className="p-1 hover:bg-muted rounded-sm transition-colors duration-200 text-muted-foreground hover:text-foreground"
                aria-label="Close modal"
              >
                <X className="h-5 w-5" />
              </button>
            )}
          </div>

          {/* Content */}
          <div className="max-h-[65vh] overflow-y-auto scrollbar-hide">
            <div className="p-4">
              {children}
            </div>
          </div>

          {/* Actions */}
          {actions && (
            <div className="flex items-center justify-end gap-3 p-4 border-t border-border bg-muted/30">
              {actions}
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div
      className={`fixed inset-0 ${position === "center"
          ? "flex items-center justify-center z-20"
          : position === "top-center"
            ? "flex items-start justify-center z-20"
            : "flex items-start justify-end top-0 right-0 z-10"
        }`}
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
      // Remove space-y-6 for this modal instance
      style={position === "top-right" ? { gap: 0, margin: 0, marginTop: "3.5rem" } : undefined}
    >
      {/* Backdrop */}
      <div
        className={` ${position !== "top-right" ? " absolute inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-300" : "top-0 left-0 right-0 h-full"}`}
        onClick={position !== "top-right" ? onClose : () => { }}
        aria-hidden="true"
      />

      {/* Modal Container */}
      <div
        className={cn(
          "relative z-10  w-full overflow-hidden h-100",
          position === "center"
            ? "flex items-center justify-center mx-4"
            : position === "top-center"
              ? "flex items-start justify-center mx-4"
              : "flex items-center justify-end  h-[93vh] z-10 "
        )}
        onClick={position !== "top-right" ? onClose : () => { }}
      >
        <div
          className={cn(
            "relative w-full  mt-3",
            position === "top-right" ? "h-full" : "mx-auto",
            "bg-background border border-border rounded-lg shadow-lg transform transition-all duration-300 scale-100 opacity-100",
            "animate-in fade-in-0 zoom-in-95 slide-in-from-bottom-2",
            modalSizes[modalSize],
            className
          )}
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-start justify-between p-4 border-b border-border gap-2">
            <h3
              id="modal-title"
              className="text-lg font-semibold text-foreground"
            >
              {title}
            </h3>
            {headerActions ? (
              <div className="flex items-center gap-2">
                {headerActions}
                {showCloseButton && (
                  <button
                    onClick={onClose}
                    className="p-1 hover:bg-muted rounded-sm transition-colors duration-200 text-muted-foreground hover:text-foreground"
                    aria-label="Close modal"
                  >
                    <X className="h-5 w-5" />
                  </button>
                )}
              </div>
            ) : (
              showCloseButton && (
                <button
                  onClick={onClose}
                  className="p-1 hover:bg-muted rounded-sm transition-colors duration-200 text-muted-foreground hover:text-foreground"
                  aria-label="Close modal"
                >
                  <X className="h-5 w-5" />
                </button>
              )
            )}
          </div>

          {/* Content */}
          <div className={` ${position !== "top-right" ? "max-h-[65vh]" : "h-[85vh]"} overflow-y-auto scrollbar-hide`}>
            <div className="p-4">
              {children}
            </div>
          </div>

          {/* Actions */}
          {actions && (
            <div className="flex items-center justify-end gap-3 p-4 border-t border-border bg-muted/30">
              {actions}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CustomModal;