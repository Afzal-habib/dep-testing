"use client"

import React, { useState, useRef, useEffect, useCallback } from "react"
import { cn } from "@/lib/utils"
import { GripVertical } from "lucide-react"

interface ResizableSidebarProps {
  children: React.ReactNode
  defaultWidth?: number
  minWidth?: number
  maxWidth?: number
  storageKey?: string
  className?: string
  dragHandleClassName?: string
  side?: 'left' | 'right'
  onWidthChange?: (width: number) => void
}

const STORAGE_KEY_PREFIX = "sidebar-width-"

export function ResizableSidebar({
  children,
  defaultWidth = 320,
  minWidth = 200,
  maxWidth = 500,
  storageKey = "communication",
  className,
  dragHandleClassName,
  side = 'left',
  onWidthChange
}: ResizableSidebarProps) {
  const [width, setWidth] = useState(defaultWidth)
  const [isResizing, setIsResizing] = useState(false)
  const [isHovering, setIsHovering] = useState(false)
  const sidebarRef = useRef<HTMLDivElement>(null)
  const startXRef = useRef(0)
  const startWidthRef = useRef(0)

  // Load saved width from localStorage on mount
  useEffect(() => {
    const savedWidth = localStorage.getItem(`${STORAGE_KEY_PREFIX}${storageKey}`)
    if (savedWidth) {
      const parsed = parseInt(savedWidth, 10)
      if (!isNaN(parsed) && parsed >= minWidth && parsed <= maxWidth) {
        setWidth(parsed)
      }
    }
  }, [storageKey, minWidth, maxWidth])

  // Update width when props change
  useEffect(() => {
    const clampedWidth = Math.max(minWidth, Math.min(maxWidth, defaultWidth))
    setWidth(clampedWidth)
    localStorage.setItem(`${STORAGE_KEY_PREFIX}${storageKey}`, String(clampedWidth))
  }, [defaultWidth, minWidth, maxWidth, storageKey])

  // Save width to localStorage when it changes
  const saveWidth = useCallback((newWidth: number) => {
    localStorage.setItem(`${STORAGE_KEY_PREFIX}${storageKey}`, String(newWidth))
  }, [storageKey])

  // Handle mouse down on drag handle
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    setIsResizing(true)
    startXRef.current = e.clientX
    startWidthRef.current = width
  }, [width])

  // Handle mouse move during resize
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isResizing) return

      const delta = e.clientX - startXRef.current
      // For right-side panels, reverse the delta direction
      const adjustedDelta = side === 'right' ? -delta : delta
      const newWidth = Math.min(maxWidth, Math.max(minWidth, startWidthRef.current + adjustedDelta))
      
      setWidth(newWidth)
      onWidthChange?.(newWidth)
    }

    const handleMouseUp = () => {
      if (isResizing) {
        setIsResizing(false)
        saveWidth(width)
      }
    }

    if (isResizing) {
      document.addEventListener("mousemove", handleMouseMove)
      document.addEventListener("mouseup", handleMouseUp)
      // Add cursor style to body during resize
      document.body.style.cursor = "col-resize"
      document.body.style.userSelect = "none"
    }

    return () => {
      document.removeEventListener("mousemove", handleMouseMove)
      document.removeEventListener("mouseup", handleMouseUp)
      document.body.style.cursor = ""
      document.body.style.userSelect = ""
    }
  }, [isResizing, width, minWidth, maxWidth, saveWidth, onWidthChange])

  // Handle touch events for mobile
  const handleTouchStart = useCallback((e: React.TouchEvent) => {
    setIsResizing(true)
    startXRef.current = e.touches[0].clientX
    startWidthRef.current = width
  }, [width])

  useEffect(() => {
    const handleTouchMove = (e: TouchEvent) => {
      if (!isResizing) return

      const delta = e.touches[0].clientX - startXRef.current
      // For right-side panels, reverse the delta direction
      const adjustedDelta = side === 'right' ? -delta : delta
      const newWidth = Math.min(maxWidth, Math.max(minWidth, startWidthRef.current + adjustedDelta))
      
      setWidth(newWidth)
      onWidthChange?.(newWidth)
    }

    const handleTouchEnd = () => {
      if (isResizing) {
        setIsResizing(false)
        saveWidth(width)
      }
    }

    if (isResizing) {
      document.addEventListener("touchmove", handleTouchMove)
      document.addEventListener("touchend", handleTouchEnd)
    }

    return () => {
      document.removeEventListener("touchmove", handleTouchMove)
      document.removeEventListener("touchend", handleTouchEnd)
    }
  }, [isResizing, width, minWidth, maxWidth, saveWidth, onWidthChange])

  // Double-click to reset to default
  const handleDoubleClick = useCallback(() => {
    setWidth(defaultWidth)
    saveWidth(defaultWidth)
    onWidthChange?.(defaultWidth)
  }, [defaultWidth, saveWidth, onWidthChange])

  return (
    <div
      ref={sidebarRef}
      className={cn(
        "relative flex shrink-0 overflow-hidden",
        className
      )}
      style={{ width: `${width}px` }}
    >
      {/* Main content */}
      <div className="flex-1 overflow-hidden">
        {children}
      </div>

      {/* Drag handle */}
      <div
        className={cn(
          "absolute top-0 w-1.5 h-full cursor-col-resize",
          "flex items-center justify-center",
          "transition-colors duration-150",
          "hover:bg-primary/20",
          isResizing && "bg-primary/30",
          side === 'right' ? "left-0" : "right-0",
          dragHandleClassName
        )}
        onMouseDown={handleMouseDown}
        onTouchStart={handleTouchStart}
        onDoubleClick={handleDoubleClick}
        onMouseEnter={() => setIsHovering(true)}
        onMouseLeave={() => setIsHovering(false)}
        title="Drag to resize, double-click to reset"
      >
        {/* Visual indicator */}
        <div
          className={cn(
            "absolute top-1/2 -translate-y-1/2",
            "w-4 h-8",
            "flex items-center justify-center",
            "rounded bg-muted border border-border shadow-sm",
            "opacity-0 transition-opacity duration-150",
            side === 'right' ? "-left-1.5" : "-right-1.5",
            (isHovering || isResizing) && "opacity-100"
          )}
        >
          <GripVertical className="h-4 w-4 text-muted-foreground" />
        </div>
      </div>
    </div>
  )
}

// Export a simple hook to get sidebar width preference
export function useSidebarWidth(storageKey: string = "communication", defaultWidth: number = 320): number {
  const [width, setWidth] = useState(defaultWidth)

  useEffect(() => {
    const savedWidth = localStorage.getItem(`${STORAGE_KEY_PREFIX}${storageKey}`)
    if (savedWidth) {
      const parsed = parseInt(savedWidth, 10)
      if (!isNaN(parsed)) {
        setWidth(parsed)
      }
    }
  }, [storageKey])

  return width
}
