"use client"

import React, { useState, useEffect, memo, useMemo, useCallback } from "react"
import Link from "next/link"
import Image from "next/image"
import { usePathname, useRouter } from "next/navigation"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { usePermissions } from "@/hooks/use-permissions"
import { useNavigation } from "@/components/providers/navigation-provider"
import { Deferred } from "@/components/ui/deferred"
import { UserCog, Handshake, AlignLeft } from 'lucide-react';
import {
  Home,
  Users2,
  Target,
  FolderOpen,
  Network,
  Eye,
  UserPlus,
  Plus,
  Building,
  TrendingUp,
  Send,
  Folder,
  FileCheck,
  Lock,
  Activity,
  ChevronLeft,
  ChevronDown,
  Menu,
  X,
  MessageSquare,
  Settings as SettingsIcon
} from "lucide-react"

import { ResizableSidebar } from "../communication/resizable-sidebar"

type MenuSubItem = {
  title: string
  href: string
  icon: React.ElementType
  allowedResource?: string
  allowedActions?: string[]
}

type MenuItem = {
  title: string
  href: string
  icon: React.ElementType
  badge: null | string
  subItems?: MenuSubItem[]
  allowedResource?: string
  allowedActions?: string[]
}

type MenuSection = {
  title: string
  items: MenuItem[]
}

const menuItems: MenuSection[] = [
  {
    title: "MAIN MENU",
    items: [
      {
        title: "Dashboard",
        href: "/dashboard",
        icon: Home,
        badge: null,
        allowedResource: "dashboard",
        allowedActions: ["read"],
      },
    ],
  },
  {
    title: "CRM",
    items: [
      {
        title: "Users",
        href: "/users",
        icon: Users2,
        badge: null,
        allowedResource: "users",
        allowedActions: ["read"],
        subItems: [
          {
            title: "Users List",
            href: "/users",
            icon: Eye,
            allowedResource: "users",
            allowedActions: ["read"],
          },
          {
            title: "Add User",
            href: "/users/add",
            icon: UserPlus,
            allowedResource: "users",
            allowedActions: ["create"],
          },
        ],
      },
      {
        title: "Leads",
        href: "/leads",
        icon: Target,
        badge: null,
        allowedResource: "leads",
        allowedActions: ["read"],
        subItems: [
          {
            title: "Leads List",
            href: "/leads",
            icon: Eye,
            allowedResource: "leads",
            allowedActions: ["read"],
          },
          {
            title: "Add Lead",
            href: "/leads/add",
            icon: Plus,
            allowedResource: "leads",
            allowedActions: ["create"],
          },
        ],
      },
      {
        title: "Clients",
        href: "/clients",
        icon: Handshake,
        badge: null,
        allowedResource: "clients",
        allowedActions: ["read"],
        subItems: [
          {
            title: "Clients List",
            href: "/clients",
            icon: Eye,
            allowedResource: "clients",
            allowedActions: ["read"],
          },
          {
            title: "Add Client",
            href: "/clients/add",
            icon: Plus,
            allowedResource: "clients",
            allowedActions: ["create"],
          },
        ],
      },

      {
        title: "Projects",
        href: "/projects",
        icon: FolderOpen,
        badge: null,
        allowedResource: "projects",
        allowedActions: ["read"],
        subItems: [
          {
            title: "Projects List",
            href: "/projects",
            icon: Eye,
            allowedResource: "projects",
            allowedActions: ["read"],
          },
          {
            title: "Create Project",
            href: "/projects/add",
            icon: Plus,
            allowedResource: "projects",
            allowedActions: ["create"],
          },
        ],
      },
    ],
  },

  {
    title: "HRM",
    items: [
      {
        title: "Departments",
        href: '/departments',
        icon: Network,
        badge: null,
        allowedResource: "departments",
        allowedActions: ["read"],
        subItems: [
          {
            title: "Departments List",
            href: '/departments',
            icon: Eye,
            allowedResource: "departments",
            allowedActions: ["read"],
          },
          {
            title: "Add Department",
            href: '/departments/add',
            icon: Plus,
            allowedResource: "departments",
            allowedActions: ["create"],
          },
        ]
      },
      {
        title: "Roles",
        href: '/roles',
        icon: UserCog,
        badge: null,
        allowedResource: "roles",
        allowedActions: ["read"],
        subItems: [
          {
            title: "Roles List",
            href: "/roles",
            icon: Eye,
            allowedResource: "roles",
            allowedActions: ["read"],
          },
          {
            title: "Add Role",
            href: "/roles/add",
            icon: Plus,
            allowedResource: "roles",
            allowedActions: ["create"],
          },
        ]
      },
    ],
  },
  {
    title: "Chat & Communications",
    items: [
      {
        title: "Messages Inbox",
        href: "/communications",
        icon: Eye,
        badge: null,
        allowedResource: "communications",
        allowedActions: ["read"],
      },
      {
        title: "Create Channel",
        href: "/communications?create=true",
        icon: Plus,
        badge: null,
        allowedResource: "communications",
        allowedActions: ["read"],
      },
      {
        title: "Client Portal Chat",
        href: "/client-portal/chat",
        icon: MessageSquare,
        badge: null,
        allowedResource: "communications",
        allowedActions: ["read"],
      },
    ],
  },
  {
    title: "SYSTEM",
    items: [
      {
        title: "Settings",
        href: "/settings",
        icon: SettingsIcon,
        badge: null,
        allowedResource: "settings",
        allowedActions: ["read"],
      },
    ],
  },
]

interface SidebarProps {
  className?: string
}

export const Sidebar = memo(function Sidebar({ className }: SidebarProps) {
  const pathname = usePathname()
  const router = useRouter()
  const { navigateTo, isNavigating } = useNavigation()

  // Memoize route calculations
  const isCommunicationsRoute = useMemo(() =>
    pathname?.startsWith("/communications") || pathname?.startsWith("/client-portal"),
    [pathname]
  )

  const [collapsed, setCollapsed] = useState(isCommunicationsRoute)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [expandedItems, setExpandedItems] = useState<string[]>([])
  const [isDesktop, setIsDesktop] = useState(false)

  // Get permissions
  const { canAccess, loading: permissionsLoading } = usePermissions()

  // Aggressive prefetching for all accessible routes - NON-BLOCKING
  useEffect(() => {
    if (permissionsLoading) return

    // Use requestIdleCallback to prefetch only when browser is idle
    const prefetchRoutes = () => {
      menuItems.forEach(section => {
        section.items.forEach(item => {
          if (!item.allowedResource || canAccess(item.allowedResource, item.allowedActions)) {
            router.prefetch(item.href)
            item.subItems?.forEach(subItem => {
              if (!subItem.allowedResource || canAccess(subItem.allowedResource, subItem.allowedActions)) {
                router.prefetch(subItem.href)
              }
            })
          }
        })
      })
    }

    // Use requestIdleCallback if available for non-blocking prefetch
    if (typeof window !== 'undefined' && 'requestIdleCallback' in window) {
      const handle = requestIdleCallback(prefetchRoutes, { timeout: 2000 })
      return () => cancelIdleCallback(handle)
    } else {
      // Fallback to setTimeout
      const timer = setTimeout(prefetchRoutes, 1000)
      return () => clearTimeout(timer)
    }
  }, [permissionsLoading, canAccess, router])

  // Handle desktop detection for resizable sidebar
  useEffect(() => {
    const handleResize = () => {
      setIsDesktop(window.innerWidth >= 1024)
    }
    handleResize()
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [])

  // Memoized helper function to check if user can access a menu item
  const canAccessItem = useCallback((item: MenuItem | MenuSubItem): boolean => {
    if (!item.allowedResource || !item.allowedActions) {
      return true // Show items without allowedResource/allowedActions requirements
    }
    const hasAccess = canAccess(item.allowedResource, item.allowedActions)
    if (!hasAccess) {
      console.log('🔧 Sidebar access denied:', {
        title: item.title,
        resource: item.allowedResource,
        actions: item.allowedActions,
        hasAccess
      })
    }
    return hasAccess
  }, [canAccess])

  // Memoized helper function to check if any sub-items are accessible
  const hasAccessibleSubItems = useCallback((subItems?: MenuSubItem[]): boolean => {
    if (!subItems) return false
    return subItems.some(subItem => canAccessItem(subItem))
  }, [canAccessItem])

  // Handle responsive behavior
  useEffect(() => {
    const handleResize = () => {
      const isMobile = window.innerWidth < 1024
      if (isMobile) {
        setCollapsed(false) // On mobile, always show full sidebar when open
        setMobileOpen(false) // Close mobile sidebar on resize
      } else {
        setCollapsed(window.innerWidth < 1280) // Auto-collapse on medium screens
      }
    }

    handleResize()
    window.addEventListener("resize", handleResize)
    return () => window.removeEventListener("resize", handleResize)
  }, [])

  // Close mobile sidebar when route changes
  useEffect(() => {
    setMobileOpen(false)
  }, [pathname])

  // Collapse sidebar for communications routes
  useEffect(() => {
    const isMobile = window.innerWidth < 1024
    if (isMobile || isCommunicationsRoute) {
      setCollapsed(false) // On mobile, always show full sidebar when open
      setMobileOpen(false)
    }
  }, [pathname])

  // Prevent body scroll when mobile sidebar is open
  useEffect(() => {
    if (mobileOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = 'unset'
    }

    return () => {
      document.body.style.overflow = 'unset'
    }
  }, [mobileOpen])

  const toggleExpanded = (title: string) => {
    setExpandedItems(prev =>
      prev.includes(title)
        ? prev.filter(item => item !== title)
        : [...prev, title]
    )
  }

  const isItemExpanded = (title: string) => expandedItems.includes(title)

  const toggleMobileSidebar = () => {
    setMobileOpen(!mobileOpen)
  }

  const toggleCollapsed = () => {
    setCollapsed(!collapsed)
  }

  const translateClass = mobileOpen ? "translate-x-0" : (isCommunicationsRoute ? "-translate-x-full" : "-translate-x-full lg:translate-x-0")

  const isWrapped = isDesktop && !isCommunicationsRoute

  const sidebarClassName = cn(

    "flex flex-col sidebar border-r bg-sidebar/95 backdrop-blur-sm transition-all duration-300 ease-in-out",

    isCommunicationsRoute ? "fixed z-50 h-screen max-h-screen" : "lg:sticky lg:top-0 lg:h-screen lg:max-h-screen fixed z-50 h-screen max-h-screen lg:z-auto",

    translateClass,

    isWrapped ? "lg:w-auto" : (collapsed ? "w-16" : "w-72"),

    className,

  )

  const sidebarContent = (

    <div className={sidebarClassName}>

      {/* Header */}

      <div className="flex h-16 gap-2 items-center justify-between border-b bg-gradient-to-r from-sidebar/98 to-sidebar-accent/5 backdrop-blur-sm px-3  shrink-0 shadow-sm">

        {!collapsed && (

          <Link href="/" className="flex items-center space-x-3 min-w-0 group">

            <div className="flex h-9 w-12 items-center justify-center shrink-0 overflow-hidden transition-transform duration-300 group-hover:scale-110">

              <Image

                src="/digi-era-logo.webp"

                width={48}

                height={36}

                alt="Logo"

                className="object-contain drop-shadow-sm max-h-full max-w-full"

                style={{ width: 'auto', height: 'auto' }}

                sizes="48px"

              />

            </div>

            <div className="min-w-0">

              <div className="text-lg font-bold tracking-tight text-sidebar-foreground truncate transition-colors duration-300 group-hover:text-primary">

                DIGI ERA PRO

              </div>

              <div className="text-xs text-muted-foreground/70 font-medium truncate transition-colors duration-300 group-hover:text-sidebar-foreground/80">

                Customer Relations

              </div>

            </div>

          </Link>

        )}

        {/* Desktop toggle button */}

        <Button

          variant="ghost"

          size="sm"

          onClick={toggleCollapsed}

          className={cn(

            "p-0 hover:bg-primary hover:shadow-md transition-all duration-300 shrink-0 hover:scale-110",

            collapsed ? "h-9 w-9" : "h-8 w-8",

            "hidden",

            !isCommunicationsRoute && "lg:flex"

          )}

        >

          <ChevronLeft className={cn(

            "transition-transform duration-300",

            collapsed ? "h-9 w-9" : "h-4 w-4",

            collapsed && "rotate-180"

          )} />

        </Button>

        {/* Mobile close button */}

        <Button

          variant="ghost"

          size="sm"

          onClick={() => setMobileOpen(false)}

          className={`h-9 w-9 p-0 hover:bg-primary hover:shadow-md transition-all duration-300 ${isCommunicationsRoute ? '' : 'lg:hidden'} shrink-0 hover:scale-110`}

        >

          <X className="h-4 w-4" />

        </Button>

      </div>

      {/* Navigation */}

      <ScrollArea className="flex-1 px-3 py-4">

        {permissionsLoading ? (

          <div className="space-y-2">

            {/* Loading skeleton */}

            {Array.from({ length: 6 }).map((_, index) => (

              <div key={index} className="flex items-center space-x-3 px-3 py-2.5">

                <div className="h-8 w-8 bg-sidebar-accent/20 rounded-lg animate-pulse" />

                {!collapsed && (

                  <div className="flex-1 space-y-1">

                    <div className="h-4 bg-sidebar-accent/20 rounded animate-pulse" />

                  </div>

                )}

              </div>

            ))}

          </div>

        ) : (

          <nav className="space-y-6">

            {menuItems.map((section, sectionIndex) => {

              // Filter items based on permissions

              const accessibleItems = section.items.filter(item =>

                canAccessItem(item) || hasAccessibleSubItems(item.subItems)

              )

              // Skip section if no accessible items

              if (accessibleItems.length === 0) return null

              return (

                <div key={sectionIndex} className="space-y-2">

                  {!collapsed && (

                    <div className="flex items-center px-3 pb-2">

                      <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground/80 truncate">

                        {section.title}

                      </h3>

                      <div className="ml-3 flex-1 border-t border-sidebar-border/40" />

                    </div>

                  )}

                  <div className="space-y-1">

                    {accessibleItems.map((item, itemIndex) => {

                      const isActive = pathname === item.href ||

                        (item.subItems && item.subItems.some(subItem => pathname === subItem.href))

                      const isExpanded = isItemExpanded(item.title)

                      // Filter accessible sub-items

                      const accessibleSubItems = item.subItems?.filter(subItem => canAccessItem(subItem))

                      const hasSubItems = accessibleSubItems && accessibleSubItems.length > 0

                      return (

                        <div key={itemIndex}>

                          {hasSubItems && !collapsed ? (

                            <Collapsible open={isExpanded} onOpenChange={() => toggleExpanded(item.title)}>

                              <CollapsibleTrigger asChild>

                                <div

                                  className={cn(

                                    "group flex w-full items-center rounded-lg px-2 py-2 text-sm font-medium transition-all duration-300 cursor-pointer",

                                    "hover:bg-gradient-to-r hover:from-sidebar-accent hover:to-sidebar-accent/50 hover:shadow-lg hover:scale-[1.02] hover:border-sidebar-accent/20",

                                    "border border-transparent",

                                    isActive

                                      ? "bg-gradient-to-r from-primary/10 via-sidebar-accent to-sidebar-accent/60 text-sidebar-accent-foreground shadow-lg font-semibold border-sidebar-accent/30"

                                      : "text-sidebar-foreground hover:text-sidebar-accent-foreground",

                                  )}

                                >

                                  <div className={cn(

                                    "flex h-6 w-6 items-center justify-center rounded-lg transition-all duration-300 mr-3 shrink-0",

                                    "transform group-hover:scale-110 group-hover:rotate-3",

                                    isActive

                                      ? "bg-primary/20 text-primary shadow-md ring-2 ring-primary/20"

                                      : "bg-sidebar-accent/20 text-sidebar-foreground/70 group-hover:bg-sidebar-accent/50 group-hover:text-sidebar-foreground group-hover:shadow-md"

                                  )}>

                                    <item.icon className="h-4 w-4" />

                                  </div>

                                  <span className="flex-1 text-left tracking-wide truncate min-w-0">

                                    {item.title}

                                  </span>

                                  {item.badge && (

                                    <span className="ml-2 rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary shrink-0">

                                      {item.badge}

                                    </span>

                                  )}

                                  <ChevronDown className={cn(

                                    "ml-2 h-4 w-4 transition-transform duration-200 shrink-0",

                                    isExpanded && "rotate-180"

                                  )} />

                                </div>

                              </CollapsibleTrigger>

                              <CollapsibleContent className="space-y-0">

                                <div className="mt-2 ml-5 space-y-1">

                                  {accessibleSubItems?.map((subItem, subIndex) => {

                                    const isSubActive = pathname === subItem.href

                                    return (

                                      <div

                                        key={subIndex}

                                        onClick={() => navigateTo(subItem.href)}

                                        className={cn(

                                          "group flex items-center rounded-md px-2 py-1.5 text-sm transition-all duration-300 cursor-pointer",

                                          "hover:bg-sidebar-accent/40 hover:text-sidebar-accent-foreground hover:translate-x-1 hover:shadow-md",

                                          "border-l-2 border-transparent hover:border-sidebar-accent/50",

                                          isSubActive

                                            ? "bg-primary text-white font-medium text-base hover:bg-primary-80 hover:text-primary-foreground border-l-primary shadow-md"

                                            : "text-sidebar-foreground/80 hover:text-sidebar-foreground",

                                          isNavigating && "opacity-60 cursor-not-allowed"

                                        )}

                                      >

                                        <div className={cn(

                                          "flex h-6 w-6 items-center justify-center rounded-md transition-all duration-300 mr-3 shrink-0",

                                          "transform group-hover:scale-110",

                                          isSubActive

                                            ? "bg-primary/20 text-white shadow-sm ring-1 ring-primary/30"

                                            : "text-sidebar-foreground/60 group-hover:text-sidebar-foreground group-hover:bg-sidebar-accent/30"

                                        )}>

                                          <subItem.icon className="h-3.5 w-3.5" />

                                        </div>

                                        <span className="tracking-wide truncate min-w-0">

                                          {subItem.title}

                                        </span>

                                      </div>

                                    )

                                  })}

                                </div>

                              </CollapsibleContent>

                            </Collapsible>

                          ) : (

                            canAccessItem(item) && (

                              <div

                                onClick={() => navigateTo(item.href)}

                                className={cn(

                                  "group flex items-center rounded-lg px-2 py-1.5 text-sm font-medium transition-all duration-300 cursor-pointer",

                                  "hover:bg-gradient-to-r hover:from-sidebar-accent hover:to-sidebar-accent/50 hover:shadow-lg hover:scale-[1.02] hover:border-sidebar-accent/20",

                                  "border border-transparent",

                                  isActive

                                    ? "bg-gradient-to-r from-primary/10 via-sidebar-accent to-sidebar-accent/60 text-sidebar-accent-foreground shadow-lg font-semibold border-sidebar-accent/30"

                                    : "text-sidebar-foreground hover:text-sidebar-accent-foreground",

                                  collapsed && "justify-center px-2",

                                  isNavigating && "opacity-60 cursor-not-allowed"

                                )}

                              >

                                <div className={cn(

                                  "flex items-center justify-center rounded-lg transition-all duration-300 shrink-0",

                                  "transform group-hover:scale-110 group-hover:rotate-3",

                                  collapsed ? "h-6 w-6" : "h-6 w-6 mr-3",

                                  isActive

                                    ? "bg-primary/20 text-primary shadow-md ring-2 ring-primary/20"

                                    : "bg-sidebar-accent/20 text-sidebar-foreground/70 group-hover:bg-sidebar-accent/50 group-hover:text-sidebar-foreground group-hover:shadow-md"

                                )}>

                                  <item.icon className="h-4 w-4" />

                                </div>

                                {!collapsed && (

                                  <div className="flex flex-1 items-center justify-between min-w-0">

                                    <span className="tracking-wide truncate">

                                      {item.title}

                                    </span>

                                    {item.badge && (

                                      <span className="ml-2 rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary shrink-0">

                                        {item.badge}

                                      </span>

                                    )}

                                  </div>

                                )}

                              </div>

                            )

                          )}

                        </div>

                      )

                    })}

                  </div>

                </div>

              )

            })}

          </nav>

        )}

      </ScrollArea>

    </div>

  )

  return (
    <>
      {/* Mobile Menu Button */}
      <button
        // variant="ghost"
        // size="sm"
        onClick={toggleMobileSidebar}
        className={`mainCollapserBtn fixed top-4 border-0 left-4 z-50 ${isCommunicationsRoute ? '' : 'lg:hidden'} h-9 w-9 p-0 bg-background/80 backdrop-blur-sm border shadow-sm hover:text-primary transition-all duration-300  flex items-center justify-center hover:scale-110`}
      >
        {mobileOpen ? (
          <X className="h-4 w-4" />
        ) : (
          <svg
            width={24}
            height={24}
            viewBox="0 0 24 24"
            fill="currentColor"
          >
            <rect x="3" y="5" width="18" height="3" rx="1.5" />
            <rect x="3" y="10.5" width="10" height="3" rx="1.5" />
            <rect x="3" y="16" width="18" height="3" rx="1.5" />
          </svg>



        )}
      </button>

      {/* Mobile Overlay */}
      {mobileOpen && (
        <div
          className={`fixed inset-0 bg-black/60 backdrop-blur-sm z-40 ${isCommunicationsRoute ? '' : 'lg:hidden'}`}
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar - Sticky positioning */}
      {isWrapped ? (
        <ResizableSidebar
          defaultWidth={collapsed ? 64 : 288}
          minWidth={collapsed ? 64 : 200}
          maxWidth={collapsed ? 64 : 500}
          storageKey="main-sidebar"
          className="hidden lg:flex border-r"
        >
          {sidebarContent}
        </ResizableSidebar>
      ) : (
        sidebarContent
      )}
    </>
  )
})