"use client"

import { useState, memo, useCallback, useMemo } from "react"
import { LogOut, User } from "lucide-react"
import { useProfessionalSession } from "@/components/providers/professional-session-provider"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { ThemeToggle } from "@/components/theme-toggle"
import { MessageNotification } from "@/components/communication/message-notification"
import SystemNotificationBell from "@/components/layout/system-notification-bell"
import CustomModal from "@/components/shared/custom-modal"
import { ProfileSettings } from '@/components/profile/profile-setting'

export const Header = memo(function Header() {
  const { user, logout } = useProfessionalSession()
  const [isProfileSettingsOpen, setIsProfileSettingsOpen] = useState(false)
  
  // Memoize user data to prevent unnecessary re-renders
  const sessionUser = useMemo(() => user, [user]) 

  const handleSignOut = useCallback(async () => {
    await logout()
  }, [logout])

  return (

    <>
      <header className="flex h-16 items-center justify-between lg:justify-end border-b bg-sidebar/95 backdrop-blur-sm px-4 lg:px-6 shrink-0 sticky top-0 z-30">
        {/* Mobile spacing for menu button */}
        <div className="w-10 lg:hidden" />

        {/* Right side */}
        <div className="flex items-center justify-end space-x-2 lg:space-x-4">
          
          <ThemeToggle />

          <MessageNotification className="h-8 w-8 lg:h-9 lg:w-9" />
          
          <SystemNotificationBell />

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <Avatar className="cursor-pointer ">
                    {sessionUser?.avatar ? (
                    <AvatarImage src={sessionUser.avatar} alt={sessionUser.name || "User"} className="object-cover" />
                    ) : (
                    <AvatarFallback className="text-xs hover:bg-primary hover:text-sm hover:font-semibold">
                      {sessionUser?.name
                      ? (() => {
                      const parts = sessionUser.name.trim().split(' ');
                      if (parts.length === 1) {
                        return parts[0][0].toUpperCase();
                      }
                      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                    })()
                  : ''}
                    </AvatarFallback>
                    )}
                </Avatar>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="w-56" align="end" forceMount>
              <DropdownMenuLabel className="font-normal">
                <div className="flex flex-col space-y-1">
                  <p className="text-sm font-medium leading-none truncate">{sessionUser?.name}</p>
                  <p className="text-xs leading-none text-muted-foreground truncate">{sessionUser?.email}</p>
                </div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => setIsProfileSettingsOpen(true)}>
                <User className="mr-2 h-4 w-4" />
                <span>Profile</span>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleSignOut}>
                <LogOut className="mr-2 h-4 w-4" />
                <span>Log out</span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>


      </header>
      {/* Profile Modal */}
      <CustomModal
        isOpen={isProfileSettingsOpen}
        onClose={() => setIsProfileSettingsOpen(false)}
        title="My Profile"
        modalSize="xl"
      >
        {isProfileSettingsOpen && <ProfileSettings />}
      </CustomModal>

    </>
  )
})