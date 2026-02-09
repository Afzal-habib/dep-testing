"use client"

import { useState, useEffect, useRef } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import {
  User,
  Mail,
  Phone,
  MapPin,
  Briefcase,
  Calendar,
  Clock,
  Shield,
  Settings,
  Key,
  Eye,
  EyeOff,
  Save,
  Loader2,
  Edit,
  Globe,
  Bell,
  Monitor,
  Sun,
  Moon,
  Linkedin,
  Twitter,
  Github
} from "lucide-react"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Separator } from "@/components/ui/separator"
import { cn } from "@/lib/utils"
import { useProfile } from "@/hooks/use-profile"
import {
  profileFormSchema,
  passwordChangeFormSchema,
  type ProfileFormData,
  type PasswordChangeFormData,
} from "@/lib/validations/profile"
import { ImageUploader } from "../upload/image-uploader"
import { useSession } from "next-auth/react"

export function ProfileSettings() {
  const [activeTab, setActiveTab] = useState<'overview' | 'edit' | 'security' >('overview')
  const [isEditing, setIsEditing] = useState(false)
  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false
  })
  const [error, setError] = useState("")
  const [success, setSuccess] = useState("")
  const [realTimeSessionDuration, setRealTimeSessionDuration] = useState<number>(0)
  const hasFetched = useRef(false)
  const sessionTimerRef = useRef<NodeJS.Timeout | null>(null)
  const sessionStartTimeRef = useRef<Date | null>(null)

  // Use the profile hook
  const { data: session, update } = useSession()


  const {
    profileData,
    isLoading,
    refetch,
    updateProfile,
    changePassword,
    formatDuration
  } = useProfile()


  async function change_state(url: string) {
    await refetch()
    console.log('Refetched profile data after image upload:', url)

    // Update the session with the new avatar
    await update({ avatar: url })

    console.log('Session updated with new avatar:', url)
  }

  // Profile form
  const profileForm = useForm<ProfileFormData>({
    resolver: zodResolver(profileFormSchema),
  })

  // Password form
  const passwordForm = useForm<PasswordChangeFormData>({
    resolver: zodResolver(passwordChangeFormSchema),
  })

  // Real-time session duration formatter
  const formatRealTimeSessionDuration = (milliseconds: number): string => {
    const totalSeconds = Math.floor(milliseconds / 1000)
    const hours = Math.floor(totalSeconds / 3600)
    const minutes = Math.floor((totalSeconds % 3600) / 60)
    const seconds = totalSeconds % 60

    if (hours > 0) {
      return `${hours}h ${minutes}m ${seconds}s`
    } else if (minutes > 0) {
      return `${minutes}m ${seconds}s`
    } else {
      return `${seconds}s`
    }
  }

  // Initialize session timer when profile data is loaded
  useEffect(() => {
    if (profileData && !sessionTimerRef.current) {
      // Set the session start time from profile data or current time
      const sessionStartTime = profileData.sessionStartTime
        ? new Date(profileData.sessionStartTime)
        : new Date()

      sessionStartTimeRef.current = sessionStartTime

      // Calculate initial duration
      const initialDuration = Date.now() - sessionStartTime.getTime()
      setRealTimeSessionDuration(initialDuration)

      // Start the timer
      sessionTimerRef.current = setInterval(() => {
        if (sessionStartTimeRef.current) {
          const currentDuration = Date.now() - sessionStartTimeRef.current.getTime()
          setRealTimeSessionDuration(currentDuration)
        }
      }, 1000) // Update every second

      console.log('Session timer started:', sessionStartTime)
    }

    // Cleanup function
    return () => {
      if (sessionTimerRef.current) {
        clearInterval(sessionTimerRef.current)
        sessionTimerRef.current = null
      }
    }
  }, [profileData])

  // Cleanup timer on component unmount
  useEffect(() => {
    return () => {
      if (sessionTimerRef.current) {
        clearInterval(sessionTimerRef.current)
        sessionTimerRef.current = null
      }
    }
  }, [])

  // Handle profile form submission
  const onProfileSubmit = async (data: ProfileFormData) => {
    setError("")
    setSuccess("")

    const socialLinks = [];
    if (data.socialLinks.linkedin) socialLinks.push({ linkName: 'LinkedIn', linkUrl: data.socialLinks.linkedin });
    if (data.socialLinks.twitter) socialLinks.push({ linkName: 'Twitter', linkUrl: data.socialLinks.twitter });
    if (data.socialLinks.github) socialLinks.push({ linkName: 'GitHub', linkUrl: data.socialLinks.github });

    const result = await updateProfile({ ...data, socialLinks } as any)
    if (result.success) {
      setSuccess("Profile updated successfully")
      setIsEditing(false)
    } else {
      setError(result.error || "Failed to update profile")
    }
  }

  // Handle password change
  const onPasswordSubmit = async (data: PasswordChangeFormData) => {
    setError("")
    setSuccess("")

    const result = await changePassword(data)
    if (result.success) {
      setSuccess("Password changed successfully")
      passwordForm.reset()
      setShowPasswords({ current: false, new: false, confirm: false })
    } else {
      setError(result.error || "Failed to change password")
    }
  }

  // Format date
  const formatDate = (date: string | Date) => {
    return new Date(date).toLocaleString()
  }

  // Fetch profile data when component mounts (only once)
  useEffect(() => {
    if (!hasFetched.current && !isLoading && !profileData) {
      console.log('ProfileSettings: Initiating profile fetch')
      hasFetched.current = true
      refetch()
    }
  }, [profileData, isLoading, refetch])

  // Set form defaults when profile data is loaded
  useEffect(() => {
    if (profileData) {
      const socialLinksObj = { linkedin: "", twitter: "", github: "" };
      if (profileData.socialLinks && Array.isArray(profileData.socialLinks)) {
        profileData.socialLinks.forEach(link => {
          const name = link.linkName.toLowerCase();
          if (name.includes('linkedin')) socialLinksObj.linkedin = link.linkUrl;
          else if (name.includes('twitter')) socialLinksObj.twitter = link.linkUrl;
          else if (name.includes('github')) socialLinksObj.github = link.linkUrl;
        });
      }
      profileForm.reset({
        name: profileData.name,
        phone: profileData.phone || "",
        position: profileData.position || "",
        avatar: profileData.avatar || "",
        address: profileData.address || {
          street: "",
          city: "",
          state: "",
          country: "",
          zipCode: "",
        },
        socialLinks: socialLinksObj,
      })
    }
  }, [profileData, profileForm])

  if (!profileData && isLoading) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Tab Navigation */}
      <div className="border-b border-border">
        <nav className="flex" aria-label="Tabs">
          {[
            { id: 'overview', name: 'Overview', icon: User },
            { id: 'edit', name: 'Edit Profile', icon: Edit },
            { id: 'security', name: 'Security', icon: Shield }
          ].map((tab) => {
            const Icon = tab.icon
            return (
              <div className="flex-1" key={tab.id}>
                <button
                  onClick={() => setActiveTab(tab.id as any)}
                  className={cn(
                    "w-full text-center whitespace-nowrap py-2 px-1 border-b-2 font-medium text-sm transition-colors",
                    activeTab === tab.id
                      ? "border-primary text-primary"
                      : "border-transparent text-muted-foreground hover:text-foreground hover:border-border"
                  )}
                >
                  <div className="flex items-center justify-center gap-2">
                    <Icon className="h-4 w-4" />
                    {tab.name}
                  </div>
                </button>
              </div>
            )
          })}
        </nav>
      </div>

      {/* Alert Messages */}
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {success && (
        <Alert>
          <AlertDescription>{success}</AlertDescription>
        </Alert>
      )}

      {/* Tab Content */}
      <div className="mt-4">
        {/* Overview Tab */}
        {activeTab === 'overview' && profileData && (
          <div className="space-y-6">
            {/* Profile Header */}
            <div className="flex items-center space-x-6">
              <Avatar className="h-20 w-20">
                {profileData.avatar ? (
                  <AvatarImage src={profileData.avatar} alt={profileData.name} className="object-cover" />
                ) : (
                  <AvatarFallback className="text-lg">
                    {profileData.name ? (() => {
                      const parts = profileData.name.trim().split(' ');
                      if (parts.length === 1) {
                        return parts[0][0].toUpperCase();
                      }
                      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
                    })()
                  : ''}
                  </AvatarFallback>
                )}
              </Avatar>


              <div className="space-y-1">
                <h3 className="text-2xl font-semibold">{profileData.name}</h3>
                <p className="text-muted-foreground">{profileData.email}</p>
                <div className="flex items-center gap-2">
                  <Badge variant={profileData.status === 'active' ? 'default' : 'secondary'}>
                    {profileData.status}
                  </Badge>
                  {profileData.emailVerified && (
                    <Badge variant="outline" className="text-green-600 border-green-600">
                      Email Verified
                    </Badge>
                  )}
                </div>
              </div>
            </div>

            {/* Session Info */}
            <div className="space-y-3">
              <h4 className="text-lg font-medium flex items-center gap-2">
                <Clock className="h-5 w-5" />
                Session Information
              </h4>

              <div className="grid grid-cols-2 gap-3">
                {/* Current Session Duration - Real Time */}
                <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                  <div className="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/20 flex items-center justify-center">
                    <Clock className="w-4 h-4 text-blue-600" />
                  </div>
                  <div className="flex-1">
                    <p className="text-sm font-medium">Current Session</p>
                    <p className="font-mono text-lg text-primary">
                      {formatRealTimeSessionDuration(realTimeSessionDuration)}
                    </p>
                    {/* <div className="flex items-center gap-1 mt-1">
                      <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                      <span className="text-xs text-green-600">Live</span>
                    </div> */}
                  </div>
                </div>

                {/* Session Started */}
                <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                  <div className="w-8 h-8 rounded-full bg-green-100 dark:bg-green-900/20 flex items-center justify-center">
                    <span className="text-green-600 text-sm">🔑</span>
                  </div>
                  <div className="flex-1">
                    <p className="text-sm font-medium">Session Started</p>
                    <p className="text-xs text-muted-foreground">
                      {sessionStartTimeRef.current
                        ? formatDate(sessionStartTimeRef.current)
                        : (profileData.sessionStartTime ? formatDate(profileData.sessionStartTime) : formatDate(new Date()))
                      }
                    </p>
                  </div>
                </div>

                {/* Last Login */}
                <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                  <div className="w-8 h-8 rounded-full bg-purple-100 dark:bg-purple-900/20 flex items-center justify-center">
                    <span className="text-purple-600 text-sm">📅</span>
                  </div>
                  <div className="flex-1">
                    <p className="text-sm font-medium">Last Login</p>
                    <p className="text-xs text-muted-foreground">
                      {profileData.lastLogin ? formatDate(profileData.lastLogin) : "Never"}
                    </p>
                  </div>
                </div>

                {/* Profile Updated */}
                <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                  <div className="w-8 h-8 rounded-full bg-orange-100 dark:bg-orange-900/20 flex items-center justify-center">
                    <span className="text-orange-600 text-sm">✏️</span>
                  </div>
                  <div className="flex-1">
                    <p className="text-sm font-medium">Profile Updated</p>
                    <p className="text-xs text-muted-foreground">{formatDate(profileData.updatedAt)}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Basic Information */}
            <div className="space-y-4">
              <h4 className="text-lg font-medium">Basic Information</h4>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Position</label>
                  <p className="mt-1">{profileData.position || "Not specified"}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Phone</label>
                  <p className="mt-1">{profileData.phone || "Not specified"}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Department</label>
                  <p className="mt-1">{profileData.department?.name || "Not assigned"}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Role</label>
                  <p className="mt-1">{profileData.role?.displayName || profileData.role?.name || "Not assigned"}</p>
                </div>
              </div>
            </div>

            {/* Address & Social Links */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Address */}
              <div className="space-y-3">
                <h4 className="text-lg font-medium flex items-center gap-2">
                  <MapPin className="h-5 w-5" />
                  Address
                </h4>
                <div className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
                  {profileData.address?.street && <p>{profileData.address.street}</p>}
                  {(profileData.address?.city || profileData.address?.state) && (
                    <p>
                      {profileData.address.city}
                      {profileData.address.city && profileData.address.state && ", "}
                      {profileData.address.state}
                    </p>
                  )}
                  {profileData.address?.country && <p>{profileData.address.country}</p>}
                  {profileData.address?.zipCode && <p>{profileData.address.zipCode}</p>}
                  {!Object.values(profileData.address || {}).some(v => v) && (
                    <p className="text-muted-foreground">No address specified</p>
                  )}
                </div>
              </div>

              {/* Social Links */}
              <div className="space-y-3">
                <h4 className="text-lg font-medium flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  Social Links
                </h4>
                <div className="space-y-2">
                  {profileData.socialLinks?.linkedin && (
                    <div className="flex items-center gap-2 p-2 bg-gray-50 dark:bg-gray-800 rounded-lg">
                      <Linkedin className="h-4 w-4 text-blue-600" />
                      <a href={profileData.socialLinks.linkedin} target="_blank" rel="noopener noreferrer"
                        className="text-blue-600 hover:underline text-sm truncate">
                        LinkedIn
                      </a>
                    </div>
                  )}
                  {profileData.socialLinks?.twitter && (
                    <div className="flex items-center gap-2 p-2 bg-gray-50 dark:bg-gray-800 rounded-lg">
                      <Twitter className="h-4 w-4 text-blue-400" />
                      <a href={profileData.socialLinks.twitter} target="_blank" rel="noopener noreferrer"
                        className="text-blue-400 hover:underline text-sm truncate">
                        Twitter
                      </a>
                    </div>
                  )}
                  {profileData.socialLinks?.github && (
                    <div className="flex items-center gap-2 p-2 bg-gray-50 dark:bg-gray-800 rounded-lg">
                      <Github className="h-4 w-4" />
                      <a href={profileData.socialLinks.github} target="_blank" rel="noopener noreferrer"
                        className="hover:underline text-sm truncate">
                        GitHub
                      </a>
                    </div>
                  )}
                  {!Object.values(profileData.socialLinks || {}).some(v => v) && (
                    <p className="text-muted-foreground text-sm p-2">No social links specified</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Edit Profile Tab */}
        {activeTab === 'edit' && profileData && (
          <form onSubmit={profileForm.handleSubmit(onProfileSubmit)} className="space-y-6">
            {/* Basic Information */}
            <Card>
              <CardHeader>
                <CardTitle>Basic Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2 col-span-2 flex flex-col">
                    <Label htmlFor="avatar">Avatar</Label>
                    <ImageUploader
                      value={profileForm.watch('avatar')}
                      onChange={(url) => {
                        profileForm.setValue('avatar', url || '')
                      }}
                      onUploadSuccess={(url) => {
                        // This is where the session should be updated
                        change_state(url)
                      }}
                      db_model="users"  // Make sure this matches your User model name
                      documentId={profileData.id}
                      size="lg"
                      className="mx-auto"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="name">Name *</Label>
                    <Input
                      id="name"
                      {...profileForm.register("name")}
                      className={profileForm.formState.errors.name ? "border-destructive" : ""}
                    />
                    {profileForm.formState.errors.name && (
                      <p className="text-sm text-destructive">{profileForm.formState.errors.name.message}</p>
                    )}
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="phone">Phone</Label>
                    <Input
                      id="phone"
                      {...profileForm.register("phone")}
                      className={profileForm.formState.errors.phone ? "border-destructive" : ""}
                    />
                    {profileForm.formState.errors.phone && (
                      <p className="text-sm text-destructive">{profileForm.formState.errors.phone.message}</p>
                    )}
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="position">Position</Label>
                    <Input
                      id="position"
                      {...profileForm.register("position")}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="avatar">Avatar URL</Label>
                    <Input
                      id="avatar"
                      {...profileForm.register("avatar")}
                      className={profileForm.formState.errors.avatar ? "border-destructive" : ""}
                    />
                    {profileForm.formState.errors.avatar && (
                      <p className="text-sm text-destructive">{profileForm.formState.errors.avatar.message}</p>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Address */}
            <Card>
              <CardHeader>
                <CardTitle>Address</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="street">Street</Label>
                  <Input
                    id="street"
                    {...profileForm.register("address.street")}
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="city">City</Label>
                    <Input
                      id="city"
                      {...profileForm.register("address.city")}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="state">State</Label>
                    <Input
                      id="state"
                      {...profileForm.register("address.state")}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="country">Country</Label>
                    <Input
                      id="country"
                      {...profileForm.register("address.country")}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="zipCode">Zip Code</Label>
                    <Input
                      id="zipCode"
                      {...profileForm.register("address.zipCode")}
                    />
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Social Links */}
            <Card>
              <CardHeader>
                <CardTitle>Social Links</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="linkedin">LinkedIn</Label>
                  <Input
                    id="linkedin"
                    {...profileForm.register("socialLinks.linkedin")}
                    placeholder="https://linkedin.com/in/username"
                    className={profileForm.formState.errors.socialLinks?.linkedin ? "border-destructive" : ""}
                  />
                  {profileForm.formState.errors.socialLinks?.linkedin && (
                    <p className="text-sm text-destructive">{profileForm.formState.errors.socialLinks.linkedin.message}</p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="twitter">Twitter</Label>
                  <Input
                    id="twitter"
                    {...profileForm.register("socialLinks.twitter")}
                    placeholder="https://twitter.com/username"
                    className={profileForm.formState.errors.socialLinks?.twitter ? "border-destructive" : ""}
                  />
                  {profileForm.formState.errors.socialLinks?.twitter && (
                    <p className="text-sm text-destructive">{profileForm.formState.errors.socialLinks.twitter.message}</p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="github">GitHub</Label>
                  <Input
                    id="github"
                    {...profileForm.register("socialLinks.github")}
                    placeholder="https://github.com/username"
                    className={profileForm.formState.errors.socialLinks?.github ? "border-destructive" : ""}
                  />
                  {profileForm.formState.errors.socialLinks?.github && (
                    <p className="text-sm text-destructive">{profileForm.formState.errors.socialLinks.github.message}</p>
                  )}
                </div>
              </CardContent>
            </Card>

            <div className="flex justify-end space-x-3 pt-4 border-t border-border">
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  profileForm.reset()
                  setIsEditing(false)
                }}
                className="border-border hover:bg-secondary"
              >
                Cancel
              </Button>
              <Button type="submit" disabled={isLoading}>
                {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                <Save className="mr-2 h-4 w-4" />
                Save Changes
              </Button>
            </div>
          </form>
        )}

        {/* Security Tab */}
        {activeTab === 'security' && profileData && (
          <div className="space-y-6">
            {/* Security Status */}
            <div className="space-y-4">
              <h4 className="text-lg font-medium">Security Status</h4>

              <div className="space-y-3">
                {/* Email Verification Status */}
                <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                  <div className={cn(
                    "w-8 h-8 rounded-full flex items-center justify-center",
                    profileData.emailVerified
                      ? "bg-green-100 dark:bg-green-900/20"
                      : "bg-yellow-100 dark:bg-yellow-900/20"
                  )}>
                    <span className={cn(
                      "text-sm",
                      profileData.emailVerified ? "text-green-600" : "text-yellow-600"
                    )}>
                      {profileData.emailVerified ? "✓" : "⚠"}
                    </span>
                  </div>
                  <div className="flex-1">
                    <p className="text-sm font-medium">
                      Email {profileData.emailVerified ? 'Verified' : 'Not Verified'}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {profileData.emailVerified
                        ? 'Email address has been verified'
                        : 'Email verification required'
                      }
                    </p>
                  </div>
                </div>

                {/* Phone Verification Status */}
                <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                  <div className={cn(
                    "w-8 h-8 rounded-full flex items-center justify-center",
                    profileData.phoneVerified
                      ? "bg-green-100 dark:bg-green-900/20"
                      : "bg-gray-100 dark:bg-gray-900/20"
                  )}>
                    <span className={cn(
                      "text-sm",
                      profileData.phoneVerified ? "text-green-600" : "text-gray-600"
                    )}>
                      {profileData.phoneVerified ? "✓" : "○"}
                    </span>
                  </div>
                  <div className="flex-1">
                    <p className="text-sm font-medium">
                      Phone {profileData.phoneVerified ? 'Verified' : 'Not Verified'}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {profileData.phoneVerified
                        ? 'Phone number has been verified'
                        : 'Phone verification optional'
                      }
                    </p>
                  </div>
                </div>

                {/* Two-Factor Authentication */}
                <div className="flex items-center space-x-3 p-3 bg-card rounded-lg border">
                  <div className={cn(
                    "w-8 h-8 rounded-full flex items-center justify-center",
                    profileData.twoFactorEnabled
                      ? "bg-green-100 dark:bg-green-900/20"
                      : "bg-gray-100 dark:bg-gray-900/20"
                  )}>
                    <span className={cn(
                      "text-sm",
                      profileData.twoFactorEnabled ? "text-green-600" : "text-gray-600"
                    )}>
                      {profileData.twoFactorEnabled ? "🔒" : "🔓"}
                    </span>
                  </div>
                  <div className="flex-1">
                    <p className="text-sm font-medium">
                      Two-Factor Authentication {profileData.twoFactorEnabled ? 'Enabled' : 'Disabled'}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {profileData.twoFactorEnabled
                        ? 'Account secured with 2FA'
                        : 'Enable 2FA for additional security'
                      }
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Change Password */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Key className="h-5 w-5" />
                  Change Password
                </CardTitle>
                <CardDescription>
                  Update your password to keep your account secure
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={passwordForm.handleSubmit(onPasswordSubmit)} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="currentPassword">Current Password</Label>
                    <div className="relative">
                      <Input
                        id="currentPassword"
                        type={showPasswords.current ? "text" : "password"}
                        {...passwordForm.register("currentPassword")}
                        className={passwordForm.formState.errors.currentPassword ? "border-destructive pr-10" : "pr-10"}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                        onClick={() => setShowPasswords(prev => ({ ...prev, current: !prev.current }))}
                      >
                        {showPasswords.current ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                    {passwordForm.formState.errors.currentPassword && (
                      <p className="text-sm text-destructive">{passwordForm.formState.errors.currentPassword.message}</p>
                    )}
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="newPassword">New Password</Label>
                    <div className="relative">
                      <Input
                        id="newPassword"
                        type={showPasswords.new ? "text" : "password"}
                        {...passwordForm.register("newPassword")}
                        className={passwordForm.formState.errors.newPassword ? "border-destructive pr-10" : "pr-10"}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                        onClick={() => setShowPasswords(prev => ({ ...prev, new: !prev.new }))}
                      >
                        {showPasswords.new ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                    {passwordForm.formState.errors.newPassword && (
                      <p className="text-sm text-destructive">{passwordForm.formState.errors.newPassword.message}</p>
                    )}
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="confirmPassword">Confirm New Password</Label>
                    <div className="relative">
                      <Input
                        id="confirmPassword"
                        type={showPasswords.confirm ? "text" : "password"}
                        {...passwordForm.register("confirmPassword")}
                        className={passwordForm.formState.errors.confirmPassword ? "border-destructive pr-10" : "pr-10"}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                        onClick={() => setShowPasswords(prev => ({ ...prev, confirm: !prev.confirm }))}
                      >
                        {showPasswords.confirm ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                    {passwordForm.formState.errors.confirmPassword && (
                      <p className="text-sm text-destructive">{passwordForm.formState.errors.confirmPassword.message}</p>
                    )}
                  </div>

                  <Button type="submit" disabled={isLoading}>
                    {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Change Password
                  </Button>
                </form>
              </CardContent>
            </Card>
          </div>
        )}

      </div>
    </div>
  )
}