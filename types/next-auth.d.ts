declare module "next-auth" {
  interface Session {
    user: {
      id: string
      name: string
      email: string
      role: string
      roleDisplayName: string
      department: string
      avatar?: string
      permissions: any[]
      sessionStartTime: number
      iat?: number
      requiresTwoFactor?: boolean
      twoFactorVerified?: boolean
    }
  }

  interface User {
    id: string
    name: string
    email: string
    role: string
    roleDisplayName: string
    department: string
    avatar?: string
    permissions: any[]
    requiresTwoFactor?: boolean
    twoFactorVerified?: boolean
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    role: string
    roleDisplayName: string
    department: string
    avatar?: string
    permissions: any[]
    sessionStartTime: number
    requiresTwoFactor?: boolean
    twoFactorVerified?: boolean
  }
}
