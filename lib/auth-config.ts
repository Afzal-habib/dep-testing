import CredentialsProvider from "next-auth/providers/credentials"
import GoogleProvider from "next-auth/providers/google" // NEW: Import GoogleProvider
import { MongoDBAdapter } from "@auth/mongodb-adapter"
import { MongoClient } from "mongodb"
import { executeGenericDbQuery } from "@/lib/mongodb"
import User from "@/models/User"
import { loginSchema } from "@/lib/validations/auth"
import { AuditLogger } from "@/lib/security/audit-logger"
import { SecurityUtils } from "@/lib/security/validation"

// Import models to ensure registration
import "@/lib/models"
import { registerModels } from "@/lib/models"

const client = new MongoClient(process.env.MONGODB_URI!)
const clientPromise = Promise.resolve(client)

export const authOptions = {
  // Remove adapter to allow account linking - we'll handle user management manually
  // adapter: MongoDBAdapter(clientPromise),
  // Allow account linking for same email addresses
  allowDangerousEmailAccountLinking: true,
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials, req) {
        try {
          // Ensure models are registered
          await registerModels()

          if (!credentials?.email || !credentials?.password) {
            throw new Error("Email and password are required")
          }

          // Apply rate limiting (if applyRateLimit is available)
          try {
            const { applyRateLimit } = await import("@/lib/security/rate-limiter")
            const mockRequest = {
              ip: req?.headers?.['x-forwarded-for'] as string || "unknown",
              headers: req?.headers || {},
            } as any

            const rateLimitResponse = await applyRateLimit(mockRequest, "auth")
            if (rateLimitResponse) {
              // Rate limit exceeded - NextResponse object is returned
              throw new Error("Too many login attempts. Please wait before trying again.")
            }
          } catch (rateLimitError: any) {
            // If it's a rate limit error, re-throw it
            if (rateLimitError.message && rateLimitError.message.includes("Too many")) {
              throw rateLimitError
            }
            // If rate limiting fails for other reasons, continue with authentication but log the error
            console.warn("Rate limiting check failed:", rateLimitError)
          }

          // Validate input with security checks
          const validatedFields = loginSchema.safeParse(credentials)
          if (!validatedFields.success) {
            throw new Error("Invalid credentials format")
          }

          // Additional input validation
          const emailValidation = SecurityUtils.validateInput(credentials.email, 'email')
          if (!emailValidation.isValid) {
            throw new Error("Invalid email format")
          }

          // Find user with password field and populate role WITH PERMISSIONS
          const user = await executeGenericDbQuery(async () => {
            return await User.findOne({ email: credentials.email.toLowerCase() })
              .select("+password")
              .populate({
                path: 'role',
                select: 'name displayName hierarchyLevel permissions'
              })
              .populate('department', 'name')
          })
          console.log("Auth attempt for user:83", user)

          if (!user) {
            // Log failed login attempt
            await AuditLogger.logFailedLogin({
              email: credentials.email,
              ipAddress: req?.headers?.['x-forwarded-for'] as string || "unknown",
              userAgent: req?.headers?.['user-agent'] as string || "unknown",
              errorMessage: "User not found",
            })
            throw new Error("Invalid credentials")
          }

          // Ensure role is populated - fallback if needed
          if (!user.role) {
            console.warn(`User ${user.email} has no role assigned, using default`)
          }

          if (!user.status || user.status !== 'active') {
            // Log failed login attempt for deactivated user
            await AuditLogger.logFailedLogin({
              email: credentials.email,
              ipAddress: req?.headers?.['x-forwarded-for'] as string || "unknown",
              userAgent: req?.headers?.['user-agent'] as string || "unknown",
              errorMessage: "Account deactivated",
            })
            throw new Error("Account is deactivated")
          }

          // Check password
          const isPasswordValid = await user.comparePassword(credentials.password)

          if (!isPasswordValid) {
            // Log failed login attempt
            await AuditLogger.logFailedLogin({
              email: credentials.email,
              ipAddress: req?.headers?.['x-forwarded-for'] as string || "unknown",
              userAgent: req?.headers?.['user-agent'] as string || "unknown",
              errorMessage: "Invalid password",
            })
            throw new Error("Invalid credentials")
          }

          // Extract permissions from populated role during login
          let userPermissions: any[] = []
          if (user.role && (user.role as any).permissions) {
            userPermissions = (user.role as any).permissions.map((permission: any) => ({
              resource: permission.resource,
              actions: permission.actions || [],
              conditions: permission.conditions || {}
            }))
          }

          // Check if 2FA is enabled for this user
          if (user.twoFactorEnabled) {
            // Reset 2FA verification status for new login attempt
            await executeGenericDbQuery(async () => {
              await User.findByIdAndUpdate(user._id, {
                twoFactorVerified: false
              })
            })

            // Require 2FA verification
            return {
              id: (user._id as any).toString(),
              name: user.name,
              email: user.email,
              role: user.role ? (user.role as any).name : 'user',
              roleDisplayName: user.role ? (user.role as any).displayName : 'User',
              department: user.department ? (user.department as any).name : null,
              avatar: user.avatar,
              permissions: userPermissions,
              requiresTwoFactor: true, // Flag to indicate 2FA is needed
              twoFactorVerified: false, // Always false for new login attempts
              _id: user._id // Include the MongoDB _id for JWT callback
            }
          }

          // No 2FA required - complete login immediately
          // Log successful login
          await AuditLogger.logUserLogin({
            userId: (user._id as any).toString(),
            userEmail: user.email,
            ipAddress: req?.headers?.['x-forwarded-for'] as string || "unknown",
            userAgent: req?.headers?.['user-agent'] as string || "unknown",
            success: true,
          })

          return {
            id: (user._id as any).toString(),
            name: user.name,
            email: user.email,
            role: user.role ? (user.role as any).name : 'user',
            roleDisplayName: user.role ? (user.role as any).displayName : 'User',
            department: user.department ? (user.department as any).name : null,
            avatar: user.avatar,
            permissions: userPermissions,
            requiresTwoFactor: false, // No 2FA needed
            twoFactorVerified: true, // Skip 2FA
            _id: user._id // Include the MongoDB _id for JWT callback
          }

          // Note: We don't log successful login here anymore since 2FA is required
          // The login will be logged after successful 2FA verification
        } catch (error: any) {
          console.error("Auth error:", error.message)
          // Ensure we return a clean error message without exposing internal details
          if (error.message.includes("Too many")) {
            throw new Error("Too many login attempts. Please wait before trying again.")
          } else if (error.message.includes("rate limit")) {
            throw new Error("Too many login attempts. Please wait before trying again.")
          } else if (error.message.includes("deactivated")) {
            throw new Error("Account is deactivated")
          } else if (error.message.includes("Invalid")) {
            throw new Error("Invalid credentials")
          } else {
            throw new Error("Authentication failed")
          }
        }
      },
    }),
    // NEW: Add GoogleProvider
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      authorization: {
        params: {
          scope: "openid email profile"
        }
      }
    }),
  ],
  session: {
    strategy: "jwt" as const,
    maxAge: 30 * 24 * 60 * 60,
    updateAge: 24 * 60 * 60, // refresh token every 24h
  },
  jwt: {
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  events: {
    async signOut(message: any) {
      // Server-side session cleanup only
      console.log('User signed out:', message?.token?.email || 'unknown')
      // Additional server-side cleanup can be added here if needed
    },
  },
  callbacks: {
    // Simplified signIn callback - let NextAuth handle account linking
    async signIn({ user, account, profile }: any) {
      if (account?.provider === "google") {
        try {
          // Ensure models are registered
          await registerModels()

          const email = profile?.email?.toLowerCase();
          if (!email) {
            console.error("No email provided by Google OAuth");
            return false;
          }

          // Check if user exists in our database and is active
          const existingUser = await executeGenericDbQuery(async () => {
            return await User.findOne({ email });
          });

          if (!existingUser) {
            console.error("User not found for Google OAuth:", email);
            return false;
          }

          if (existingUser.status !== "active") {
            console.error("Account deactivated for Google OAuth:", email);
            return false;
          }

          // Mark user as OAuth for JWT processing
          user.isOAuthUser = true;
          user.authProvider = 'oauth';

          // Log successful Google login
          await AuditLogger.logUserLogin({
            userId: (existingUser._id as any).toString(),
            userEmail: existingUser.email,
            ipAddress: "unknown",
            userAgent: "unknown",
            success: true,
          });

          return true;
        } catch (error) {
          console.error("Google signIn error:", error);
          return false;
        }
      }
      return true; // Allow other providers (e.g., credentials)
    },
    async jwt({ token, user, trigger, session }: any) {
      // Handle session updates (including avatar changes and 2FA verification)
      if (trigger === "update" && session) {
        console.log('JWT callback - updating session with:', session)

        // Update specific fields from session update
        if (session.avatar !== undefined) {
          token.avatar = session.avatar
          console.log('JWT callback - avatar updated to:', session.avatar)
        }

        // Handle 2FA verification update
        if (session.twoFactorVerified !== undefined) {
          token.twoFactorVerified = session.twoFactorVerified
          console.log('JWT callback - 2FA verified updated to:', session.twoFactorVerified)
        }

        // Merge any other user data updates
        if (session.user) {
          token.user = { ...token.user, ...session.user }
        }

        return token
      }

      if (user) {
        console.log('JWT callback - processing user:', {
          email: user.email,
          id: user.id,
          isOAuth: user.isOAuthUser,
          authProvider: user.authProvider,
          hasPermissions: !!user.permissions,
          permissionsCount: user.permissions ? user.permissions.length : 0,
          hasRole: !!user.role,
          roleName: user.role ? (typeof user.role === 'object' ? (user.role as any).name : user.role) : null,
          roleType: typeof user.role,
          userKeys: Object.keys(user)
        });        // Handle both credentials and OAuth providers
        let fullUser = user;

        // Validate user object structure first
        if (!user.email && !user.id) {
          console.error('Invalid user object in JWT callback:', user);
          return token;
        }

        // For OAuth providers, we need to populate user data from database
        // For credentials providers, user data is already populated by authorize function
        if (user.isOAuthUser || user.authProvider === 'oauth') {
          // OAuth user - fetch from database
          fullUser = await executeGenericDbQuery(async () => {
            if (user.email) {
              return await User.findOne({ email: user.email.toLowerCase() })
                .populate({
                  path: 'role',
                  select: 'name displayName hierarchyLevel permissions'
                })
                .populate('department', 'name');
            }
            return null;
          });

          if (!fullUser) {
            console.error('OAuth user not found in database for JWT:', user.email || user.id);
            return token;
          }
        } else {
          // Credentials user - use data from authorize function (already populated with permissions)
          console.log('Credentials user - using data from authorize function:', {
            email: user.email,
            hasPermissions: !!user.permissions,
            permissionsCount: user.permissions ? user.permissions.length : 0,
            hasRole: !!user.role,
            roleType: typeof user.role
          });

          // For credentials users, the authorize function already populated all necessary data
          // including role and permissions. We should preserve this data.
          fullUser = user;

          // Only fetch 2FA data if missing (don't refetch role/permissions)
          if (!user.hasOwnProperty('requiresTwoFactor') || !user.hasOwnProperty('twoFactorVerified')) {
            console.warn('Credentials user missing 2FA data, fetching from database:', user.email);
            const dbUser = await executeGenericDbQuery(async () => {
              if (user.email) {
                return await User.findOne({ email: user.email.toLowerCase() })
                  .select('twoFactorEnabled twoFactorVerified')
              }
              return null;
            });

            if (dbUser) {
              // Only merge 2FA settings, don't override permissions/role
              fullUser.requiresTwoFactor = dbUser.twoFactorEnabled || false;
              fullUser.twoFactorVerified = fullUser.twoFactorVerified ?? (dbUser.twoFactorEnabled ? false : true);
              console.log('Updated 2FA settings from DB - requiresTwoFactor:', fullUser.requiresTwoFactor, 'twoFactorVerified:', fullUser.twoFactorVerified);
            } else {
              // Default values if user not found
              fullUser.requiresTwoFactor = false;
              fullUser.twoFactorVerified = true;
            }
          }
        }

        // Ensure fullUser has required properties (handle both _id and id)
        const userId = fullUser?._id || fullUser?.id;
        if (!fullUser || !userId) {
          console.error('User or user ID missing in JWT callback for:', fullUser?.email || 'unknown user');
          return token;
        }

        // Extract permissions from populated role or use existing permissions
        let userPermissions: any[] = [];
        let roleObj: any = null;

        if (fullUser.role && (fullUser.role as any).permissions) {
          // Role has embedded permissions (not referenced)
          userPermissions = (fullUser.role as any).permissions.map((permission: any) => ({
            resource: permission.resource,
            actions: permission.actions || [],
            conditions: permission.conditions || {}
          }));

          // Store complete role object for consistent structure
          roleObj = {
            name: (fullUser.role as any).name,
            displayName: (fullUser.role as any).displayName,
            hierarchyLevel: (fullUser.role as any).hierarchyLevel,
            permissions: userPermissions
          };

          console.log('JWT callback - extracted permissions from role:', {
            roleName: roleObj.name,
            permissionCount: userPermissions.length,
            permissions: userPermissions,
            authProvider: user.authProvider || user.isOAuthUser ? 'oauth' : 'credentials'
          });
        } else if (fullUser.permissions && Array.isArray(fullUser.permissions)) {
          // Use existing permissions from user object (credentials flow)
          userPermissions = fullUser.permissions;

          // For credentials flow, construct role object from existing data
          if (fullUser.role) {
            roleObj = {
              name: typeof fullUser.role === 'string' ? fullUser.role : (fullUser.role as any).name,
              displayName: typeof fullUser.role === 'object' ? (fullUser.role as any).displayName : 'User',
              hierarchyLevel: typeof fullUser.role === 'object' ? (fullUser.role as any).hierarchyLevel : 1,
              permissions: userPermissions
            };
          } else {
            roleObj = {
              name: 'user',
              displayName: 'User',
              hierarchyLevel: 1,
              permissions: userPermissions
            };
          }

          console.log('JWT callback - using existing user permissions:', {
            permissionCount: userPermissions.length,
            permissions: userPermissions,
            authProvider: user.authProvider || user.isOAuthUser ? 'oauth' : 'credentials',
            constructedRole: roleObj
          });
        } else {
          console.warn('JWT callback - no permissions found for user:', {
            email: fullUser.email,
            hasRole: !!fullUser.role,
            roleType: typeof fullUser.role,
            roleName: fullUser.role ? (fullUser.role as any).name : null,
            hasUserPermissions: !!fullUser.permissions
          });

          // Fallback role object
          roleObj = {
            name: fullUser.role ? (typeof fullUser.role === 'string' ? fullUser.role : (fullUser.role as any).name) : 'user',
            displayName: fullUser.role ? (typeof fullUser.role === 'object' ? (fullUser.role as any).displayName : 'User') : 'User',
            hierarchyLevel: fullUser.role ? (typeof fullUser.role === 'object' ? (fullUser.role as any).hierarchyLevel : 1) : 1,
            permissions: []
          };
        }

        token.user = fullUser;
        token.sub = userId.toString(); // Set the user ID for session (handles both _id and id)
        token.role = roleObj.name;
        token.roleDisplayName = roleObj.displayName;
        token.roleObject = roleObj; // Store complete role object
        token.department = fullUser.department ? (fullUser.department as any).name : null;
        token.avatar = fullUser.avatar;
        token.permissions = userPermissions;
        token.sessionStartTime = Date.now();

        console.log('🔧 JWT token being set:', {
          email: fullUser.email,
          role: token.role,
          department: token.department,
          roleObject: roleObj,
          permissionCount: userPermissions.length,
          isSuperAdmin: token.role === 'super_admin',
          permissions: userPermissions
        });

        // Handle 2FA based on authentication method
        if (user.isOAuthUser || user.authProvider === 'oauth') {
          // OAuth user - skip 2FA completely
          token.authProvider = 'oauth';
          token.requiresTwoFactor = false; // Always skip 2FA for OAuth
          token.twoFactorVerified = true;  // Always verified for OAuth
          console.log('OAuth user detected - skipping 2FA');
        } else {
          // Credentials user - follow 2FA settings from authorize function or database
          token.authProvider = 'credentials';

          // Use requiresTwoFactor from user object (set by authorize function) or fallback to twoFactorEnabled
          const requires2FA = fullUser.requiresTwoFactor ?? (fullUser.twoFactorEnabled ?? false);
          const is2FAVerified = fullUser.twoFactorVerified ?? (!requires2FA);

          token.requiresTwoFactor = requires2FA;
          token.twoFactorVerified = is2FAVerified;

          console.log('Credentials user detected - 2FA required:', requires2FA, 'verified:', is2FAVerified, 'from fullUser.twoFactorEnabled:', fullUser.twoFactorEnabled);
        }
      }
      return token;
    },

    async session({ session, token }: { session: any; token: any }) {
      if (token) {
        session.user = {
          ...(session.user || {}),
          id: token.sub,
          role: token.role || token.roleObject, // Use role object when available, fallback to role string
          roleDisplayName: token.roleDisplayName,
          department: token.department || token.user.department,
          avatar: token.avatar,
          permissions: token.permissions || [],
          requiresTwoFactor: token.requiresTwoFactor || false,
          twoFactorVerified: token.twoFactorVerified || false,
          sessionStartTime: token.sessionStartTime,
          iat: token.iat,
        };

        // Server-side session management only - no client-side storage
        // All user data is maintained in the JWT token and database
        // console.log('token user 524:', token);
        // console.log('session user 525:', session.user);
        // console.log('🔧 Session being returned:', {
        //   email: session.user?.email,
        //   role: session.user?.role,
        //   roleType: typeof session.user?.role,
        //   roleName: typeof session.user?.role === 'object' ? session.user.role.name : session.user?.role,
        //   permissionCount: session.user?.permissions?.length || 0,
        //   hasPermissions: !!session.user?.permissions
        // });
      }

      return session
    },
  },
  pages: {
    signIn: "/auth/login",
    error: "/auth/error",
  },
  secret: process.env.NEXTAUTH_SECRET,
}