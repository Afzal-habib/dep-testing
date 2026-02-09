# Complete Request Lifecycle Guide - Digi Era Pro CRM Permission System

## Table of Contents
1. [Overview](#overview)
2. [Authentication Flow](#authentication-flow)
3. [Permission System Architecture](#permission-system-architecture)
4. [Request Lifecycle Stages](#request-lifecycle-stages)
5. [API Endpoint Protection](#api-endpoint-protection)
6. [UI Route Protection](#ui-route-protection)
7. [Component-Level Protection](#component-level-protection)
8. [Real-world Examples](#real-world-examples)
9. [Security Features](#security-features)
10. [Troubleshooting](#troubleshooting)

---

## Overview

The Digi Era Pro CRM system implements a **multi-layered security architecture** with dynamic role-based permissions. Every request goes through multiple validation stages to ensure users can only access resources they're authorized for.

### Key Components:
- **NextAuth.js** for authentication
- **Dynamic Role System** with granular permissions
- **Multi-tier Middleware** (Rate limiting + Auth + Permissions)
- **Client-side Route Guards**
- **Component-level Permission Checks**

---

## Authentication Flow

### 1. Login Process (`/auth/login`)

```typescript
// User Login → NextAuth.js handles authentication
POST /api/auth/signin/credentials
{
  "email": "user@company.com",
  "password": "password123"
}
```

**Authentication Steps:**
1. Credentials validated against MongoDB
2. User role and permissions fetched from database
3. JWT session created with user data and permissions
4. Session stored in secure cookie

### 2. Session Structure

```typescript
interface Session {
  user: {
    id: string
    name: string
    email: string
    role: string
    permissions: Permission[] // Dynamic permissions array
    department: string
  }
  expires: string
}

interface Permission {
  resource: string        // e.g., 'users', 'roles', 'departments'
  actions: string[]      // e.g., ['read', 'create', 'update']
  conditions: {
    own?: boolean         // Can access own records
    department?: boolean  // Can access department records
    assigned?: boolean    // Can access assigned records
    subordinates?: boolean // Can access subordinates' records
  }
}
```

---

## Permission System Architecture

### Core Permission Types

| Resource | Actions | Description |
|----------|---------|-------------|
| `dashboard` | `read` | Dashboard access |
| `users` | `create`, `read`, `update`, `delete`, `assign` | User management |
| `roles` | `create`, `read`, `update`, `delete`, `assign` | Role management |
| `departments` | `create`, `read`, `update`, `delete` | Department management |
| `system-permissions` | `create`, `read`, `update`, `delete` | System permission management |
| `system-monitoring` | `read` | Security monitoring access |

### Sample User Permissions

```typescript
// HR Manager Permissions
const hrManagerPermissions = [
  {
    resource: "dashboard",
    actions: ["read"],
    conditions: {}
  },
  {
    resource: "users",
    actions: ["create", "read", "update"],
    conditions: { department: true }
  },
  {
    resource: "roles",
    actions: ["read"],
    conditions: {}
  }
]
```

---

## Request Lifecycle Stages

### Stage 1: Initial Request
```
User clicks "Users" in sidebar → Browser makes request to /users
```

### Stage 2: Middleware (Next.js Route Middleware)
```typescript
// middleware.ts - UI Route Security Headers
export default function middleware(req: NextRequest) {
  // Applies security headers to UI routes
  // API routes handle their own security
  if (pathname.includes('/auth/') || pathname.includes('/dashboard/')) {
    // IP validation for sensitive routes
    // Security headers application
  }
}
```

### Stage 3: Client-Side Route Protection
```typescript
// admin-layout.tsx - Route Guard
<RouteGuard resource="users" action="read" showErrorPage={true}>
  {children}
</RouteGuard>
```

### Stage 4: Component Rendering
```typescript
// Page component loads and makes API calls
const UsersPage = () => {
  const { data, loading, error } = useQuery('/api/users')
  // Component renders based on permissions
}
```

### Stage 5: API Request Protection
```typescript
// /api/users/route.ts - API Endpoint Protection
export async function GET(request: NextRequest) {
  // Triple-layer protection:
  const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'users', 'read')
  // 1. Rate limiting
  // 2. Authentication check
  // 3. Permission validation
}
```

---

## API Endpoint Protection

### Ultra-Generic Middleware Usage

Every API endpoint uses the `genericApiRoutesMiddleware` function for comprehensive protection:

```typescript
import { genericApiRoutesMiddleware } from '@/lib/middleware/route-middleware'

// GET /api/users - List users
export async function GET(request: NextRequest) {
  try {
    // ✨ ONE LINE DOES EVERYTHING:
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'users', 'read')
    
    // Your business logic here...
    const users = await User.find({})
    
    return NextResponse.json({ success: true, data: users })
  } catch (error: any) {
    return NextResponse.json({ 
      success: false, 
      error: error.message 
    }, { status: error.status || 500 })
  }
}

// POST /api/users - Create user
export async function POST(request: NextRequest) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'users', 'create')
    
    const body = await request.json()
    const newUser = await User.create(body)
    
    return NextResponse.json({ success: true, data: newUser })
  } catch (error: any) {
    return NextResponse.json({ 
      success: false, 
      error: error.message 
    }, { status: error.status || 500 })
  }
}
```

### What `genericApiRoutesMiddleware` Does Automatically:

1. **Rate Limiting** - Prevents abuse
   - `read` operations → API rate limit (100 req/min)
   - `create/update/delete` → Sensitive rate limit (20 req/min)
   - `login/auth` → Auth rate limit (5 req/min)

2. **Authentication Check** - Validates session
   - Checks NextAuth.js session
   - Validates JWT token
   - Fetches user data

3. **Permission Validation** - Checks resource access
   - Matches user permissions against required resource+action
   - Handles super admin bypass
   - Logs security events

### API Protection Examples

```typescript
// Different resource operations
const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'roles', 'create')
const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'departments', 'update')
const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'system-permissions', 'read')
const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'system-monitoring', 'read')
```

---

## UI Route Protection

### 1. Admin Layout with Route Guards

```typescript
// components/layout/admin-layout.tsx
export function AdminLayout({ children }: AdminLayoutProps) {
  const pathname = usePathname()
  
  const getResourceAndAction = (path: string) => {
    const segments = path.split('/').filter(Boolean)
    
    if (segments.length === 0) {
      return { resource: 'dashboard', action: 'read' }
    }
    
    const resource = segments[0] || 'dashboard'
    let action = 'read'
    
    if (segments.includes('add')) {
      action = 'create'
    } else if (segments.includes('edit')) {
      action = 'update'
    }
    
    return { resource, action }
  }
  
  const { resource, action } = getResourceAndAction(pathname)

  return (
    <AuthGuard>
      <div className="flex min-h-screen bg-background">
        <Sidebar />
        <div className="flex flex-1 flex-col min-w-0">
          <Header />
          <main className="flex-1 overflow-y-auto p-4 lg:p-6">
            <RouteGuard resource={resource} action={action} showErrorPage={true}>
              {children}
            </RouteGuard>
          </main>
        </div>
      </div>
    </AuthGuard>
  )
}
```

### 2. Route Guard Component

```typescript
// components/auth/route-guard.tsx
export function RouteGuard({ 
  children, 
  resource, 
  action = 'read',
  showErrorPage = true 
}: RouteGuardProps) {
  const { hasPermission, loading } = usePermissions()
  
  if (loading) {
    return <ProfessionalLoader
          size="md"
        />
  }

  if (!hasPermission(resource, action)) {
    if (showErrorPage) {
      return (
        <PermissionError
          resource={resource}
          action={action}
          onRetry={() => window.location.reload()}
        />
      )
    }
    return null
  }

  return <>{children}</>
}
```

### 3. Permission Hook

```typescript
// hooks/use-permissions.ts
export function usePermissions() {
  const { data: session, status } = useSession()
  const [permissions, setPermissions] = useState<Permission[]>([])
  
  const hasPermission = useCallback((resource: string, action: string) => {
    if (status !== 'authenticated') return false
    
    const  sessionUserRole= session?.user?.role.name
    if (sessionUserRole === 'super_admin') return true
    
    return permissions.some(permission =>
      permission.resource === resource &&
      permission.actions.includes(action)
    )
  }, [permissions, session, status])
  
  return {
    hasPermission,
    permissions,
    loading: status === 'loading'
  }
}
```

---

## Component-Level Protection

### 1. Conditional Rendering

```typescript
// components/users/user-actions.tsx
export function UserActions({ user }: { user: User }) {
  const { hasPermission } = usePermissions()
  
  return (
    <div className="flex gap-2">
      {hasPermission('users', 'update') && (
        <Button onClick={() => editUser(user.id)}>
          Edit
        </Button>
      )}
      
      {hasPermission('users', 'delete') && (
        <Button variant="destructive" onClick={() => deleteUser(user.id)}>
          Delete
        </Button>
      )}
      
      {hasPermission('users', 'assign') && (
        <Button onClick={() => assignRole(user.id)}>
          Assign Role
        </Button>
      )}
    </div>
  )
}
```

### 2. Sidebar Menu Protection

```typescript
// components/layout/sidebar.tsx
const menuItems = [
  {
    title: "Dashboard",
    href: "/dashboard",
    icon: LayoutDashboard,
    resource: "dashboard",
    action: "read"
  },
  {
    title: "Users",
    href: "/users",
    icon: Users,
    resource: "users",
    action: "read"
  },
  {
    title: "Roles",
    href: "/roles",
    icon: Shield,
    resource: "roles",
    action: "read"
  }
]

export function Sidebar() {
  const { hasPermission } = usePermissions()
  
  return (
    <nav>
      {menuItems.map(item => (
        hasPermission(item.resource, item.action) && (
          <Link key={item.href} href={item.href}>
            {item.title}
          </Link>
        )
      ))}
    </nav>
  )
}
```

### 3. Form Field Protection

```typescript
// components/users/user-form.tsx
export function UserForm() {
  const { hasPermission } = usePermissions()
  
  return (
    <form>
      <Input name="name" placeholder="Name" />
      <Input name="email" placeholder="Email" />
      
      {hasPermission('users', 'assign') && (
        <Select name="role">
          <option value="user">User</option>
          <option value="manager">Manager</option>
        </Select>
      )}
      
      {hasPermission('users', 'create') ? (
        <Button type="submit">Create User</Button>
      ) : (
        <Button disabled>No Permission</Button>
      )}
    </form>
  )
}
```

---

## Real-world Examples

### Example 1: User Management Workflow

#### 1. User clicks "Users" in sidebar
```typescript
// Sidebar checks permission before showing menu item
hasPermission('users', 'read') // ✅ true for HR Manager
```

#### 2. Browser navigates to `/users`
```typescript
// admin-layout.tsx applies RouteGuard
<RouteGuard resource="users" action="read">
  <UsersPage />
</RouteGuard>
```

#### 3. UsersPage component loads
```typescript
// app/users/page.tsx
export default function UsersPage() {
  const { data, loading, error } = useQuery('/api/users')
  
  return (
    <div>
      <UserList users={data} />
      {hasPermission('users', 'create') && (
        <Button href="/users/add">Add User</Button>
      )}
    </div>
  )
}
```

#### 4. API call to fetch users
```typescript
// app/api/users/route.ts
export async function GET(request: NextRequest) {
  // Triple protection automatically applied
  const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'users', 'read')
  
  // Query users based on permission conditions
  const users = await User.find({
    department: user.department // HR Manager sees only HR users
  })
  
  return NextResponse.json({ success: true, data: users })
}
```

### Example 2: Creating a New Role

#### 1. User navigates to `/roles/add`
```typescript
// RouteGuard checks create permission
<RouteGuard resource="roles" action="create">
  <AddRolePage />
</RouteGuard>
```

#### 2. Form submission
```typescript
// components/roles/role-form.tsx
const handleSubmit = async (data) => {
  try {
    await fetch('/api/roles', {
      method: 'POST',
      body: JSON.stringify(data)
    })
  } catch (error) {
    handleAPIError(error) // Shows user-friendly error
  }
}
```

#### 3. API processes creation
```typescript
// app/api/roles/route.ts
export async function POST(request: NextRequest) {
  const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'roles', 'create')
  
  const body = await request.json()
  const newRole = await Role.create(body)
  
  return NextResponse.json({ success: true, data: newRole })
}
```

---

## Security Features

### 1. Rate Limiting
- **API calls**: 100 requests/minute
- **Sensitive operations**: 20 requests/minute  
- **Authentication**: 5 requests/minute

### 2. IP Validation
- Tracks suspicious IP patterns
- Logs security events
- Automatic threat detection

### 3. Session Security
- Secure JWT tokens
- Automatic session refresh
- Secure cookie settings

### 4. Permission Caching
- Client-side permission caching
- Automatic cache invalidation
- Performance optimization

### 5. Audit Logging
```typescript
// All operations are logged
{
  timestamp: "2025-10-02T10:30:00Z",
  userEmail: "user@company.com",
  resource: "users",
  action: "create",
  success: true,
  ip: "192.168.1.100",
  userAgent: "Mozilla/5.0..."
}
```

---

## Troubleshooting

### Common Issues

#### 1. Permission Denied Errors
```typescript
// Check user permissions in session
console.log(session.user.permissions)

// Verify permission exists in database
const userPermissions = await getUserPermissions(userId)
```

#### 2. Route Access Issues
```typescript
// Debug route mapping
const { resource, action } = getResourceAndAction('/users/add')
console.log({ resource, action }) // { resource: 'users', action: 'create' }
```

#### 3. API Authentication Failures
```typescript
// Test authentication endpoint
GET /api/debug/permissions
// Returns detailed session and permission info
```

### Debug API Endpoint

```typescript
// app/api/debug/permissions/route.ts
export async function GET(request: NextRequest) {
  try {
    const { session, user, userEmail } = await genericApiRoutesMiddleware(request, 'debug', 'read')
    
    return NextResponse.json({
      success: true,
      debug: {
        userEmail,
        userId: user?._id,
        sessionUser: session.user,
        permissionCheck: {
          resource: 'debug',
          action: 'read',
          passed: true
        }
      }
    })
  } catch (error) {
    return NextResponse.json({
      success: false,
      error: error.message,
      debug: {
        errorType: error.constructor.name,
        permissionCheck: {
          resource: 'debug', 
          action: 'read',
          passed: false
        }
      }
    }, { status: error.status || 403 })
  }
}
```

### Testing Permissions

#### 1. Postman Testing
```http
GET {{baseUrl}}/api/debug/permissions
Authorization: Bearer {{sessionToken}}

POST {{baseUrl}}/api/debug/permissions
Content-Type: application/json
{
  "resource": "users",
  "action": "create"
}
```

#### 2. Browser Console Testing
```javascript
// Test client-side permissions
const { hasPermission } = usePermissions()
console.log(hasPermission('users', 'create')) // true/false

// Test API directly
fetch('/api/users')
  .then(res => res.json())
  .then(console.log)
  .catch(console.error)
```

---

## Summary

The Digi Era Pro CRM implements a **comprehensive, multi-layered security system** that protects every aspect of the application:

1. **Authentication** via NextAuth.js with secure sessions
2. **Dynamic Permissions** with granular resource+action control
3. **API Protection** via ultra-generic middleware (`genericApiRoutesMiddleware`)
4. **UI Route Guards** preventing unauthorized page access
5. **Component-level Checks** for fine-grained UI control
6. **Security Monitoring** with audit logs and threat detection

Every request flows through multiple validation layers, ensuring users can only access resources they're explicitly authorized for. The system is designed to be secure by default while remaining developer-friendly with minimal boilerplate code.

---

*This guide covers the complete request lifecycle as implemented in the Digi Era Pro CRM system. For specific implementation details, refer to the source code in the respective files mentioned throughout this document.*