# Supabase Backend Project - Complete Implementation Plan

## Project Overview

Building a secure, scalable, and maintainable backend using Supabase with:
- **Generic CRUD Architecture** - Reusable patterns for all entities
- **Dynamic Role-Based Access Control** - Flexible permissions system
- **Comprehensive Security Layers** - Industry-standard security practices
- **React Frontend** - TypeScript + Tailwind CSS with optimized caching

---

## Table of Contents

1. [Phase 1: Project Setup & Security Foundation](#phase-1-project-setup--security-foundation)
2. [Phase 2: Database Schema & Security Policies](#phase-2-database-schema--security-policies)
3. [Phase 3: Generic CRUD Architecture](#phase-3-generic-crud-architecture)
4. [Phase 4: Dynamic Roles & Permissions System](#phase-4-dynamic-roles--permissions-system)
5. [Phase 5: Users CRUD Implementation](#phase-5-users-crud-implementation)
6. [Phase 6: Department CRUD Implementation](#phase-6-department-crud-implementation)
7. [Phase 7: React Frontend Setup](#phase-7-react-frontend-setup)
8. [Phase 8: Frontend Generic CRUD & State Management](#phase-8-frontend-generic-crud--state-management)
9. [Phase 9: Testing & Optimization](#phase-9-testing--optimization)
10. [Phase 10: Deployment & Monitoring](#phase-10-deployment--monitoring)

---

## Phase 1: Project Setup & Security Foundation

### 1.1 Project Initialization

```bash
# Create project structure
mkdir supabase-backend && cd supabase-backend
npm init -y
supabase init
```

### 1.2 Directory Structure

```
supabase-backend/
├── supabase/
│   ├── config.toml
│   ├── migrations/
│   │   ├── 00001_extensions.sql
│   │   ├── 00002_security_tables.sql
│   │   ├── 00003_roles_permissions.sql
│   │   ├── 00004_users.sql
│   │   ├── 00005_departments.sql
│   │   └── 00006_rls_policies.sql
│   ├── functions/
│   │   ├── _shared/
│   │   │   ├── cors.ts
│   │   │   ├── auth.ts
│   │   │   ├── validation.ts
│   │   │   ├── rate-limiter.ts
│   │   │   ├── error-handler.ts
│   │   │   └── response.ts
│   │   ├── generic-crud/
│   │   │   └── index.ts
│   │   └── webhooks/
│   │       └── index.ts
│   ├── seed.sql
│   └── tests/
├── src/
│   ├── lib/
│   │   ├── supabase.ts
│   │   ├── database.types.ts
│   │   └── constants.ts
│   ├── schemas/
│   │   ├── user.schema.ts
│   │   ├── department.schema.ts
│   │   └── common.schema.ts
│   └── types/
│       └── index.ts
├── scripts/
│   ├── seed.ts
│   └── generate-types.ts
├── .env.local
├── .env.example
└── package.json
```

### 1.3 Environment Configuration

```env
# .env.example

# Supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key

# Database Direct Connection (for migrations)
DATABASE_URL=postgresql://postgres:[password]@db.[ref].supabase.co:5432/postgres

# Security
JWT_SECRET=your-jwt-secret
RATE_LIMIT_MAX_REQUESTS=100
RATE_LIMIT_WINDOW_MS=900000

# External Services (if needed)
RESEND_API_KEY=
SENTRY_DSN=
```

### 1.4 Security Configuration Checklist

| Security Layer | Implementation | Priority |
|----------------|----------------|----------|
| Rate Limiting | Database + Edge Function | HIGH |
| Input Validation | Zod schemas | HIGH |
| Authentication | Supabase Auth | HIGH |
| Authorization | Dynamic RLS + Permissions | HIGH |
| Error Handling | Generic error handler | HIGH |
| Audit Logging | Database triggers | MEDIUM |
| CSRF Protection | Token validation | MEDIUM |
| HTTPS Enforcement | Supabase default | HIGH |
| Security Headers | Edge functions | MEDIUM |
| Secrets Management | Environment variables | HIGH |
| SQL Injection | Parameterized queries | HIGH |

---

## Phase 2: Database Schema & Security Policies

### 2.1 Migration 00001: Extensions

```sql
-- supabase/migrations/00001_extensions.sql

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";  -- Case-insensitive text

-- Create custom schemas
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS audit;
```

### 2.2 Migration 00002: Security Tables

```sql
-- supabase/migrations/00002_security_tables.sql

-- ============================================
-- RATE LIMITING TABLE
-- ============================================
CREATE TABLE security.rate_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identifier TEXT NOT NULL,           -- IP address or user ID
    endpoint TEXT NOT NULL,              -- API endpoint
    request_count INTEGER DEFAULT 1,
    window_start TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(identifier, endpoint)
);

CREATE INDEX idx_rate_limits_identifier ON security.rate_limits(identifier);
CREATE INDEX idx_rate_limits_window ON security.rate_limits(window_start);

-- ============================================
-- AUDIT LOG TABLE
-- ============================================
CREATE TABLE audit.logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    table_name TEXT NOT NULL,
    record_id UUID,
    action TEXT NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE', 'SELECT')),
    old_data JSONB,
    new_data JSONB,
    changed_fields TEXT[],
    user_id UUID,
    user_email TEXT,
    ip_address INET,
    user_agent TEXT,
    request_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_table ON audit.logs(table_name);
CREATE INDEX idx_audit_logs_user ON audit.logs(user_id);
CREATE INDEX idx_audit_logs_created ON audit.logs(created_at DESC);
CREATE INDEX idx_audit_logs_action ON audit.logs(action);

-- ============================================
-- API KEYS TABLE (for service-to-service)
-- ============================================
CREATE TABLE security.api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    permissions JSONB DEFAULT '[]',
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- SECURITY FUNCTIONS
-- ============================================

-- Rate limit check function
CREATE OR REPLACE FUNCTION security.check_rate_limit(
    p_identifier TEXT,
    p_endpoint TEXT,
    p_max_requests INTEGER DEFAULT 100,
    p_window_seconds INTEGER DEFAULT 900
)
RETURNS TABLE (
    allowed BOOLEAN,
    remaining INTEGER,
    reset_at TIMESTAMPTZ
) AS $$
DECLARE
    v_current_count INTEGER;
    v_window_start TIMESTAMPTZ;
    v_reset_at TIMESTAMPTZ;
BEGIN
    -- Clean old entries (older than 1 hour)
    DELETE FROM security.rate_limits 
    WHERE window_start < NOW() - INTERVAL '1 hour';

    -- Get or create rate limit entry
    INSERT INTO security.rate_limits (identifier, endpoint, request_count, window_start)
    VALUES (p_identifier, p_endpoint, 1, NOW())
    ON CONFLICT (identifier, endpoint) DO UPDATE SET
        request_count = CASE
            WHEN security.rate_limits.window_start < NOW() - (p_window_seconds || ' seconds')::INTERVAL
            THEN 1
            ELSE security.rate_limits.request_count + 1
        END,
        window_start = CASE
            WHEN security.rate_limits.window_start < NOW() - (p_window_seconds || ' seconds')::INTERVAL
            THEN NOW()
            ELSE security.rate_limits.window_start
        END
    RETURNING request_count, window_start
    INTO v_current_count, v_window_start;

    v_reset_at := v_window_start + (p_window_seconds || ' seconds')::INTERVAL;

    RETURN QUERY SELECT 
        v_current_count <= p_max_requests,
        GREATEST(0, p_max_requests - v_current_count),
        v_reset_at;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Generic audit trigger function
CREATE OR REPLACE FUNCTION audit.log_changes()
RETURNS TRIGGER AS $$
DECLARE
    v_old_data JSONB;
    v_new_data JSONB;
    v_changed_fields TEXT[];
    v_user_id UUID;
    v_user_email TEXT;
BEGIN
    -- Get current user info
    v_user_id := auth.uid();
    v_user_email := auth.email();

    IF TG_OP = 'DELETE' THEN
        v_old_data := to_jsonb(OLD);
        v_new_data := NULL;
    ELSIF TG_OP = 'UPDATE' THEN
        v_old_data := to_jsonb(OLD);
        v_new_data := to_jsonb(NEW);
        -- Get changed fields
        SELECT array_agg(key)
        INTO v_changed_fields
        FROM jsonb_each(v_new_data)
        WHERE v_old_data->key IS DISTINCT FROM v_new_data->key;
    ELSIF TG_OP = 'INSERT' THEN
        v_old_data := NULL;
        v_new_data := to_jsonb(NEW);
    END IF;

    INSERT INTO audit.logs (
        table_name,
        record_id,
        action,
        old_data,
        new_data,
        changed_fields,
        user_id,
        user_email
    ) VALUES (
        TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME,
        COALESCE(NEW.id, OLD.id),
        TG_OP,
        v_old_data,
        v_new_data,
        v_changed_fields,
        v_user_id,
        v_user_email
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

### 2.3 Migration 00003: Roles & Permissions

```sql
-- supabase/migrations/00003_roles_permissions.sql

-- ============================================
-- PERMISSIONS TABLE
-- ============================================
CREATE TABLE public.permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code TEXT UNIQUE NOT NULL,              -- e.g., 'users.create', 'departments.read'
    name TEXT NOT NULL,
    description TEXT,
    resource TEXT NOT NULL,                 -- e.g., 'users', 'departments'
    action TEXT NOT NULL,                   -- e.g., 'create', 'read', 'update', 'delete'
    is_system BOOLEAN DEFAULT false,        -- System permissions can't be deleted
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_permissions_resource ON public.permissions(resource);
CREATE INDEX idx_permissions_code ON public.permissions(code);

-- ============================================
-- ROLES TABLE
-- ============================================
CREATE TABLE public.roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code TEXT UNIQUE NOT NULL,              -- e.g., 'super_admin', 'manager'
    name TEXT NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT false,        -- System roles can't be deleted
    is_active BOOLEAN DEFAULT true,
    created_by UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_roles_code ON public.roles(code);
CREATE INDEX idx_roles_active ON public.roles(is_active) WHERE is_active = true;

-- ============================================
-- ROLE_PERMISSIONS (Junction Table)
-- ============================================
CREATE TABLE public.role_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_id UUID NOT NULL REFERENCES public.roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES public.permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(role_id, permission_id)
);

CREATE INDEX idx_role_permissions_role ON public.role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission ON public.role_permissions(permission_id);

-- ============================================
-- UPDATED_AT TRIGGER
-- ============================================
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_permissions_updated_at
    BEFORE UPDATE ON public.permissions
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER set_roles_updated_at
    BEFORE UPDATE ON public.roles
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ============================================
-- SEED DEFAULT PERMISSIONS
-- ============================================
INSERT INTO public.permissions (code, name, description, resource, action, is_system) VALUES
-- User permissions
('users.create', 'Create Users', 'Can create new users', 'users', 'create', true),
('users.read', 'Read Users', 'Can view users', 'users', 'read', true),
('users.read_own', 'Read Own User', 'Can view own profile', 'users', 'read_own', true),
('users.update', 'Update Users', 'Can update users', 'users', 'update', true),
('users.update_own', 'Update Own User', 'Can update own profile', 'users', 'update_own', true),
('users.delete', 'Delete Users', 'Can delete users', 'users', 'delete', true),

-- Role permissions
('roles.create', 'Create Roles', 'Can create new roles', 'roles', 'create', true),
('roles.read', 'Read Roles', 'Can view roles', 'roles', 'read', true),
('roles.update', 'Update Roles', 'Can update roles', 'roles', 'update', true),
('roles.delete', 'Delete Roles', 'Can delete roles', 'roles', 'delete', true),
('roles.assign', 'Assign Roles', 'Can assign roles to users', 'roles', 'assign', true),

-- Permission permissions
('permissions.read', 'Read Permissions', 'Can view permissions', 'permissions', 'read', true),
('permissions.manage', 'Manage Permissions', 'Can manage role permissions', 'permissions', 'manage', true),

-- Department permissions
('departments.create', 'Create Departments', 'Can create departments', 'departments', 'create', true),
('departments.read', 'Read Departments', 'Can view departments', 'departments', 'read', true),
('departments.update', 'Update Departments', 'Can update departments', 'departments', 'update', true),
('departments.delete', 'Delete Departments', 'Can delete departments', 'departments', 'delete', true),

-- Settings permissions
('settings.read', 'Read Settings', 'Can view settings', 'settings', 'read', true),
('settings.update', 'Update Settings', 'Can update settings', 'settings', 'update', true),

-- Audit permissions
('audit.read', 'Read Audit Logs', 'Can view audit logs', 'audit', 'read', true);

-- ============================================
-- SEED DEFAULT ROLES
-- ============================================
INSERT INTO public.roles (code, name, description, is_system) VALUES
('super_admin', 'Super Administrator', 'Full system access', true),
('admin', 'Administrator', 'Administrative access', true),
('manager', 'Manager', 'Management access', true),
('user', 'User', 'Standard user access', true),
('guest', 'Guest', 'Limited read-only access', true);

-- Assign all permissions to super_admin
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r
CROSS JOIN public.permissions p
WHERE r.code = 'super_admin';

-- Assign permissions to admin (all except super admin specific)
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r
CROSS JOIN public.permissions p
WHERE r.code = 'admin'
AND p.code NOT IN ('roles.delete', 'permissions.manage');

-- Assign permissions to manager
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r
CROSS JOIN public.permissions p
WHERE r.code = 'manager'
AND p.code IN ('users.read', 'users.update', 'departments.read', 'departments.update', 'roles.read', 'permissions.read');

-- Assign permissions to user
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r
CROSS JOIN public.permissions p
WHERE r.code = 'user'
AND p.code IN ('users.read_own', 'users.update_own', 'departments.read');

-- Assign permissions to guest
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r
CROSS JOIN public.permissions p
WHERE r.code = 'guest'
AND p.code IN ('departments.read');
```

### 2.4 Migration 00004: Users

```sql
-- supabase/migrations/00004_users.sql

-- ============================================
-- USERS PROFILE TABLE
-- ============================================
CREATE TABLE public.users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email CITEXT UNIQUE NOT NULL,
    full_name TEXT,
    avatar_url TEXT,
    phone TEXT,
    department_id UUID,                     -- Will add FK after departments table
    metadata JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    email_verified_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_users_email ON public.users(email);
CREATE INDEX idx_users_department ON public.users(department_id);
CREATE INDEX idx_users_active ON public.users(is_active) WHERE is_active = true;
CREATE INDEX idx_users_full_name ON public.users USING GIN(to_tsvector('english', full_name));

-- ============================================
-- USER_ROLES (Junction Table)
-- ============================================
CREATE TABLE public.user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES public.roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES public.users(id),
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,                 -- Optional role expiration
    UNIQUE(user_id, role_id)
);

CREATE INDEX idx_user_roles_user ON public.user_roles(user_id);
CREATE INDEX idx_user_roles_role ON public.user_roles(role_id);

-- ============================================
-- TRIGGERS
-- ============================================
CREATE TRIGGER set_users_updated_at
    BEFORE UPDATE ON public.users
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- Audit trigger for users
CREATE TRIGGER audit_users
    AFTER INSERT OR UPDATE OR DELETE ON public.users
    FOR EACH ROW EXECUTE FUNCTION audit.log_changes();

-- ============================================
-- AUTO-CREATE USER ON AUTH SIGNUP
-- ============================================
CREATE OR REPLACE FUNCTION public.handle_new_auth_user()
RETURNS TRIGGER AS $$
DECLARE
    v_default_role_id UUID;
BEGIN
    -- Get default role (user)
    SELECT id INTO v_default_role_id
    FROM public.roles
    WHERE code = 'user'
    LIMIT 1;

    -- Create user profile
    INSERT INTO public.users (id, email, full_name, avatar_url)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name'),
        NEW.raw_user_meta_data->>'avatar_url'
    );

    -- Assign default role
    IF v_default_role_id IS NOT NULL THEN
        INSERT INTO public.user_roles (user_id, role_id)
        VALUES (NEW.id, v_default_role_id);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_auth_user();
```

### 2.5 Migration 00005: Departments

```sql
-- supabase/migrations/00005_departments.sql

-- ============================================
-- DEPARTMENTS TABLE
-- ============================================
CREATE TABLE public.departments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL,
    description TEXT,
    parent_id UUID REFERENCES public.departments(id) ON DELETE SET NULL,
    manager_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    settings JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES public.users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_departments_code ON public.departments(code);
CREATE INDEX idx_departments_parent ON public.departments(parent_id);
CREATE INDEX idx_departments_manager ON public.departments(manager_id);
CREATE INDEX idx_departments_active ON public.departments(is_active) WHERE is_active = true;
CREATE INDEX idx_departments_name ON public.departments USING GIN(to_tsvector('english', name));

-- Add FK constraint to users.department_id
ALTER TABLE public.users
ADD CONSTRAINT fk_users_department
FOREIGN KEY (department_id) REFERENCES public.departments(id) ON DELETE SET NULL;

-- ============================================
-- TRIGGERS
-- ============================================
CREATE TRIGGER set_departments_updated_at
    BEFORE UPDATE ON public.departments
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- Audit trigger for departments
CREATE TRIGGER audit_departments
    AFTER INSERT OR UPDATE OR DELETE ON public.departments
    FOR EACH ROW EXECUTE FUNCTION audit.log_changes();

-- ============================================
-- DEPARTMENT HIERARCHY FUNCTION
-- ============================================
CREATE OR REPLACE FUNCTION public.get_department_hierarchy(p_department_id UUID)
RETURNS TABLE (
    id UUID,
    name TEXT,
    code TEXT,
    parent_id UUID,
    level INTEGER,
    path UUID[]
) AS $$
BEGIN
    RETURN QUERY
    WITH RECURSIVE hierarchy AS (
        -- Base case: start from the given department
        SELECT 
            d.id,
            d.name,
            d.code,
            d.parent_id,
            0 as level,
            ARRAY[d.id] as path
        FROM public.departments d
        WHERE d.id = p_department_id

        UNION ALL

        -- Recursive case: get children
        SELECT 
            d.id,
            d.name,
            d.code,
            d.parent_id,
            h.level + 1,
            h.path || d.id
        FROM public.departments d
        INNER JOIN hierarchy h ON d.parent_id = h.id
    )
    SELECT * FROM hierarchy
    ORDER BY path;
END;
$$ LANGUAGE plpgsql;
```

### 2.6 Migration 00006: RLS Policies

```sql
-- supabase/migrations/00006_rls_policies.sql

-- ============================================
-- ENABLE RLS
-- ============================================
ALTER TABLE public.permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.departments ENABLE ROW LEVEL SECURITY;

-- ============================================
-- PERMISSION CHECK FUNCTIONS
-- ============================================

-- Check if user has specific permission
CREATE OR REPLACE FUNCTION public.has_permission(p_permission_code TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM public.user_roles ur
        JOIN public.role_permissions rp ON ur.role_id = rp.role_id
        JOIN public.permissions p ON rp.permission_id = p.id
        JOIN public.roles r ON ur.role_id = r.id
        WHERE ur.user_id = auth.uid()
        AND p.code = p_permission_code
        AND r.is_active = true
        AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;

-- Check if user has any of the given permissions
CREATE OR REPLACE FUNCTION public.has_any_permission(p_permissions TEXT[])
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM public.user_roles ur
        JOIN public.role_permissions rp ON ur.role_id = rp.role_id
        JOIN public.permissions p ON rp.permission_id = p.id
        JOIN public.roles r ON ur.role_id = r.id
        WHERE ur.user_id = auth.uid()
        AND p.code = ANY(p_permissions)
        AND r.is_active = true
        AND (ur.expires_at IS NULL OR ur.expires_at > NOW())
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;

-- Check if user is super admin
CREATE OR REPLACE FUNCTION public.is_super_admin()
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM public.user_roles ur
        JOIN public.roles r ON ur.role_id = r.id
        WHERE ur.user_id = auth.uid()
        AND r.code = 'super_admin'
        AND r.is_active = true
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;

-- Get all user permissions
CREATE OR REPLACE FUNCTION public.get_my_permissions()
RETURNS TABLE (permission_code TEXT, resource TEXT, action TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT DISTINCT p.code, p.resource, p.action
    FROM public.user_roles ur
    JOIN public.role_permissions rp ON ur.role_id = rp.role_id
    JOIN public.permissions p ON rp.permission_id = p.id
    JOIN public.roles r ON ur.role_id = r.id
    WHERE ur.user_id = auth.uid()
    AND r.is_active = true
    AND (ur.expires_at IS NULL OR ur.expires_at > NOW());
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;

-- ============================================
-- PERMISSIONS RLS POLICIES
-- ============================================
CREATE POLICY "Permissions: Read with permission"
ON public.permissions FOR SELECT
USING (has_permission('permissions.read') OR is_super_admin());

-- ============================================
-- ROLES RLS POLICIES
-- ============================================
CREATE POLICY "Roles: Read with permission"
ON public.roles FOR SELECT
USING (has_permission('roles.read') OR is_super_admin());

CREATE POLICY "Roles: Create with permission"
ON public.roles FOR INSERT
WITH CHECK (has_permission('roles.create') OR is_super_admin());

CREATE POLICY "Roles: Update with permission"
ON public.roles FOR UPDATE
USING (has_permission('roles.update') OR is_super_admin())
WITH CHECK (NOT is_system OR is_super_admin());

CREATE POLICY "Roles: Delete with permission"
ON public.roles FOR DELETE
USING ((has_permission('roles.delete') OR is_super_admin()) AND NOT is_system);

-- ============================================
-- ROLE_PERMISSIONS RLS POLICIES
-- ============================================
CREATE POLICY "Role Permissions: Read with permission"
ON public.role_permissions FOR SELECT
USING (has_permission('permissions.read') OR is_super_admin());

CREATE POLICY "Role Permissions: Manage with permission"
ON public.role_permissions FOR ALL
USING (has_permission('permissions.manage') OR is_super_admin());

-- ============================================
-- USERS RLS POLICIES
-- ============================================
CREATE POLICY "Users: Read own profile"
ON public.users FOR SELECT
USING (
    auth.uid() = id 
    OR has_permission('users.read') 
    OR is_super_admin()
);

CREATE POLICY "Users: Create with permission"
ON public.users FOR INSERT
WITH CHECK (has_permission('users.create') OR is_super_admin());

CREATE POLICY "Users: Update own profile"
ON public.users FOR UPDATE
USING (
    (auth.uid() = id AND has_permission('users.update_own'))
    OR has_permission('users.update')
    OR is_super_admin()
);

CREATE POLICY "Users: Delete with permission"
ON public.users FOR DELETE
USING (
    (has_permission('users.delete') OR is_super_admin())
    AND id != auth.uid()  -- Can't delete yourself
);

-- ============================================
-- USER_ROLES RLS POLICIES
-- ============================================
CREATE POLICY "User Roles: Read with permission"
ON public.user_roles FOR SELECT
USING (
    user_id = auth.uid()
    OR has_permission('roles.read')
    OR is_super_admin()
);

CREATE POLICY "User Roles: Assign with permission"
ON public.user_roles FOR INSERT
WITH CHECK (has_permission('roles.assign') OR is_super_admin());

CREATE POLICY "User Roles: Remove with permission"
ON public.user_roles FOR DELETE
USING (has_permission('roles.assign') OR is_super_admin());

-- ============================================
-- DEPARTMENTS RLS POLICIES
-- ============================================
CREATE POLICY "Departments: Read with permission"
ON public.departments FOR SELECT
USING (
    has_permission('departments.read') 
    OR is_super_admin()
    -- Users can read their own department
    OR id = (SELECT department_id FROM public.users WHERE id = auth.uid())
);

CREATE POLICY "Departments: Create with permission"
ON public.departments FOR INSERT
WITH CHECK (has_permission('departments.create') OR is_super_admin());

CREATE POLICY "Departments: Update with permission"
ON public.departments FOR UPDATE
USING (has_permission('departments.update') OR is_super_admin());

CREATE POLICY "Departments: Delete with permission"
ON public.departments FOR DELETE
USING (has_permission('departments.delete') OR is_super_admin());
```

---

## Phase 3: Generic CRUD Architecture

### 3.1 Generic CRUD Database Functions

```sql
-- supabase/migrations/00007_generic_crud_functions.sql

-- ============================================
-- GENERIC FILTERED COUNT
-- ============================================
CREATE OR REPLACE FUNCTION public.generic_count(
    p_table_name TEXT,
    p_filters JSONB DEFAULT '{}'
)
RETURNS BIGINT AS $$
DECLARE
    v_sql TEXT;
    v_count BIGINT;
    v_filter_key TEXT;
    v_filter_value JSONB;
    v_where_clauses TEXT[] := ARRAY[]::TEXT[];
BEGIN
    -- Build base query
    v_sql := format('SELECT COUNT(*) FROM public.%I WHERE 1=1', p_table_name);

    -- Add filter conditions
    FOR v_filter_key, v_filter_value IN SELECT * FROM jsonb_each(p_filters)
    LOOP
        IF jsonb_typeof(v_filter_value) = 'null' THEN
            v_where_clauses := array_append(v_where_clauses, 
                format('%I IS NULL', v_filter_key));
        ELSIF jsonb_typeof(v_filter_value) = 'array' THEN
            v_where_clauses := array_append(v_where_clauses, 
                format('%I = ANY(SELECT jsonb_array_elements_text(%L))', v_filter_key, v_filter_value));
        ELSE
            v_where_clauses := array_append(v_where_clauses, 
                format('%I = %L', v_filter_key, v_filter_value #>> '{}'));
        END IF;
    END LOOP;

    -- Append WHERE clauses
    IF array_length(v_where_clauses, 1) > 0 THEN
        v_sql := v_sql || ' AND ' || array_to_string(v_where_clauses, ' AND ');
    END IF;

    EXECUTE v_sql INTO v_count;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- GENERIC SOFT DELETE
-- ============================================
CREATE OR REPLACE FUNCTION public.generic_soft_delete(
    p_table_name TEXT,
    p_id UUID
)
RETURNS BOOLEAN AS $$
DECLARE
    v_sql TEXT;
    v_result BOOLEAN;
BEGIN
    v_sql := format(
        'UPDATE public.%I SET is_active = false, updated_at = NOW() WHERE id = %L RETURNING true',
        p_table_name,
        p_id
    );

    EXECUTE v_sql INTO v_result;
    RETURN COALESCE(v_result, false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- BULK OPERATIONS
-- ============================================
CREATE OR REPLACE FUNCTION public.generic_bulk_update(
    p_table_name TEXT,
    p_ids UUID[],
    p_updates JSONB
)
RETURNS INTEGER AS $$
DECLARE
    v_sql TEXT;
    v_set_clauses TEXT[] := ARRAY[]::TEXT[];
    v_key TEXT;
    v_value JSONB;
    v_affected INTEGER;
BEGIN
    -- Build SET clauses
    FOR v_key, v_value IN SELECT * FROM jsonb_each(p_updates)
    LOOP
        v_set_clauses := array_append(v_set_clauses, 
            format('%I = %L', v_key, v_value #>> '{}'));
    END LOOP;

    -- Always update updated_at
    v_set_clauses := array_append(v_set_clauses, 'updated_at = NOW()');

    v_sql := format(
        'UPDATE public.%I SET %s WHERE id = ANY(%L)',
        p_table_name,
        array_to_string(v_set_clauses, ', '),
        p_ids
    );

    EXECUTE v_sql;
    GET DIAGNOSTICS v_affected = ROW_COUNT;
    RETURN v_affected;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

### 3.2 Shared Edge Function Utilities

```typescript
// supabase/functions/_shared/cors.ts
export const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-request-id',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Max-Age': '86400',
}

export function handleCors(req: Request): Response | null {
    if (req.method === 'OPTIONS') {
        return new Response('ok', { headers: corsHeaders })
    }
    return null
}
```

```typescript
// supabase/functions/_shared/error-handler.ts
import { corsHeaders } from './cors.ts'

export interface AppError {
    code: string
    message: string
    statusCode: number
    details?: unknown
}

export const ErrorCodes = {
    // Client errors
    VALIDATION_ERROR: { code: 'VALIDATION_ERROR', statusCode: 400 },
    UNAUTHORIZED: { code: 'UNAUTHORIZED', statusCode: 401 },
    FORBIDDEN: { code: 'FORBIDDEN', statusCode: 403 },
    NOT_FOUND: { code: 'NOT_FOUND', statusCode: 404 },
    CONFLICT: { code: 'CONFLICT', statusCode: 409 },
    RATE_LIMITED: { code: 'RATE_LIMITED', statusCode: 429 },
    
    // Server errors
    INTERNAL_ERROR: { code: 'INTERNAL_ERROR', statusCode: 500 },
    DATABASE_ERROR: { code: 'DATABASE_ERROR', statusCode: 500 },
    EXTERNAL_SERVICE_ERROR: { code: 'EXTERNAL_SERVICE_ERROR', statusCode: 502 },
} as const

export function createError(
    errorType: keyof typeof ErrorCodes,
    message: string,
    details?: unknown
): AppError {
    const error = ErrorCodes[errorType]
    return {
        code: error.code,
        message,
        statusCode: error.statusCode,
        details
    }
}

export function errorResponse(error: AppError): Response {
    return new Response(
        JSON.stringify({
            success: false,
            error: {
                code: error.code,
                message: error.message,
                ...(error.details && { details: error.details })
            }
        }),
        {
            status: error.statusCode,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
    )
}

export function handleError(error: unknown): Response {
    console.error('Error:', error)

    if ((error as AppError).code) {
        return errorResponse(error as AppError)
    }

    // Supabase/Postgres errors
    if ((error as any).code) {
        const pgError = error as any
        switch (pgError.code) {
            case '23505': // Unique violation
                return errorResponse(createError('CONFLICT', 'Record already exists'))
            case '23503': // Foreign key violation
                return errorResponse(createError('VALIDATION_ERROR', 'Referenced record not found'))
            case '42501': // Permission denied
                return errorResponse(createError('FORBIDDEN', 'Permission denied'))
            case 'PGRST116': // Not found
                return errorResponse(createError('NOT_FOUND', 'Record not found'))
            default:
                return errorResponse(createError('DATABASE_ERROR', 'Database operation failed'))
        }
    }

    return errorResponse(createError('INTERNAL_ERROR', 'An unexpected error occurred'))
}
```

```typescript
// supabase/functions/_shared/auth.ts
import { createClient, SupabaseClient, User } from 'https://esm.sh/@supabase/supabase-js@2'
import { createError } from './error-handler.ts'

export interface AuthContext {
    user: User
    permissions: string[]
    supabase: SupabaseClient
    supabaseAdmin: SupabaseClient
}

export async function getAuthContext(req: Request): Promise<AuthContext> {
    const authHeader = req.headers.get('Authorization')
    
    if (!authHeader) {
        throw createError('UNAUTHORIZED', 'Missing authorization header')
    }

    // Create clients
    const supabaseAdmin = createClient(
        Deno.env.get('SUPABASE_URL')!,
        Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    )

    const supabase = createClient(
        Deno.env.get('SUPABASE_URL')!,
        Deno.env.get('SUPABASE_ANON_KEY')!,
        { global: { headers: { Authorization: authHeader } } }
    )

    // Verify user
    const { data: { user }, error } = await supabase.auth.getUser()
    
    if (error || !user) {
        throw createError('UNAUTHORIZED', 'Invalid or expired token')
    }

    // Get user permissions
    const { data: permissions } = await supabaseAdmin.rpc('get_my_permissions')

    return {
        user,
        permissions: permissions?.map((p: any) => p.permission_code) || [],
        supabase,
        supabaseAdmin
    }
}

export function requirePermission(ctx: AuthContext, permission: string): void {
    if (!ctx.permissions.includes(permission)) {
        throw createError('FORBIDDEN', `Missing required permission: ${permission}`)
    }
}

export function requireAnyPermission(ctx: AuthContext, permissions: string[]): void {
    const hasPermission = permissions.some(p => ctx.permissions.includes(p))
    if (!hasPermission) {
        throw createError('FORBIDDEN', `Missing one of required permissions: ${permissions.join(', ')}`)
    }
}
```

```typescript
// supabase/functions/_shared/rate-limiter.ts
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { createError } from './error-handler.ts'

interface RateLimitConfig {
    maxRequests: number
    windowSeconds: number
}

const defaultConfig: RateLimitConfig = {
    maxRequests: 100,
    windowSeconds: 900 // 15 minutes
}

export async function checkRateLimit(
    identifier: string,
    endpoint: string,
    config: Partial<RateLimitConfig> = {}
): Promise<{ remaining: number; resetAt: Date }> {
    const { maxRequests, windowSeconds } = { ...defaultConfig, ...config }

    const supabaseAdmin = createClient(
        Deno.env.get('SUPABASE_URL')!,
        Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    )

    const { data, error } = await supabaseAdmin.rpc('check_rate_limit', {
        p_identifier: identifier,
        p_endpoint: endpoint,
        p_max_requests: maxRequests,
        p_window_seconds: windowSeconds
    })

    if (error) {
        console.error('Rate limit check error:', error)
        // Fail open - allow request if rate limit check fails
        return { remaining: maxRequests, resetAt: new Date() }
    }

    const result = data[0]
    
    if (!result.allowed) {
        throw createError('RATE_LIMITED', 'Too many requests', {
            remaining: 0,
            resetAt: result.reset_at
        })
    }

    return {
        remaining: result.remaining,
        resetAt: new Date(result.reset_at)
    }
}

export function getRateLimitHeaders(remaining: number, resetAt: Date): Record<string, string> {
    return {
        'X-RateLimit-Remaining': remaining.toString(),
        'X-RateLimit-Reset': resetAt.toISOString()
    }
}
```

```typescript
// supabase/functions/_shared/validation.ts
import { z } from 'https://deno.land/x/zod@v3.22.4/mod.ts'
import { createError } from './error-handler.ts'

// ============================================
// COMMON SCHEMAS
// ============================================
export const paginationSchema = z.object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().positive().max(100).default(10),
    sortBy: z.string().optional(),
    sortOrder: z.enum(['asc', 'desc']).default('desc')
})

export const idSchema = z.string().uuid('Invalid ID format')

export const searchSchema = z.object({
    search: z.string().max(200).optional(),
    filters: z.record(z.any()).optional()
})

// ============================================
// ENTITY SCHEMAS
// ============================================
export const userCreateSchema = z.object({
    email: z.string().email('Invalid email format'),
    full_name: z.string().min(2).max(100).optional(),
    phone: z.string().max(20).optional(),
    department_id: z.string().uuid().optional(),
    role_ids: z.array(z.string().uuid()).optional()
})

export const userUpdateSchema = userCreateSchema.partial().extend({
    is_active: z.boolean().optional()
})

export const departmentCreateSchema = z.object({
    name: z.string().min(2).max(100),
    code: z.string().min(2).max(50).regex(/^[a-z0-9_-]+$/i, 'Invalid code format'),
    description: z.string().max(500).optional(),
    parent_id: z.string().uuid().optional(),
    manager_id: z.string().uuid().optional()
})

export const departmentUpdateSchema = departmentCreateSchema.partial().extend({
    is_active: z.boolean().optional()
})

export const roleCreateSchema = z.object({
    name: z.string().min(2).max(100),
    code: z.string().min(2).max(50).regex(/^[a-z0-9_]+$/i, 'Invalid code format'),
    description: z.string().max(500).optional(),
    permission_ids: z.array(z.string().uuid()).optional()
})

export const roleUpdateSchema = roleCreateSchema.partial().extend({
    is_active: z.boolean().optional()
})

// ============================================
// VALIDATION HELPER
// ============================================
export function validate<T>(schema: z.ZodSchema<T>, data: unknown): T {
    const result = schema.safeParse(data)
    
    if (!result.success) {
        const errors = result.error.errors.map(e => ({
            field: e.path.join('.'),
            message: e.message
        }))
        
        throw createError('VALIDATION_ERROR', 'Validation failed', errors)
    }
    
    return result.data
}
```

```typescript
// supabase/functions/_shared/response.ts
import { corsHeaders } from './cors.ts'

export interface ApiResponse<T> {
    success: boolean
    data?: T
    error?: {
        code: string
        message: string
        details?: unknown
    }
    meta?: {
        pagination?: {
            page: number
            limit: number
            total: number
            totalPages: number
        }
        [key: string]: unknown
    }
}

export function successResponse<T>(
    data: T,
    meta?: ApiResponse<T>['meta'],
    headers: Record<string, string> = {}
): Response {
    const response: ApiResponse<T> = {
        success: true,
        data,
        ...(meta && { meta })
    }

    return new Response(JSON.stringify(response), {
        status: 200,
        headers: {
            ...corsHeaders,
            'Content-Type': 'application/json',
            ...headers
        }
    })
}

export function createdResponse<T>(data: T): Response {
    return new Response(
        JSON.stringify({ success: true, data }),
        {
            status: 201,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        }
    )
}

export function noContentResponse(): Response {
    return new Response(null, {
        status: 204,
        headers: corsHeaders
    })
}
```

### 3.3 Generic CRUD Edge Function

```typescript
// supabase/functions/generic-crud/index.ts
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { handleCors, corsHeaders } from '../_shared/cors.ts'
import { getAuthContext, requirePermission } from '../_shared/auth.ts'
import { handleError, createError } from '../_shared/error-handler.ts'
import { validate, paginationSchema, searchSchema, idSchema } from '../_shared/validation.ts'
import { checkRateLimit, getRateLimitHeaders } from '../_shared/rate-limiter.ts'
import { successResponse, createdResponse, noContentResponse } from '../_shared/response.ts'
import { z } from 'https://deno.land/x/zod@v3.22.4/mod.ts'

interface CrudConfig {
    tableName: string
    resource: string
    selectFields: string
    searchFields: string[]
    createSchema: z.ZodSchema
    updateSchema: z.ZodSchema
    defaultSort: string
    relations?: string
}

// CRUD configurations for each entity
const crudConfigs: Record<string, CrudConfig> = {
    users: {
        tableName: 'users',
        resource: 'users',
        selectFields: 'id, email, full_name, avatar_url, phone, department_id, is_active, created_at, updated_at',
        searchFields: ['full_name', 'email'],
        createSchema: z.object({
            email: z.string().email(),
            full_name: z.string().optional(),
            phone: z.string().optional(),
            department_id: z.string().uuid().optional()
        }),
        updateSchema: z.object({
            full_name: z.string().optional(),
            phone: z.string().optional(),
            department_id: z.string().uuid().optional(),
            is_active: z.boolean().optional()
        }),
        defaultSort: 'created_at',
        relations: 'department:departments(id, name, code), user_roles(role:roles(id, name, code))'
    },
    departments: {
        tableName: 'departments',
        resource: 'departments',
        selectFields: 'id, name, code, description, parent_id, manager_id, is_active, created_at, updated_at',
        searchFields: ['name', 'code', 'description'],
        createSchema: z.object({
            name: z.string().min(2).max(100),
            code: z.string().min(2).max(50),
            description: z.string().optional(),
            parent_id: z.string().uuid().optional(),
            manager_id: z.string().uuid().optional()
        }),
        updateSchema: z.object({
            name: z.string().min(2).max(100).optional(),
            description: z.string().optional(),
            parent_id: z.string().uuid().optional(),
            manager_id: z.string().uuid().optional(),
            is_active: z.boolean().optional()
        }),
        defaultSort: 'name',
        relations: 'parent:departments!parent_id(id, name), manager:users!manager_id(id, full_name, email)'
    },
    roles: {
        tableName: 'roles',
        resource: 'roles',
        selectFields: 'id, name, code, description, is_system, is_active, created_at, updated_at',
        searchFields: ['name', 'code', 'description'],
        createSchema: z.object({
            name: z.string().min(2).max(100),
            code: z.string().min(2).max(50),
            description: z.string().optional()
        }),
        updateSchema: z.object({
            name: z.string().optional(),
            description: z.string().optional(),
            is_active: z.boolean().optional()
        }),
        defaultSort: 'name',
        relations: 'role_permissions(permission:permissions(id, code, name, resource, action))'
    }
}

serve(async (req) => {
    // Handle CORS
    const corsResponse = handleCors(req)
    if (corsResponse) return corsResponse

    try {
        const url = new URL(req.url)
        const pathParts = url.pathname.split('/').filter(Boolean)
        
        // Expected: /generic-crud/{entity} or /generic-crud/{entity}/{id}
        const entity = pathParts[1]
        const id = pathParts[2]

        if (!entity || !crudConfigs[entity]) {
            throw createError('NOT_FOUND', 'Entity not found')
        }

        const config = crudConfigs[entity]
        const ctx = await getAuthContext(req)

        // Rate limiting
        const clientIp = req.headers.get('x-forwarded-for') || 'unknown'
        const rateLimit = await checkRateLimit(
            ctx.user.id || clientIp,
            `${entity}:${req.method}`
        )
        const rateLimitHeaders = getRateLimitHeaders(rateLimit.remaining, rateLimit.resetAt)

        // Route to appropriate handler
        switch (req.method) {
            case 'GET':
                if (id) {
                    return await handleGetOne(ctx, config, id, rateLimitHeaders)
                }
                return await handleGetMany(ctx, config, url.searchParams, rateLimitHeaders)

            case 'POST':
                return await handleCreate(ctx, config, req, rateLimitHeaders)

            case 'PUT':
            case 'PATCH':
                if (!id) throw createError('VALIDATION_ERROR', 'ID is required')
                return await handleUpdate(ctx, config, id, req, rateLimitHeaders)

            case 'DELETE':
                if (!id) throw createError('VALIDATION_ERROR', 'ID is required')
                return await handleDelete(ctx, config, id, rateLimitHeaders)

            default:
                throw createError('VALIDATION_ERROR', 'Method not allowed')
        }
    } catch (error) {
        return handleError(error)
    }
})

// ============================================
// HANDLERS
// ============================================

async function handleGetMany(
    ctx: any,
    config: CrudConfig,
    params: URLSearchParams,
    headers: Record<string, string>
) {
    requirePermission(ctx, `${config.resource}.read`)

    // Parse and validate query params
    const pagination = validate(paginationSchema, {
        page: params.get('page'),
        limit: params.get('limit'),
        sortBy: params.get('sortBy'),
        sortOrder: params.get('sortOrder')
    })

    const search = params.get('search')
    const isActive = params.get('is_active')

    // Build query
    let query = ctx.supabaseAdmin
        .from(config.tableName)
        .select(`${config.selectFields}${config.relations ? ', ' + config.relations : ''}`, { count: 'exact' })

    // Apply search filter
    if (search && config.searchFields.length > 0) {
        const searchConditions = config.searchFields
            .map(field => `${field}.ilike.%${search}%`)
            .join(',')
        query = query.or(searchConditions)
    }

    // Apply active filter
    if (isActive !== null && isActive !== undefined) {
        query = query.eq('is_active', isActive === 'true')
    }

    // Apply sorting
    const sortBy = pagination.sortBy || config.defaultSort
    query = query.order(sortBy, { ascending: pagination.sortOrder === 'asc' })

    // Apply pagination
    const from = (pagination.page - 1) * pagination.limit
    const to = from + pagination.limit - 1
    query = query.range(from, to)

    const { data, error, count } = await query

    if (error) throw error

    return successResponse(data, {
        pagination: {
            page: pagination.page,
            limit: pagination.limit,
            total: count || 0,
            totalPages: Math.ceil((count || 0) / pagination.limit)
        }
    }, headers)
}

async function handleGetOne(
    ctx: any,
    config: CrudConfig,
    id: string,
    headers: Record<string, string>
) {
    requirePermission(ctx, `${config.resource}.read`)
    validate(idSchema, id)

    const { data, error } = await ctx.supabaseAdmin
        .from(config.tableName)
        .select(`${config.selectFields}${config.relations ? ', ' + config.relations : ''}`)
        .eq('id', id)
        .single()

    if (error) {
        if (error.code === 'PGRST116') {
            throw createError('NOT_FOUND', `${config.resource} not found`)
        }
        throw error
    }

    return successResponse(data, undefined, headers)
}

async function handleCreate(
    ctx: any,
    config: CrudConfig,
    req: Request,
    headers: Record<string, string>
) {
    requirePermission(ctx, `${config.resource}.create`)

    const body = await req.json()
    const validatedData = validate(config.createSchema, body)

    const { data, error } = await ctx.supabaseAdmin
        .from(config.tableName)
        .insert({
            ...validatedData,
            created_by: ctx.user.id
        })
        .select(`${config.selectFields}${config.relations ? ', ' + config.relations : ''}`)
        .single()

    if (error) throw error

    return createdResponse(data)
}

async function handleUpdate(
    ctx: any,
    config: CrudConfig,
    id: string,
    req: Request,
    headers: Record<string, string>
) {
    requirePermission(ctx, `${config.resource}.update`)
    validate(idSchema, id)

    const body = await req.json()
    const validatedData = validate(config.updateSchema, body)

    const { data, error } = await ctx.supabaseAdmin
        .from(config.tableName)
        .update(validatedData)
        .eq('id', id)
        .select(`${config.selectFields}${config.relations ? ', ' + config.relations : ''}`)
        .single()

    if (error) {
        if (error.code === 'PGRST116') {
            throw createError('NOT_FOUND', `${config.resource} not found`)
        }
        throw error
    }

    return successResponse(data, undefined, headers)
}

async function handleDelete(
    ctx: any,
    config: CrudConfig,
    id: string,
    headers: Record<string, string>
) {
    requirePermission(ctx, `${config.resource}.delete`)
    validate(idSchema, id)

    // Soft delete
    const { error } = await ctx.supabaseAdmin
        .from(config.tableName)
        .update({ is_active: false })
        .eq('id', id)

    if (error) throw error

    return noContentResponse()
}
```

---

## Phase 4: Dynamic Roles & Permissions System

### 4.1 Role Management API

```typescript
// supabase/functions/roles/index.ts
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { handleCors } from '../_shared/cors.ts'
import { getAuthContext, requirePermission } from '../_shared/auth.ts'
import { handleError, createError } from '../_shared/error-handler.ts'
import { validate, roleCreateSchema, roleUpdateSchema, idSchema } from '../_shared/validation.ts'
import { successResponse, createdResponse, noContentResponse } from '../_shared/response.ts'

serve(async (req) => {
    const corsResponse = handleCors(req)
    if (corsResponse) return corsResponse

    try {
        const url = new URL(req.url)
        const pathParts = url.pathname.split('/').filter(Boolean)
        const id = pathParts[1]
        const action = pathParts[2] // For special actions like /roles/{id}/permissions

        const ctx = await getAuthContext(req)

        switch (req.method) {
            case 'GET':
                if (id && action === 'permissions') {
                    return await getRolePermissions(ctx, id)
                }
                if (id) {
                    return await getRole(ctx, id)
                }
                return await getRoles(ctx, url.searchParams)

            case 'POST':
                if (id && action === 'permissions') {
                    return await assignPermissions(ctx, id, req)
                }
                return await createRole(ctx, req)

            case 'PUT':
            case 'PATCH':
                if (!id) throw createError('VALIDATION_ERROR', 'Role ID required')
                return await updateRole(ctx, id, req)

            case 'DELETE':
                if (id && action === 'permissions') {
                    return await removePermissions(ctx, id, req)
                }
                if (!id) throw createError('VALIDATION_ERROR', 'Role ID required')
                return await deleteRole(ctx, id)

            default:
                throw createError('VALIDATION_ERROR', 'Method not allowed')
        }
    } catch (error) {
        return handleError(error)
    }
})

async function getRoles(ctx: any, params: URLSearchParams) {
    requirePermission(ctx, 'roles.read')

    const page = parseInt(params.get('page') || '1')
    const limit = parseInt(params.get('limit') || '10')
    const search = params.get('search')
    const includeInactive = params.get('include_inactive') === 'true'

    let query = ctx.supabaseAdmin
        .from('roles')
        .select(`
            id, name, code, description, is_system, is_active, created_at, updated_at,
            role_permissions(
                permission:permissions(id, code, name)
            )
        `, { count: 'exact' })

    if (search) {
        query = query.or(`name.ilike.%${search}%,code.ilike.%${search}%`)
    }

    if (!includeInactive) {
        query = query.eq('is_active', true)
    }

    const from = (page - 1) * limit
    query = query.range(from, from + limit - 1).order('name')

    const { data, error, count } = await query
    if (error) throw error

    // Transform data to include permissions array
    const transformedData = data.map((role: any) => ({
        ...role,
        permissions: role.role_permissions?.map((rp: any) => rp.permission) || [],
        role_permissions: undefined
    }))

    return successResponse(transformedData, {
        pagination: { page, limit, total: count || 0, totalPages: Math.ceil((count || 0) / limit) }
    })
}

async function getRole(ctx: any, id: string) {
    requirePermission(ctx, 'roles.read')
    validate(idSchema, id)

    const { data, error } = await ctx.supabaseAdmin
        .from('roles')
        .select(`
            *,
            role_permissions(
                permission:permissions(*)
            )
        `)
        .eq('id', id)
        .single()

    if (error) throw error

    return successResponse({
        ...data,
        permissions: data.role_permissions?.map((rp: any) => rp.permission) || [],
        role_permissions: undefined
    })
}

async function createRole(ctx: any, req: Request) {
    requirePermission(ctx, 'roles.create')

    const body = await req.json()
    const { permission_ids, ...roleData } = validate(roleCreateSchema.extend({
        permission_ids: z.array(z.string().uuid()).optional()
    }), body)

    // Create role
    const { data: role, error: roleError } = await ctx.supabaseAdmin
        .from('roles')
        .insert({
            ...roleData,
            created_by: ctx.user.id
        })
        .select()
        .single()

    if (roleError) throw roleError

    // Assign permissions if provided
    if (permission_ids?.length) {
        const { error: permError } = await ctx.supabaseAdmin
            .from('role_permissions')
            .insert(permission_ids.map(pid => ({
                role_id: role.id,
                permission_id: pid
            })))

        if (permError) throw permError
    }

    return createdResponse(role)
}

async function updateRole(ctx: any, id: string, req: Request) {
    requirePermission(ctx, 'roles.update')
    validate(idSchema, id)

    const body = await req.json()
    const validatedData = validate(roleUpdateSchema, body)

    // Check if system role
    const { data: existing } = await ctx.supabaseAdmin
        .from('roles')
        .select('is_system')
        .eq('id', id)
        .single()

    if (existing?.is_system && validatedData.code) {
        throw createError('FORBIDDEN', 'Cannot modify system role code')
    }

    const { data, error } = await ctx.supabaseAdmin
        .from('roles')
        .update(validatedData)
        .eq('id', id)
        .select()
        .single()

    if (error) throw error

    return successResponse(data)
}

async function deleteRole(ctx: any, id: string) {
    requirePermission(ctx, 'roles.delete')
    validate(idSchema, id)

    // Check if system role
    const { data: existing } = await ctx.supabaseAdmin
        .from('roles')
        .select('is_system, code')
        .eq('id', id)
        .single()

    if (existing?.is_system) {
        throw createError('FORBIDDEN', 'Cannot delete system role')
    }

    // Soft delete
    const { error } = await ctx.supabaseAdmin
        .from('roles')
        .update({ is_active: false })
        .eq('id', id)

    if (error) throw error

    return noContentResponse()
}

async function getRolePermissions(ctx: any, roleId: string) {
    requirePermission(ctx, 'permissions.read')
    validate(idSchema, roleId)

    const { data, error } = await ctx.supabaseAdmin
        .from('role_permissions')
        .select('permission:permissions(*)')
        .eq('role_id', roleId)

    if (error) throw error

    return successResponse(data.map((rp: any) => rp.permission))
}

async function assignPermissions(ctx: any, roleId: string, req: Request) {
    requirePermission(ctx, 'permissions.manage')
    validate(idSchema, roleId)

    const { permission_ids } = await req.json()
    
    if (!Array.isArray(permission_ids)) {
        throw createError('VALIDATION_ERROR', 'permission_ids must be an array')
    }

    // Insert new permissions (ignore duplicates)
    const { error } = await ctx.supabaseAdmin
        .from('role_permissions')
        .upsert(
            permission_ids.map((pid: string) => ({
                role_id: roleId,
                permission_id: pid
            })),
            { onConflict: 'role_id,permission_id', ignoreDuplicates: true }
        )

    if (error) throw error

    return await getRolePermissions(ctx, roleId)
}

async function removePermissions(ctx: any, roleId: string, req: Request) {
    requirePermission(ctx, 'permissions.manage')
    validate(idSchema, roleId)

    const { permission_ids } = await req.json()

    const { error } = await ctx.supabaseAdmin
        .from('role_permissions')
        .delete()
        .eq('role_id', roleId)
        .in('permission_id', permission_ids)

    if (error) throw error

    return noContentResponse()
}
```

### 4.2 Permissions API

```typescript
// supabase/functions/permissions/index.ts
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { handleCors } from '../_shared/cors.ts'
import { getAuthContext, requirePermission } from '../_shared/auth.ts'
import { handleError } from '../_shared/error-handler.ts'
import { successResponse } from '../_shared/response.ts'

serve(async (req) => {
    const corsResponse = handleCors(req)
    if (corsResponse) return corsResponse

    try {
        const ctx = await getAuthContext(req)
        requirePermission(ctx, 'permissions.read')

        const url = new URL(req.url)
        const resource = url.searchParams.get('resource')

        let query = ctx.supabaseAdmin
            .from('permissions')
            .select('*')
            .order('resource')
            .order('action')

        if (resource) {
            query = query.eq('resource', resource)
        }

        const { data, error } = await query
        if (error) throw error

        // Group by resource
        const grouped = data.reduce((acc: any, perm: any) => {
            if (!acc[perm.resource]) {
                acc[perm.resource] = []
            }
            acc[perm.resource].push(perm)
            return acc
        }, {})

        return successResponse({
            permissions: data,
            byResource: grouped
        })
    } catch (error) {
        return handleError(error)
    }
})
```

---

## Phase 5: Users CRUD Implementation

### 5.1 Users API

```typescript
// supabase/functions/users/index.ts
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { handleCors } from '../_shared/cors.ts'
import { getAuthContext, requirePermission, requireAnyPermission } from '../_shared/auth.ts'
import { handleError, createError } from '../_shared/error-handler.ts'
import { validate, userCreateSchema, userUpdateSchema, idSchema, paginationSchema } from '../_shared/validation.ts'
import { successResponse, createdResponse, noContentResponse } from '../_shared/response.ts'

serve(async (req) => {
    const corsResponse = handleCors(req)
    if (corsResponse) return corsResponse

    try {
        const url = new URL(req.url)
        const pathParts = url.pathname.split('/').filter(Boolean)
        const id = pathParts[1]
        const action = pathParts[2] // /users/{id}/roles

        const ctx = await getAuthContext(req)

        switch (req.method) {
            case 'GET':
                if (id === 'me') return await getCurrentUser(ctx)
                if (id && action === 'roles') return await getUserRoles(ctx, id)
                if (id) return await getUser(ctx, id)
                return await getUsers(ctx, url.searchParams)

            case 'POST':
                if (id && action === 'roles') return await assignRoles(ctx, id, req)
                return await createUser(ctx, req)

            case 'PUT':
            case 'PATCH':
                if (id === 'me') return await updateCurrentUser(ctx, req)
                if (!id) throw createError('VALIDATION_ERROR', 'User ID required')
                return await updateUser(ctx, id, req)

            case 'DELETE':
                if (id && action === 'roles') return await removeRoles(ctx, id, req)
                if (!id) throw createError('VALIDATION_ERROR', 'User ID required')
                return await deleteUser(ctx, id)

            default:
                throw createError('VALIDATION_ERROR', 'Method not allowed')
        }
    } catch (error) {
        return handleError(error)
    }
})

async function getUsers(ctx: any, params: URLSearchParams) {
    requirePermission(ctx, 'users.read')

    const pagination = validate(paginationSchema, {
        page: params.get('page'),
        limit: params.get('limit'),
        sortBy: params.get('sortBy') || 'created_at',
        sortOrder: params.get('sortOrder')
    })

    const search = params.get('search')
    const departmentId = params.get('department_id')
    const roleId = params.get('role_id')
    const isActive = params.get('is_active')

    let query = ctx.supabaseAdmin
        .from('users')
        .select(`
            id, email, full_name, avatar_url, phone, is_active, created_at, updated_at,
            department:departments(id, name, code),
            user_roles(role:roles(id, name, code))
        `, { count: 'exact' })

    // Filters
    if (search) {
        query = query.or(`full_name.ilike.%${search}%,email.ilike.%${search}%`)
    }
    if (departmentId) {
        query = query.eq('department_id', departmentId)
    }
    if (isActive !== null && isActive !== undefined) {
        query = query.eq('is_active', isActive === 'true')
    }

    // Sorting and pagination
    query = query
        .order(pagination.sortBy, { ascending: pagination.sortOrder === 'asc' })
        .range((pagination.page - 1) * pagination.limit, pagination.page * pagination.limit - 1)

    const { data, error, count } = await query
    if (error) throw error

    // Transform response
    const users = data.map((user: any) => ({
        ...user,
        roles: user.user_roles?.map((ur: any) => ur.role) || [],
        user_roles: undefined
    }))

    return successResponse(users, {
        pagination: {
            page: pagination.page,
            limit: pagination.limit,
            total: count || 0,
            totalPages: Math.ceil((count || 0) / pagination.limit)
        }
    })
}

async function getUser(ctx: any, id: string) {
    const isOwnProfile = id === ctx.user.id
    
    if (isOwnProfile) {
        requireAnyPermission(ctx, ['users.read_own', 'users.read'])
    } else {
        requirePermission(ctx, 'users.read')
    }

    validate(idSchema, id)

    const { data, error } = await ctx.supabaseAdmin
        .from('users')
        .select(`
            *,
            department:departments(id, name, code),
            user_roles(role:roles(id, name, code, role_permissions(permission:permissions(id, code, name))))
        `)
        .eq('id', id)
        .single()

    if (error) {
        if (error.code === 'PGRST116') {
            throw createError('NOT_FOUND', 'User not found')
        }
        throw error
    }

    return successResponse({
        ...data,
        roles: data.user_roles?.map((ur: any) => ({
            ...ur.role,
            permissions: ur.role.role_permissions?.map((rp: any) => rp.permission) || []
        })) || [],
        user_roles: undefined
    })
}

async function getCurrentUser(ctx: any) {
    return getUser(ctx, ctx.user.id)
}

async function createUser(ctx: any, req: Request) {
    requirePermission(ctx, 'users.create')

    const body = await req.json()
    const { role_ids, ...userData } = validate(userCreateSchema.extend({
        role_ids: z.array(z.string().uuid()).optional()
    }), body)

    // Create auth user
    const { data: authUser, error: authError } = await ctx.supabaseAdmin.auth.admin.createUser({
        email: userData.email,
        email_confirm: true,
        user_metadata: {
            full_name: userData.full_name
        }
    })

    if (authError) throw authError

    // Update profile with additional data
    const { data: user, error: userError } = await ctx.supabaseAdmin
        .from('users')
        .update({
            phone: userData.phone,
            department_id: userData.department_id
        })
        .eq('id', authUser.user.id)
        .select()
        .single()

    if (userError) throw userError

    // Assign roles if provided
    if (role_ids?.length) {
        await ctx.supabaseAdmin
            .from('user_roles')
            .insert(role_ids.map((rid: string) => ({
                user_id: user.id,
                role_id: rid,
                assigned_by: ctx.user.id
            })))
    }

    return createdResponse(user)
}

async function updateUser(ctx: any, id: string, req: Request) {
    const isOwnProfile = id === ctx.user.id

    if (isOwnProfile) {
        requireAnyPermission(ctx, ['users.update_own', 'users.update'])
    } else {
        requirePermission(ctx, 'users.update')
    }

    validate(idSchema, id)
    const body = await req.json()
    const validatedData = validate(userUpdateSchema, body)

    // If updating own profile, can't change is_active
    if (isOwnProfile && validatedData.is_active !== undefined) {
        delete validatedData.is_active
    }

    const { data, error } = await ctx.supabaseAdmin
        .from('users')
        .update(validatedData)
        .eq('id', id)
        .select(`
            *,
            department:departments(id, name, code)
        `)
        .single()

    if (error) throw error

    return successResponse(data)
}

async function updateCurrentUser(ctx: any, req: Request) {
    return updateUser(ctx, ctx.user.id, req)
}

async function deleteUser(ctx: any, id: string) {
    requirePermission(ctx, 'users.delete')
    validate(idSchema, id)

    // Can't delete yourself
    if (id === ctx.user.id) {
        throw createError('FORBIDDEN', 'Cannot delete your own account')
    }

    // Soft delete - deactivate user
    const { error: userError } = await ctx.supabaseAdmin
        .from('users')
        .update({ is_active: false })
        .eq('id', id)

    if (userError) throw userError

    // Optionally disable auth user
    await ctx.supabaseAdmin.auth.admin.updateUserById(id, {
        ban_duration: '876000h' // ~100 years (effectively permanent)
    })

    return noContentResponse()
}

async function getUserRoles(ctx: any, userId: string) {
    requirePermission(ctx, 'roles.read')
    validate(idSchema, userId)

    const { data, error } = await ctx.supabaseAdmin
        .from('user_roles')
        .select('*, role:roles(*)')
        .eq('user_id', userId)

    if (error) throw error

    return successResponse(data.map((ur: any) => ({
        ...ur.role,
        assigned_at: ur.assigned_at,
        expires_at: ur.expires_at
    })))
}

async function assignRoles(ctx: any, userId: string, req: Request) {
    requirePermission(ctx, 'roles.assign')
    validate(idSchema, userId)

    const { role_ids, expires_at } = await req.json()

    const { error } = await ctx.supabaseAdmin
        .from('user_roles')
        .upsert(
            role_ids.map((rid: string) => ({
                user_id: userId,
                role_id: rid,
                assigned_by: ctx.user.id,
                expires_at
            })),
            { onConflict: 'user_id,role_id' }
        )

    if (error) throw error

    return getUserRoles(ctx, userId)
}

async function removeRoles(ctx: any, userId: string, req: Request) {
    requirePermission(ctx, 'roles.assign')
    validate(idSchema, userId)

    const { role_ids } = await req.json()

    const { error } = await ctx.supabaseAdmin
        .from('user_roles')
        .delete()
        .eq('user_id', userId)
        .in('role_id', role_ids)

    if (error) throw error

    return noContentResponse()
}
```

---

## Phase 6: Department CRUD Implementation

### 6.1 Department API

```typescript
// supabase/functions/departments/index.ts
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { handleCors } from '../_shared/cors.ts'
import { getAuthContext, requirePermission } from '../_shared/auth.ts'
import { handleError, createError } from '../_shared/error-handler.ts'
import { validate, departmentCreateSchema, departmentUpdateSchema, idSchema, paginationSchema } from '../_shared/validation.ts'
import { successResponse, createdResponse, noContentResponse } from '../_shared/response.ts'

serve(async (req) => {
    const corsResponse = handleCors(req)
    if (corsResponse) return corsResponse

    try {
        const url = new URL(req.url)
        const pathParts = url.pathname.split('/').filter(Boolean)
        const id = pathParts[1]
        const action = pathParts[2] // /departments/{id}/users, /departments/{id}/hierarchy

        const ctx = await getAuthContext(req)

        switch (req.method) {
            case 'GET':
                if (id && action === 'users') return await getDepartmentUsers(ctx, id, url.searchParams)
                if (id && action === 'hierarchy') return await getDepartmentHierarchy(ctx, id)
                if (id) return await getDepartment(ctx, id)
                return await getDepartments(ctx, url.searchParams)

            case 'POST':
                return await createDepartment(ctx, req)

            case 'PUT':
            case 'PATCH':
                if (!id) throw createError('VALIDATION_ERROR', 'Department ID required')
                return await updateDepartment(ctx, id, req)

            case 'DELETE':
                if (!id) throw createError('VALIDATION_ERROR', 'Department ID required')
                return await deleteDepartment(ctx, id)

            default:
                throw createError('VALIDATION_ERROR', 'Method not allowed')
        }
    } catch (error) {
        return handleError(error)
    }
})

async function getDepartments(ctx: any, params: URLSearchParams) {
    requirePermission(ctx, 'departments.read')

    const pagination = validate(paginationSchema, {
        page: params.get('page'),
        limit: params.get('limit'),
        sortBy: params.get('sortBy') || 'name',
        sortOrder: params.get('sortOrder')
    })

    const search = params.get('search')
    const parentId = params.get('parent_id')
    const isActive = params.get('is_active')
    const flat = params.get('flat') === 'true' // Return flat list or tree

    let query = ctx.supabaseAdmin
        .from('departments')
        .select(`
            id, name, code, description, parent_id, is_active, created_at, updated_at,
            manager:users!manager_id(id, full_name, email, avatar_url),
            parent:departments!parent_id(id, name, code),
            _count:users(count)
        `, { count: 'exact' })

    if (search) {
        query = query.or(`name.ilike.%${search}%,code.ilike.%${search}%`)
    }
    if (parentId) {
        query = query.eq('parent_id', parentId)
    } else if (!flat) {
        // Only get root departments for tree view
        query = query.is('parent_id', null)
    }
    if (isActive !== null && isActive !== undefined) {
        query = query.eq('is_active', isActive === 'true')
    }

    query = query
        .order(pagination.sortBy, { ascending: pagination.sortOrder === 'asc' })
        .range((pagination.page - 1) * pagination.limit, pagination.page * pagination.limit - 1)

    const { data, error, count } = await query
    if (error) throw error

    // Transform to include user count
    const departments = data.map((dept: any) => ({
        ...dept,
        user_count: dept._count?.[0]?.count || 0,
        _count: undefined
    }))

    return successResponse(departments, {
        pagination: {
            page: pagination.page,
            limit: pagination.limit,
            total: count || 0,
            totalPages: Math.ceil((count || 0) / pagination.limit)
        }
    })
}

async function getDepartment(ctx: any, id: string) {
    requirePermission(ctx, 'departments.read')
    validate(idSchema, id)

    const { data, error } = await ctx.supabaseAdmin
        .from('departments')
        .select(`
            *,
            manager:users!manager_id(id, full_name, email, avatar_url),
            parent:departments!parent_id(id, name, code),
            children:departments!parent_id(id, name, code, is_active)
        `)
        .eq('id', id)
        .single()

    if (error) {
        if (error.code === 'PGRST116') {
            throw createError('NOT_FOUND', 'Department not found')
        }
        throw error
    }

    // Get user count
    const { count } = await ctx.supabaseAdmin
        .from('users')
        .select('*', { count: 'exact', head: true })
        .eq('department_id', id)

    return successResponse({
        ...data,
        user_count: count || 0
    })
}

async function getDepartmentHierarchy(ctx: any, id: string) {
    requirePermission(ctx, 'departments.read')
    validate(idSchema, id)

    const { data, error } = await ctx.supabaseAdmin
        .rpc('get_department_hierarchy', { p_department_id: id })

    if (error) throw error

    return successResponse(data)
}

async function getDepartmentUsers(ctx: any, id: string, params: URLSearchParams) {
    requirePermission(ctx, 'departments.read')
    validate(idSchema, id)

    const page = parseInt(params.get('page') || '1')
    const limit = parseInt(params.get('limit') || '10')

    const { data, error, count } = await ctx.supabaseAdmin
        .from('users')
        .select('id, email, full_name, avatar_url, is_active', { count: 'exact' })
        .eq('department_id', id)
        .order('full_name')
        .range((page - 1) * limit, page * limit - 1)

    if (error) throw error

    return successResponse(data, {
        pagination: { page, limit, total: count || 0, totalPages: Math.ceil((count || 0) / limit) }
    })
}

async function createDepartment(ctx: any, req: Request) {
    requirePermission(ctx, 'departments.create')

    const body = await req.json()
    const validatedData = validate(departmentCreateSchema, body)

    // Check if code is unique
    const { data: existing } = await ctx.supabaseAdmin
        .from('departments')
        .select('id')
        .eq('code', validatedData.code)
        .single()

    if (existing) {
        throw createError('CONFLICT', 'Department code already exists')
    }

    // Validate parent exists if provided
    if (validatedData.parent_id) {
        const { data: parent } = await ctx.supabaseAdmin
            .from('departments')
            .select('id')
            .eq('id', validatedData.parent_id)
            .single()

        if (!parent) {
            throw createError('VALIDATION_ERROR', 'Parent department not found')
        }
    }

    const { data, error } = await ctx.supabaseAdmin
        .from('departments')
        .insert({
            ...validatedData,
            created_by: ctx.user.id
        })
        .select(`
            *,
            manager:users!manager_id(id, full_name, email),
            parent:departments!parent_id(id, name, code)
        `)
        .single()

    if (error) throw error

    return createdResponse(data)
}

async function updateDepartment(ctx: any, id: string, req: Request) {
    requirePermission(ctx, 'departments.update')
    validate(idSchema, id)

    const body = await req.json()
    const validatedData = validate(departmentUpdateSchema, body)

    // Prevent circular reference
    if (validatedData.parent_id === id) {
        throw createError('VALIDATION_ERROR', 'Department cannot be its own parent')
    }

    const { data, error } = await ctx.supabaseAdmin
        .from('departments')
        .update(validatedData)
        .eq('id', id)
        .select(`
            *,
            manager:users!manager_id(id, full_name, email),
            parent:departments!parent_id(id, name, code)
        `)
        .single()

    if (error) throw error

    return successResponse(data)
}

async function deleteDepartment(ctx: any, id: string) {
    requirePermission(ctx, 'departments.delete')
    validate(idSchema, id)

    // Check if department has users
    const { count: userCount } = await ctx.supabaseAdmin
        .from('users')
        .select('*', { count: 'exact', head: true })
        .eq('department_id', id)

    if (userCount && userCount > 0) {
        throw createError('CONFLICT', 'Cannot delete department with users. Reassign users first.')
    }

    // Check if department has children
    const { count: childCount } = await ctx.supabaseAdmin
        .from('departments')
        .select('*', { count: 'exact', head: true })
        .eq('parent_id', id)

    if (childCount && childCount > 0) {
        throw createError('CONFLICT', 'Cannot delete department with sub-departments')
    }

    // Soft delete
    const { error } = await ctx.supabaseAdmin
        .from('departments')
        .update({ is_active: false })
        .eq('id', id)

    if (error) throw error

    return noContentResponse()
}
```

---

## Phase 7: React Frontend Setup

### 7.1 Project Initialization

```bash
# Create React app with Vite
npm create vite@latest frontend -- --template react-ts
cd frontend

# Install dependencies
npm install @supabase/supabase-js @tanstack/react-query axios zustand
npm install react-router-dom react-hook-form @hookform/resolvers zod
npm install -D tailwindcss postcss autoprefixer
npm install @headlessui/react @heroicons/react

# Initialize Tailwind
npx tailwindcss init -p
```

### 7.2 Project Structure

```
frontend/
├── src/
│   ├── api/
│   │   ├── client.ts              # Axios/fetch client
│   │   ├── endpoints.ts           # API endpoints
│   │   └── types.ts               # API types
│   ├── components/
│   │   ├── common/
│   │   │   ├── Button.tsx
│   │   │   ├── Input.tsx
│   │   │   ├── Modal.tsx
│   │   │   ├── Table.tsx
│   │   │   ├── Pagination.tsx
│   │   │   └── ErrorBoundary.tsx
│   │   ├── forms/
│   │   │   ├── UserForm.tsx
│   │   │   ├── DepartmentForm.tsx
│   │   │   └── RoleForm.tsx
│   │   └── layout/
│   │       ├── Header.tsx
│   │       ├── Sidebar.tsx
│   │       └── MainLayout.tsx
│   ├── features/
│   │   ├── auth/
│   │   ├── users/
│   │   ├── departments/
│   │   └── roles/
│   ├── hooks/
│   │   ├── useAuth.ts
│   │   ├── usePermissions.ts
│   │   ├── useGenericCrud.ts
│   │   └── useDebounce.ts
│   ├── lib/
│   │   ├── supabase.ts
│   │   ├── queryClient.ts
│   │   └── utils.ts
│   ├── providers/
│   │   ├── AuthProvider.tsx
│   │   ├── QueryProvider.tsx
│   │   └── ToastProvider.tsx
│   ├── stores/
│   │   ├── authStore.ts
│   │   └── uiStore.ts
│   ├── types/
│   │   └── index.ts
│   ├── App.tsx
│   └── main.tsx
├── .env
├── tailwind.config.js
└── vite.config.ts
```

### 7.3 Core Configuration

```typescript
// src/lib/supabase.ts
import { createClient } from '@supabase/supabase-js'
import type { Database } from './database.types'

export const supabase = createClient<Database>(
    import.meta.env.VITE_SUPABASE_URL,
    import.meta.env.VITE_SUPABASE_ANON_KEY
)
```

```typescript
// src/lib/queryClient.ts
import { QueryClient } from '@tanstack/react-query'

export const queryClient = new QueryClient({
    defaultOptions: {
        queries: {
            staleTime: 1000 * 60 * 5, // 5 minutes
            gcTime: 1000 * 60 * 30,   // 30 minutes
            retry: 1,
            refetchOnWindowFocus: false
        },
        mutations: {
            retry: 0
        }
    }
})
```

```typescript
// src/api/client.ts
import { supabase } from '@/lib/supabase'

interface ApiOptions {
    method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
    body?: unknown
    params?: Record<string, string | number | boolean | undefined>
}

interface ApiResponse<T> {
    success: boolean
    data?: T
    error?: {
        code: string
        message: string
        details?: unknown
    }
    meta?: {
        pagination?: {
            page: number
            limit: number
            total: number
            totalPages: number
        }
    }
}

class ApiError extends Error {
    constructor(
        public code: string,
        message: string,
        public statusCode: number,
        public details?: unknown
    ) {
        super(message)
        this.name = 'ApiError'
    }
}

export async function apiClient<T>(
    endpoint: string,
    options: ApiOptions = {}
): Promise<ApiResponse<T>> {
    const { method = 'GET', body, params } = options

    // Get current session token
    const { data: { session } } = await supabase.auth.getSession()
    
    if (!session?.access_token) {
        throw new ApiError('UNAUTHORIZED', 'Not authenticated', 401)
    }

    // Build URL with params
    const url = new URL(`${import.meta.env.VITE_SUPABASE_URL}/functions/v1/${endpoint}`)
    if (params) {
        Object.entries(params).forEach(([key, value]) => {
            if (value !== undefined) {
                url.searchParams.set(key, String(value))
            }
        })
    }

    const response = await fetch(url.toString(), {
        method,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${session.access_token}`
        },
        ...(body && { body: JSON.stringify(body) })
    })

    const data = await response.json()

    if (!response.ok || !data.success) {
        throw new ApiError(
            data.error?.code || 'UNKNOWN',
            data.error?.message || 'Request failed',
            response.status,
            data.error?.details
        )
    }

    return data
}
```

---

## Phase 8: Frontend Generic CRUD & State Management

### 8.1 Generic CRUD Hook

```typescript
// src/hooks/useGenericCrud.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import { useState, useCallback } from 'react'

interface PaginationParams {
    page?: number
    limit?: number
    sortBy?: string
    sortOrder?: 'asc' | 'desc'
    search?: string
    [key: string]: string | number | boolean | undefined
}

interface UseCrudOptions<T> {
    endpoint: string
    queryKey: string
    defaultParams?: PaginationParams
    transformResponse?: (data: any) => T
    onCreateSuccess?: (data: T) => void
    onUpdateSuccess?: (data: T) => void
    onDeleteSuccess?: () => void
}

export function useGenericCrud<T extends { id: string }>({
    endpoint,
    queryKey,
    defaultParams = {},
    transformResponse,
    onCreateSuccess,
    onUpdateSuccess,
    onDeleteSuccess
}: UseCrudOptions<T>) {
    const queryClient = useQueryClient()
    const [params, setParams] = useState<PaginationParams>({
        page: 1,
        limit: 10,
        ...defaultParams
    })

    // ============================================
    // LIST QUERY
    // ============================================
    const listQuery = useQuery({
        queryKey: [queryKey, 'list', params],
        queryFn: async () => {
            const response = await apiClient<T[]>(endpoint, { params })
            return {
                data: transformResponse ? response.data?.map(transformResponse) : response.data,
                pagination: response.meta?.pagination
            }
        },
        placeholderData: (prev) => prev
    })

    // ============================================
    // SINGLE ITEM QUERY
    // ============================================
    const useItem = (id: string | undefined) => {
        return useQuery({
            queryKey: [queryKey, 'detail', id],
            queryFn: async () => {
                const response = await apiClient<T>(`${endpoint}/${id}`)
                return transformResponse ? transformResponse(response.data) : response.data
            },
            enabled: !!id
        })
    }

    // ============================================
    // CREATE MUTATION
    // ============================================
    const createMutation = useMutation({
        mutationFn: async (data: Partial<T>) => {
            const response = await apiClient<T>(endpoint, {
                method: 'POST',
                body: data
            })
            return response.data!
        },
        onSuccess: (data) => {
            queryClient.invalidateQueries({ queryKey: [queryKey, 'list'] })
            onCreateSuccess?.(data)
        }
    })

    // ============================================
    // UPDATE MUTATION
    // ============================================
    const updateMutation = useMutation({
        mutationFn: async ({ id, data }: { id: string; data: Partial<T> }) => {
            const response = await apiClient<T>(`${endpoint}/${id}`, {
                method: 'PATCH',
                body: data
            })
            return response.data!
        },
        onSuccess: (data) => {
            queryClient.invalidateQueries({ queryKey: [queryKey, 'list'] })
            queryClient.setQueryData([queryKey, 'detail', data.id], data)
            onUpdateSuccess?.(data)
        }
    })

    // ============================================
    // DELETE MUTATION
    // ============================================
    const deleteMutation = useMutation({
        mutationFn: async (id: string) => {
            await apiClient(`${endpoint}/${id}`, { method: 'DELETE' })
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: [queryKey, 'list'] })
            onDeleteSuccess?.()
        }
    })

    // ============================================
    // PAGINATION HELPERS
    // ============================================
    const setPage = useCallback((page: number) => {
        setParams(prev => ({ ...prev, page }))
    }, [])

    const setLimit = useCallback((limit: number) => {
        setParams(prev => ({ ...prev, limit, page: 1 }))
    }, [])

    const setSearch = useCallback((search: string) => {
        setParams(prev => ({ ...prev, search, page: 1 }))
    }, [])

    const setSort = useCallback((sortBy: string, sortOrder: 'asc' | 'desc' = 'asc') => {
        setParams(prev => ({ ...prev, sortBy, sortOrder }))
    }, [])

    const setFilters = useCallback((filters: Record<string, any>) => {
        setParams(prev => ({ ...prev, ...filters, page: 1 }))
    }, [])

    const resetFilters = useCallback(() => {
        setParams({ page: 1, limit: 10, ...defaultParams })
    }, [defaultParams])

    return {
        // List data
        items: listQuery.data?.data || [],
        pagination: listQuery.data?.pagination,
        isLoading: listQuery.isLoading,
        isFetching: listQuery.isFetching,
        error: listQuery.error,
        refetch: listQuery.refetch,

        // Single item
        useItem,

        // Mutations
        create: createMutation.mutateAsync,
        update: updateMutation.mutateAsync,
        delete: deleteMutation.mutateAsync,
        isCreating: createMutation.isPending,
        isUpdating: updateMutation.isPending,
        isDeleting: deleteMutation.isPending,

        // Pagination controls
        params,
        setPage,
        setLimit,
        setSearch,
        setSort,
        setFilters,
        resetFilters
    }
}
```

### 8.2 Permission Hook

```typescript
// src/hooks/usePermissions.ts
import { useQuery } from '@tanstack/react-query'
import { supabase } from '@/lib/supabase'
import { useAuth } from './useAuth'
import { useCallback, useMemo } from 'react'

export function usePermissions() {
    const { user, isAuthenticated } = useAuth()

    const { data: permissions = [], isLoading } = useQuery({
        queryKey: ['permissions', user?.id],
        queryFn: async () => {
            const { data, error } = await supabase.rpc('get_my_permissions')
            if (error) throw error
            return data.map((p: any) => p.permission_code)
        },
        enabled: isAuthenticated,
        staleTime: 1000 * 60 * 10 // 10 minutes
    })

    const can = useCallback((permission: string) => {
        return permissions.includes(permission)
    }, [permissions])

    const canAny = useCallback((perms: string[]) => {
        return perms.some(p => permissions.includes(p))
    }, [permissions])

    const canAll = useCallback((perms: string[]) => {
        return perms.every(p => permissions.includes(p))
    }, [permissions])

    // Group permissions by resource
    const permissionsByResource = useMemo(() => {
        return permissions.reduce((acc: Record<string, string[]>, perm: string) => {
            const [resource] = perm.split('.')
            if (!acc[resource]) acc[resource] = []
            acc[resource].push(perm)
            return acc
        }, {})
    }, [permissions])

    return {
        permissions,
        permissionsByResource,
        can,
        canAny,
        canAll,
        isLoading
    }
}

// Permission guard component
export function Can({ 
    permission, 
    children, 
    fallback = null 
}: { 
    permission: string | string[]
    children: React.ReactNode
    fallback?: React.ReactNode 
}) {
    const { can, canAny } = usePermissions()

    const hasPermission = Array.isArray(permission)
        ? canAny(permission)
        : can(permission)

    return hasPermission ? <>{children}</> : <>{fallback}</>
}
```

### 8.3 Generic Error Handling

```typescript
// src/lib/errorHandler.ts
import { toast } from 'react-hot-toast'

interface ApiError {
    code: string
    message: string
    statusCode: number
    details?: unknown
}

const errorMessages: Record<string, string> = {
    UNAUTHORIZED: 'Please sign in to continue',
    FORBIDDEN: 'You do not have permission to perform this action',
    NOT_FOUND: 'The requested resource was not found',
    CONFLICT: 'This record already exists',
    VALIDATION_ERROR: 'Please check your input and try again',
    RATE_LIMITED: 'Too many requests. Please try again later',
    INTERNAL_ERROR: 'An unexpected error occurred. Please try again'
}

export function handleError(error: unknown): void {
    console.error('Error:', error)

    if (error instanceof Error && 'code' in error) {
        const apiError = error as unknown as ApiError
        const message = errorMessages[apiError.code] || apiError.message
        
        toast.error(message)

        // Handle specific errors
        if (apiError.code === 'UNAUTHORIZED') {
            // Redirect to login
            window.location.href = '/login'
        }
        
        return
    }

    toast.error('An unexpected error occurred')
}

// React Query error handler
export function onQueryError(error: unknown): void {
    handleError(error)
}

// Mutation error handler with field-level errors
export function getMutationErrorHandler(setError?: (field: string, error: { message: string }) => void) {
    return (error: unknown) => {
        handleError(error)

        // Set field-level errors if validation error
        if (error instanceof Error && 'details' in error) {
            const details = (error as any).details
            if (Array.isArray(details) && setError) {
                details.forEach((d: { field: string; message: string }) => {
                    setError(d.field, { message: d.message })
                })
            }
        }
    }
}
```

### 8.4 Example: Users Feature

```typescript
// src/features/users/hooks/useUsers.ts
import { useGenericCrud } from '@/hooks/useGenericCrud'
import { User } from '@/types'
import { toast } from 'react-hot-toast'

export function useUsers() {
    return useGenericCrud<User>({
        endpoint: 'users',
        queryKey: 'users',
        defaultParams: {
            sortBy: 'created_at',
            sortOrder: 'desc'
        },
        onCreateSuccess: () => toast.success('User created successfully'),
        onUpdateSuccess: () => toast.success('User updated successfully'),
        onDeleteSuccess: () => toast.success('User deleted successfully')
    })
}

export function useUser(id: string | undefined) {
    const { useItem } = useUsers()
    return useItem(id)
}
```

```typescript
// src/features/users/components/UserList.tsx
import { useState } from 'react'
import { useUsers } from '../hooks/useUsers'
import { usePermissions, Can } from '@/hooks/usePermissions'
import { Table, Pagination, SearchInput, Button, Modal } from '@/components/common'
import { UserForm } from './UserForm'
import { useDebounce } from '@/hooks/useDebounce'

export function UserList() {
    const [showCreateModal, setShowCreateModal] = useState(false)
    const [editingUser, setEditingUser] = useState<User | null>(null)
    const [searchTerm, setSearchTerm] = useState('')
    const debouncedSearch = useDebounce(searchTerm, 300)

    const {
        items: users,
        pagination,
        isLoading,
        setPage,
        setSearch,
        create,
        update,
        delete: deleteUser,
        isCreating,
        isUpdating
    } = useUsers()

    // Update search when debounced value changes
    useEffect(() => {
        setSearch(debouncedSearch)
    }, [debouncedSearch, setSearch])

    const handleCreate = async (data: Partial<User>) => {
        await create(data)
        setShowCreateModal(false)
    }

    const handleUpdate = async (data: Partial<User>) => {
        if (editingUser) {
            await update({ id: editingUser.id, data })
            setEditingUser(null)
        }
    }

    const handleDelete = async (id: string) => {
        if (confirm('Are you sure you want to delete this user?')) {
            await deleteUser(id)
        }
    }

    const columns = [
        { key: 'full_name', label: 'Name', sortable: true },
        { key: 'email', label: 'Email', sortable: true },
        { key: 'department.name', label: 'Department' },
        { 
            key: 'roles', 
            label: 'Roles',
            render: (user: User) => user.roles?.map(r => r.name).join(', ')
        },
        { 
            key: 'is_active', 
            label: 'Status',
            render: (user: User) => (
                <span className={user.is_active ? 'text-green-600' : 'text-red-600'}>
                    {user.is_active ? 'Active' : 'Inactive'}
                </span>
            )
        },
        {
            key: 'actions',
            label: 'Actions',
            render: (user: User) => (
                <div className="flex gap-2">
                    <Can permission="users.update">
                        <Button size="sm" onClick={() => setEditingUser(user)}>
                            Edit
                        </Button>
                    </Can>
                    <Can permission="users.delete">
                        <Button size="sm" variant="danger" onClick={() => handleDelete(user.id)}>
                            Delete
                        </Button>
                    </Can>
                </div>
            )
        }
    ]

    return (
        <div className="space-y-4">
            <div className="flex justify-between items-center">
                <h1 className="text-2xl font-bold">Users</h1>
                <Can permission="users.create">
                    <Button onClick={() => setShowCreateModal(true)}>
                        Add User
                    </Button>
                </Can>
            </div>

            <div className="flex gap-4">
                <SearchInput
                    value={searchTerm}
                    onChange={setSearchTerm}
                    placeholder="Search users..."
                />
            </div>

            <Table
                columns={columns}
                data={users}
                isLoading={isLoading}
            />

            {pagination && (
                <Pagination
                    page={pagination.page}
                    totalPages={pagination.totalPages}
                    onPageChange={setPage}
                />
            )}

            {/* Create Modal */}
            <Modal
                isOpen={showCreateModal}
                onClose={() => setShowCreateModal(false)}
                title="Create User"
            >
                <UserForm
                    onSubmit={handleCreate}
                    isLoading={isCreating}
                />
            </Modal>

            {/* Edit Modal */}
            <Modal
                isOpen={!!editingUser}
                onClose={() => setEditingUser(null)}
                title="Edit User"
            >
                <UserForm
                    user={editingUser}
                    onSubmit={handleUpdate}
                    isLoading={isUpdating}
                />
            </Modal>
        </div>
    )
}
```

---

## Phase 9: Testing & Optimization

### 9.1 Backend Testing Checklist

- [ ] Unit tests for validation schemas
- [ ] Integration tests for each CRUD endpoint
- [ ] RLS policy tests
- [ ] Permission function tests
- [ ] Rate limiting tests
- [ ] Error handling tests

### 9.2 Frontend Testing Checklist

- [ ] Component unit tests (React Testing Library)
- [ ] Hook tests
- [ ] Integration tests with MSW
- [ ] E2E tests with Playwright

### 9.3 Performance Optimization

| Area | Optimization | Implementation |
|------|--------------|----------------|
| Database | Indexes | Add for all filtered columns |
| Database | Materialized Views | For complex aggregations |
| API | Response caching | Cache-Control headers |
| Frontend | React Query staleTime | 5min for lists, 10min for details |
| Frontend | Pagination | Limit 10-25 items per page |
| Frontend | Debounced search | 300ms debounce |
| Frontend | Bundle splitting | Lazy load routes |

---

## Phase 10: Deployment & Monitoring

### 10.1 Deployment Checklist

- [ ] Environment variables configured
- [ ] Database migrations applied
- [ ] Edge functions deployed
- [ ] RLS policies tested in production
- [ ] CORS configured properly
- [ ] SSL/HTTPS verified

### 10.2 Monitoring Setup

- [ ] Supabase dashboard alerts
- [ ] Error tracking (Sentry)
- [ ] Performance monitoring
- [ ] Audit log review process

---

## Quick Reference

### API Endpoints

| Endpoint | Method | Permission | Description |
|----------|--------|------------|-------------|
| `/users` | GET | users.read | List users |
| `/users/:id` | GET | users.read | Get user |
| `/users` | POST | users.create | Create user |
| `/users/:id` | PATCH | users.update | Update user |
| `/users/:id` | DELETE | users.delete | Delete user |
| `/departments` | GET | departments.read | List departments |
| `/roles` | GET | roles.read | List roles |
| `/roles/:id/permissions` | POST | permissions.manage | Assign permissions |

### Permission Codes

```
users.create, users.read, users.read_own, users.update, users.update_own, users.delete
departments.create, departments.read, departments.update, departments.delete
roles.create, roles.read, roles.update, roles.delete, roles.assign
permissions.read, permissions.manage
audit.read
settings.read, settings.update
```

---

## Next Steps

1. **Complete Phase 1-2**: Set up project and create all migrations
2. **Complete Phase 3-4**: Implement generic CRUD and roles/permissions
3. **Complete Phase 5-6**: Build users and departments APIs
4. **Complete Phase 7-8**: Set up React frontend with generic patterns
5. **Test everything** before moving to production
