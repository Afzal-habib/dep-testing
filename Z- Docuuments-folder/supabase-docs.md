# Complete Supabase Guide: From Scratch to Advanced

## Table of Contents
1. [Introduction to Supabase](#1-introduction-to-supabase)
2. [Setup & Installation](#2-setup--installation)
3. [Database Schema Design](#3-database-schema-design)
4. [CRUD Operations](#4-crud-operations)
5. [Authentication](#5-authentication)
6. [Authorization - RLS, Roles & Permissions](#6-authorization---rls-roles--permissions)
7. [Edge Functions](#7-edge-functions)
8. [Security Layers](#8-security-layers)
9. [Migrations & Seeders](#9-migrations--seeders)
10. [Prisma ORM Integration](#10-prisma-orm-integration)
11. [React.js Integration](#11-reactjs-integration)
12. [Caching & Optimization](#12-caching--optimization)
13. [VS Code Setup](#13-vs-code-setup)
14. [Best Practices](#14-best-practices)

---

## 1. Introduction to Supabase

### What is Supabase?
Supabase is an open-source Firebase alternative providing:
- **PostgreSQL Database** - Full Postgres with extensions
- **Authentication** - Email, OAuth, Magic Links, Phone
- **Authorization** - Row Level Security (RLS)
- **Realtime** - WebSocket subscriptions
- **Storage** - File storage with CDN
- **Edge Functions** - Serverless Deno functions
- **Auto-generated APIs** - REST & GraphQL

### Why Choose Supabase?
- Open source & self-hostable
- Built on PostgreSQL (not proprietary)
- No vendor lock-in
- Generous free tier
- Real-time by default
- Built-in auth & storage

---

## 2. Setup & Installation

### 2.1 Create Supabase Project

```bash
# Install Supabase CLI
npm install -g supabase

# Login to Supabase
supabase login

# Initialize project
supabase init

# Start local development
supabase start
```

### 2.2 Project Structure
```
your-project/
├── supabase/
│   ├── config.toml           # Supabase configuration
│   ├── migrations/           # SQL migrations
│   ├── functions/            # Edge functions
│   ├── seed.sql              # Seed data
│   └── .env                  # Environment variables
├── src/
│   └── lib/
│       └── supabase.ts       # Supabase client
├── .env.local
└── package.json
```

### 2.3 Environment Variables
```env
# .env.local
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
```

### 2.4 Install Dependencies
```bash
npm install @supabase/supabase-js
npm install @supabase/auth-helpers-react  # For React
npm install @supabase/ssr                  # For SSR frameworks
```

---

## 3. Database Schema Design

### 3.1 Schema Best Practices

```sql
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create custom types
CREATE TYPE user_role AS ENUM ('admin', 'manager', 'user', 'guest');
CREATE TYPE order_status AS ENUM ('pending', 'processing', 'shipped', 'delivered', 'cancelled');

-- Create schemas for organization
CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS auth_custom;
```

### 3.2 Complete Schema Example

```sql
-- ============================================
-- USERS & PROFILES
-- ============================================

-- Profiles table (extends auth.users)
CREATE TABLE public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT,
    avatar_url TEXT,
    role user_role DEFAULT 'user',
    phone TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- ORGANIZATIONS & TEAMS
-- ============================================

CREATE TABLE public.organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    logo_url TEXT,
    settings JSONB DEFAULT '{}',
    created_by UUID REFERENCES public.profiles(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE public.organization_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
    role TEXT DEFAULT 'member',
    permissions JSONB DEFAULT '[]',
    joined_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, user_id)
);

-- ============================================
-- PRODUCTS & CATEGORIES
-- ============================================

CREATE TABLE public.categories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    description TEXT,
    parent_id UUID REFERENCES public.categories(id),
    image_url TEXT,
    sort_order INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE public.products (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    compare_price DECIMAL(10,2),
    cost_price DECIMAL(10,2),
    sku TEXT UNIQUE,
    barcode TEXT,
    quantity INTEGER DEFAULT 0,
    category_id UUID REFERENCES public.categories(id),
    images JSONB DEFAULT '[]',
    attributes JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    is_featured BOOLEAN DEFAULT false,
    created_by UUID REFERENCES public.profiles(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- ORDERS
-- ============================================

CREATE TABLE public.orders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_number TEXT UNIQUE NOT NULL,
    user_id UUID REFERENCES public.profiles(id),
    status order_status DEFAULT 'pending',
    subtotal DECIMAL(10,2) NOT NULL,
    tax DECIMAL(10,2) DEFAULT 0,
    shipping DECIMAL(10,2) DEFAULT 0,
    discount DECIMAL(10,2) DEFAULT 0,
    total DECIMAL(10,2) NOT NULL,
    shipping_address JSONB,
    billing_address JSONB,
    notes TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE public.order_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_id UUID REFERENCES public.orders(id) ON DELETE CASCADE,
    product_id UUID REFERENCES public.products(id),
    quantity INTEGER NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    total DECIMAL(10,2) NOT NULL,
    metadata JSONB DEFAULT '{}'
);

-- ============================================
-- INDEXES FOR PERFORMANCE
-- ============================================

CREATE INDEX idx_profiles_email ON public.profiles(email);
CREATE INDEX idx_profiles_role ON public.profiles(role);
CREATE INDEX idx_products_category ON public.products(category_id);
CREATE INDEX idx_products_slug ON public.products(slug);
CREATE INDEX idx_products_active ON public.products(is_active) WHERE is_active = true;
CREATE INDEX idx_orders_user ON public.orders(user_id);
CREATE INDEX idx_orders_status ON public.orders(status);
CREATE INDEX idx_orders_created ON public.orders(created_at DESC);
CREATE INDEX idx_order_items_order ON public.order_items(order_id);

-- Full-text search index
CREATE INDEX idx_products_search ON public.products 
    USING GIN(to_tsvector('english', name || ' ' || COALESCE(description, '')));

-- ============================================
-- TRIGGERS
-- ============================================

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_updated_at
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER set_updated_at
    BEFORE UPDATE ON public.products
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER set_updated_at
    BEFORE UPDATE ON public.orders
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Auto-create profile on signup
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.profiles (id, email, full_name, avatar_url)
    VALUES (
        NEW.id,
        NEW.email,
        NEW.raw_user_meta_data->>'full_name',
        NEW.raw_user_meta_data->>'avatar_url'
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION handle_new_user();

-- Generate order number
CREATE OR REPLACE FUNCTION generate_order_number()
RETURNS TRIGGER AS $$
BEGIN
    NEW.order_number = 'ORD-' || TO_CHAR(NOW(), 'YYYYMMDD') || '-' || 
                       LPAD(FLOOR(RANDOM() * 10000)::TEXT, 4, '0');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_order_number
    BEFORE INSERT ON public.orders
    FOR EACH ROW EXECUTE FUNCTION generate_order_number();
```

---

## 4. CRUD Operations

### 4.1 Supabase Client Setup

```typescript
// src/lib/supabase.ts
import { createClient } from '@supabase/supabase-js'
import type { Database } from './database.types'

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!

export const supabase = createClient<Database>(supabaseUrl, supabaseAnonKey)

// Admin client (server-side only)
export const supabaseAdmin = createClient<Database>(
    supabaseUrl,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    { auth: { autoRefreshToken: false, persistSession: false } }
)
```

### 4.2 Generate TypeScript Types

```bash
# Generate types from database
supabase gen types typescript --project-id your-project-id > src/lib/database.types.ts
```

### 4.3 Basic CRUD Operations

```typescript
// src/services/products.ts
import { supabase } from '@/lib/supabase'
import type { Database } from '@/lib/database.types'

type Product = Database['public']['Tables']['products']['Row']
type ProductInsert = Database['public']['Tables']['products']['Insert']
type ProductUpdate = Database['public']['Tables']['products']['Update']

// ============================================
// CREATE
// ============================================

export async function createProduct(data: ProductInsert) {
    const { data: product, error } = await supabase
        .from('products')
        .insert(data)
        .select()
        .single()
    
    if (error) throw error
    return product
}

// Bulk insert
export async function createProducts(products: ProductInsert[]) {
    const { data, error } = await supabase
        .from('products')
        .insert(products)
        .select()
    
    if (error) throw error
    return data
}

// ============================================
// READ
// ============================================

// Get all with pagination
export async function getProducts({
    page = 1,
    limit = 10,
    category,
    search,
    sortBy = 'created_at',
    sortOrder = 'desc'
}: {
    page?: number
    limit?: number
    category?: string
    search?: string
    sortBy?: string
    sortOrder?: 'asc' | 'desc'
}) {
    let query = supabase
        .from('products')
        .select('*, category:categories(*)', { count: 'exact' })
        .eq('is_active', true)
    
    // Filters
    if (category) {
        query = query.eq('category_id', category)
    }
    
    if (search) {
        query = query.or(`name.ilike.%${search}%,description.ilike.%${search}%`)
    }
    
    // Sorting
    query = query.order(sortBy, { ascending: sortOrder === 'asc' })
    
    // Pagination
    const from = (page - 1) * limit
    const to = from + limit - 1
    query = query.range(from, to)
    
    const { data, error, count } = await query
    
    if (error) throw error
    
    return {
        data,
        pagination: {
            page,
            limit,
            total: count || 0,
            totalPages: Math.ceil((count || 0) / limit)
        }
    }
}

// Get single
export async function getProduct(id: string) {
    const { data, error } = await supabase
        .from('products')
        .select(`
            *,
            category:categories(*),
            created_by:profiles(id, full_name, avatar_url)
        `)
        .eq('id', id)
        .single()
    
    if (error) throw error
    return data
}

// Get by slug
export async function getProductBySlug(slug: string) {
    const { data, error } = await supabase
        .from('products')
        .select('*, category:categories(*)')
        .eq('slug', slug)
        .single()
    
    if (error) throw error
    return data
}

// Full-text search
export async function searchProducts(query: string) {
    const { data, error } = await supabase
        .from('products')
        .select()
        .textSearch('name', query, { type: 'websearch' })
    
    if (error) throw error
    return data
}

// ============================================
// UPDATE
// ============================================

export async function updateProduct(id: string, data: ProductUpdate) {
    const { data: product, error } = await supabase
        .from('products')
        .update(data)
        .eq('id', id)
        .select()
        .single()
    
    if (error) throw error
    return product
}

// Bulk update
export async function updateProductsStatus(ids: string[], is_active: boolean) {
    const { data, error } = await supabase
        .from('products')
        .update({ is_active })
        .in('id', ids)
        .select()
    
    if (error) throw error
    return data
}

// ============================================
// DELETE
// ============================================

export async function deleteProduct(id: string) {
    const { error } = await supabase
        .from('products')
        .delete()
        .eq('id', id)
    
    if (error) throw error
}

// Soft delete
export async function softDeleteProduct(id: string) {
    return updateProduct(id, { is_active: false })
}

// Bulk delete
export async function deleteProducts(ids: string[]) {
    const { error } = await supabase
        .from('products')
        .delete()
        .in('id', ids)
    
    if (error) throw error
}

// ============================================
// ADVANCED QUERIES
// ============================================

// Aggregations using RPC
export async function getProductStats() {
    const { data, error } = await supabase.rpc('get_product_stats')
    if (error) throw error
    return data
}

// Related products
export async function getRelatedProducts(productId: string, categoryId: string) {
    const { data, error } = await supabase
        .from('products')
        .select()
        .eq('category_id', categoryId)
        .neq('id', productId)
        .eq('is_active', true)
        .limit(4)
    
    if (error) throw error
    return data
}
```

### 4.4 Database Functions for Complex Operations

```sql
-- Get product statistics
CREATE OR REPLACE FUNCTION get_product_stats()
RETURNS JSON AS $$
DECLARE
    result JSON;
BEGIN
    SELECT json_build_object(
        'total_products', COUNT(*),
        'active_products', COUNT(*) FILTER (WHERE is_active = true),
        'total_value', SUM(price * quantity),
        'avg_price', AVG(price),
        'out_of_stock', COUNT(*) FILTER (WHERE quantity = 0),
        'categories', (
            SELECT json_agg(row_to_json(c))
            FROM (
                SELECT 
                    cat.name,
                    COUNT(p.id) as product_count
                FROM categories cat
                LEFT JOIN products p ON p.category_id = cat.id
                GROUP BY cat.id, cat.name
            ) c
        )
    ) INTO result
    FROM products;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql;

-- Upsert product
CREATE OR REPLACE FUNCTION upsert_product(
    p_sku TEXT,
    p_name TEXT,
    p_price DECIMAL,
    p_quantity INTEGER
)
RETURNS products AS $$
DECLARE
    result products;
BEGIN
    INSERT INTO products (sku, name, price, quantity, slug)
    VALUES (p_sku, p_name, p_price, p_quantity, LOWER(REPLACE(p_name, ' ', '-')))
    ON CONFLICT (sku) DO UPDATE SET
        name = EXCLUDED.name,
        price = EXCLUDED.price,
        quantity = EXCLUDED.quantity,
        updated_at = NOW()
    RETURNING * INTO result;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql;
```

---

## 5. Authentication

### 5.1 Auth Configuration

```typescript
// src/lib/auth.ts
import { supabase } from './supabase'

export const auth = {
    // ============================================
    // SIGN UP
    // ============================================
    
    async signUp(email: string, password: string, metadata?: object) {
        const { data, error } = await supabase.auth.signUp({
            email,
            password,
            options: {
                data: metadata,
                emailRedirectTo: `${window.location.origin}/auth/callback`
            }
        })
        if (error) throw error
        return data
    },

    // ============================================
    // SIGN IN
    // ============================================
    
    async signIn(email: string, password: string) {
        const { data, error } = await supabase.auth.signInWithPassword({
            email,
            password
        })
        if (error) throw error
        return data
    },

    async signInWithOAuth(provider: 'google' | 'github' | 'discord') {
        const { data, error } = await supabase.auth.signInWithOAuth({
            provider,
            options: {
                redirectTo: `${window.location.origin}/auth/callback`,
                queryParams: {
                    access_type: 'offline',
                    prompt: 'consent'
                }
            }
        })
        if (error) throw error
        return data
    },

    async signInWithMagicLink(email: string) {
        const { data, error } = await supabase.auth.signInWithOtp({
            email,
            options: {
                emailRedirectTo: `${window.location.origin}/auth/callback`
            }
        })
        if (error) throw error
        return data
    },

    async signInWithPhone(phone: string) {
        const { data, error } = await supabase.auth.signInWithOtp({ phone })
        if (error) throw error
        return data
    },

    async verifyOtp(phone: string, token: string) {
        const { data, error } = await supabase.auth.verifyOtp({
            phone,
            token,
            type: 'sms'
        })
        if (error) throw error
        return data
    },

    // ============================================
    // SESSION MANAGEMENT
    // ============================================
    
    async getSession() {
        const { data: { session }, error } = await supabase.auth.getSession()
        if (error) throw error
        return session
    },

    async getUser() {
        const { data: { user }, error } = await supabase.auth.getUser()
        if (error) throw error
        return user
    },

    async signOut() {
        const { error } = await supabase.auth.signOut()
        if (error) throw error
    },

    async refreshSession() {
        const { data, error } = await supabase.auth.refreshSession()
        if (error) throw error
        return data
    },

    // ============================================
    // PASSWORD MANAGEMENT
    // ============================================
    
    async resetPassword(email: string) {
        const { data, error } = await supabase.auth.resetPasswordForEmail(email, {
            redirectTo: `${window.location.origin}/auth/reset-password`
        })
        if (error) throw error
        return data
    },

    async updatePassword(newPassword: string) {
        const { data, error } = await supabase.auth.updateUser({
            password: newPassword
        })
        if (error) throw error
        return data
    },

    // ============================================
    // USER MANAGEMENT
    // ============================================
    
    async updateUser(updates: { email?: string; data?: object }) {
        const { data, error } = await supabase.auth.updateUser(updates)
        if (error) throw error
        return data
    },

    // ============================================
    // AUTH STATE LISTENER
    // ============================================
    
    onAuthStateChange(callback: (event: string, session: any) => void) {
        return supabase.auth.onAuthStateChange(callback)
    }
}
```

### 5.2 Auth Callback Handler

```typescript
// src/app/auth/callback/route.ts (Next.js App Router)
import { createRouteHandlerClient } from '@supabase/auth-helpers-nextjs'
import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'

export async function GET(request: Request) {
    const requestUrl = new URL(request.url)
    const code = requestUrl.searchParams.get('code')

    if (code) {
        const supabase = createRouteHandlerClient({ cookies })
        await supabase.auth.exchangeCodeForSession(code)
    }

    return NextResponse.redirect(new URL('/dashboard', request.url))
}
```

### 5.3 Auth Context Provider

```typescript
// src/contexts/AuthContext.tsx
import { createContext, useContext, useEffect, useState } from 'react'
import { User, Session } from '@supabase/supabase-js'
import { supabase } from '@/lib/supabase'

interface AuthContextType {
    user: User | null
    session: Session | null
    loading: boolean
    signIn: (email: string, password: string) => Promise<void>
    signUp: (email: string, password: string) => Promise<void>
    signOut: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: React.ReactNode }) {
    const [user, setUser] = useState<User | null>(null)
    const [session, setSession] = useState<Session | null>(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        // Get initial session
        supabase.auth.getSession().then(({ data: { session } }) => {
            setSession(session)
            setUser(session?.user ?? null)
            setLoading(false)
        })

        // Listen for auth changes
        const { data: { subscription } } = supabase.auth.onAuthStateChange(
            async (event, session) => {
                setSession(session)
                setUser(session?.user ?? null)
                setLoading(false)
            }
        )

        return () => subscription.unsubscribe()
    }, [])

    const signIn = async (email: string, password: string) => {
        const { error } = await supabase.auth.signInWithPassword({ email, password })
        if (error) throw error
    }

    const signUp = async (email: string, password: string) => {
        const { error } = await supabase.auth.signUp({ email, password })
        if (error) throw error
    }

    const signOut = async () => {
        const { error } = await supabase.auth.signOut()
        if (error) throw error
    }

    return (
        <AuthContext.Provider value={{ user, session, loading, signIn, signUp, signOut }}>
            {children}
        </AuthContext.Provider>
    )
}

export const useAuth = () => {
    const context = useContext(AuthContext)
    if (!context) throw new Error('useAuth must be used within AuthProvider')
    return context
}
```

---

## 6. Authorization - RLS, Roles & Permissions

### 6.1 Enable Row Level Security

```sql
-- Enable RLS on all tables
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.order_items ENABLE ROW LEVEL SECURITY;
```

### 6.2 Basic RLS Policies

```sql
-- ============================================
-- PROFILES POLICIES
-- ============================================

-- Users can view their own profile
CREATE POLICY "Users can view own profile"
ON public.profiles FOR SELECT
USING (auth.uid() = id);

-- Users can update their own profile
CREATE POLICY "Users can update own profile"
ON public.profiles FOR UPDATE
USING (auth.uid() = id);

-- Public profiles (for public data)
CREATE POLICY "Public profiles are viewable"
ON public.profiles FOR SELECT
USING (true);

-- ============================================
-- PRODUCTS POLICIES
-- ============================================

-- Anyone can view active products
CREATE POLICY "Active products are viewable"
ON public.products FOR SELECT
USING (is_active = true);

-- Only admins can insert products
CREATE POLICY "Admins can insert products"
ON public.products FOR INSERT
WITH CHECK (
    EXISTS (
        SELECT 1 FROM public.profiles
        WHERE id = auth.uid() AND role = 'admin'
    )
);

-- Only admins can update products
CREATE POLICY "Admins can update products"
ON public.products FOR UPDATE
USING (
    EXISTS (
        SELECT 1 FROM public.profiles
        WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
);

-- Only admins can delete products
CREATE POLICY "Admins can delete products"
ON public.products FOR DELETE
USING (
    EXISTS (
        SELECT 1 FROM public.profiles
        WHERE id = auth.uid() AND role = 'admin'
    )
);

-- ============================================
-- ORDERS POLICIES
-- ============================================

-- Users can view their own orders
CREATE POLICY "Users can view own orders"
ON public.orders FOR SELECT
USING (auth.uid() = user_id);

-- Users can create their own orders
CREATE POLICY "Users can create orders"
ON public.orders FOR INSERT
WITH CHECK (auth.uid() = user_id);

-- Admins can view all orders
CREATE POLICY "Admins can view all orders"
ON public.orders FOR SELECT
USING (
    EXISTS (
        SELECT 1 FROM public.profiles
        WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
);

-- Admins can update orders
CREATE POLICY "Admins can update orders"
ON public.orders FOR UPDATE
USING (
    EXISTS (
        SELECT 1 FROM public.profiles
        WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
);
```

### 6.3 Dynamic Role-Based Permissions System

```sql
-- ============================================
-- PERMISSIONS TABLE
-- ============================================

CREATE TABLE public.permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- ROLES TABLE
-- ============================================

CREATE TABLE public.roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    is_system BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- ROLE PERMISSIONS (Many-to-Many)
-- ============================================

CREATE TABLE public.role_permissions (
    role_id UUID REFERENCES public.roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES public.permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- ============================================
-- USER ROLES
-- ============================================

CREATE TABLE public.user_roles (
    user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
    role_id UUID REFERENCES public.roles(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES public.organizations(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES public.profiles(id),
    granted_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id, organization_id)
);

-- ============================================
-- SEED DEFAULT PERMISSIONS
-- ============================================

INSERT INTO public.permissions (name, description, resource, action) VALUES
-- Product permissions
('products.create', 'Create products', 'products', 'create'),
('products.read', 'View products', 'products', 'read'),
('products.update', 'Update products', 'products', 'update'),
('products.delete', 'Delete products', 'products', 'delete'),
-- Order permissions
('orders.create', 'Create orders', 'orders', 'create'),
('orders.read', 'View orders', 'orders', 'read'),
('orders.update', 'Update orders', 'orders', 'update'),
('orders.delete', 'Delete orders', 'orders', 'delete'),
-- User permissions
('users.create', 'Create users', 'users', 'create'),
('users.read', 'View users', 'users', 'read'),
('users.update', 'Update users', 'users', 'update'),
('users.delete', 'Delete users', 'users', 'delete'),
-- Settings permissions
('settings.read', 'View settings', 'settings', 'read'),
('settings.update', 'Update settings', 'settings', 'update');

-- ============================================
-- SEED DEFAULT ROLES
-- ============================================

INSERT INTO public.roles (name, description, is_system) VALUES
('super_admin', 'Full access to everything', true),
('admin', 'Administrative access', true),
('manager', 'Manager access', true),
('editor', 'Content editor', true),
('viewer', 'Read-only access', true);

-- Assign permissions to roles
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM public.roles r, public.permissions p
WHERE r.name = 'super_admin';

INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM public.roles r, public.permissions p
WHERE r.name = 'admin' AND p.name NOT LIKE 'users.delete';

-- ============================================
-- HELPER FUNCTIONS
-- ============================================

-- Check if user has permission
CREATE OR REPLACE FUNCTION has_permission(
    p_user_id UUID,
    p_permission TEXT,
    p_organization_id UUID DEFAULT NULL
)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM public.user_roles ur
        JOIN public.role_permissions rp ON ur.role_id = rp.role_id
        JOIN public.permissions p ON rp.permission_id = p.id
        WHERE ur.user_id = p_user_id
        AND p.name = p_permission
        AND (p_organization_id IS NULL OR ur.organization_id = p_organization_id)
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Get user permissions
CREATE OR REPLACE FUNCTION get_user_permissions(
    p_user_id UUID,
    p_organization_id UUID DEFAULT NULL
)
RETURNS TABLE (permission_name TEXT, resource TEXT, action TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT DISTINCT p.name, p.resource, p.action
    FROM public.user_roles ur
    JOIN public.role_permissions rp ON ur.role_id = rp.role_id
    JOIN public.permissions p ON rp.permission_id = p.id
    WHERE ur.user_id = p_user_id
    AND (p_organization_id IS NULL OR ur.organization_id = p_organization_id);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Get user roles
CREATE OR REPLACE FUNCTION get_user_roles(p_user_id UUID)
RETURNS TABLE (role_name TEXT, organization_id UUID) AS $$
BEGIN
    RETURN QUERY
    SELECT r.name, ur.organization_id
    FROM public.user_roles ur
    JOIN public.roles r ON ur.role_id = r.id
    WHERE ur.user_id = p_user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================
-- RLS WITH DYNAMIC PERMISSIONS
-- ============================================

-- Products with dynamic permissions
CREATE POLICY "Dynamic products read"
ON public.products FOR SELECT
USING (
    is_active = true 
    OR has_permission(auth.uid(), 'products.read')
);

CREATE POLICY "Dynamic products insert"
ON public.products FOR INSERT
WITH CHECK (has_permission(auth.uid(), 'products.create'));

CREATE POLICY "Dynamic products update"
ON public.products FOR UPDATE
USING (has_permission(auth.uid(), 'products.update'));

CREATE POLICY "Dynamic products delete"
ON public.products FOR DELETE
USING (has_permission(auth.uid(), 'products.delete'));
```

### 6.4 Permission Checking in TypeScript

```typescript
// src/lib/permissions.ts
import { supabase } from './supabase'

export async function hasPermission(
    userId: string,
    permission: string,
    organizationId?: string
): Promise<boolean> {
    const { data, error } = await supabase.rpc('has_permission', {
        p_user_id: userId,
        p_permission: permission,
        p_organization_id: organizationId
    })
    
    if (error) {
        console.error('Permission check error:', error)
        return false
    }
    
    return data
}

export async function getUserPermissions(
    userId: string,
    organizationId?: string
): Promise<string[]> {
    const { data, error } = await supabase.rpc('get_user_permissions', {
        p_user_id: userId,
        p_organization_id: organizationId
    })
    
    if (error) throw error
    return data.map((p: any) => p.permission_name)
}

// React hook for permissions
export function usePermissions() {
    const { user } = useAuth()
    const [permissions, setPermissions] = useState<string[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        if (user) {
            getUserPermissions(user.id)
                .then(setPermissions)
                .finally(() => setLoading(false))
        }
    }, [user])

    const can = useCallback(
        (permission: string) => permissions.includes(permission),
        [permissions]
    )

    return { permissions, can, loading }
}

// Usage in components
function ProductsPage() {
    const { can } = usePermissions()

    return (
        <div>
            {can('products.create') && (
                <Button onClick={createProduct}>Add Product</Button>
            )}
            {/* ... */}
        </div>
    )
}
```

---

## 7. Edge Functions

### 7.1 Create Edge Function

```bash
# Create new function
supabase functions new send-email
```

### 7.2 Edge Function Examples

```typescript
// supabase/functions/send-email/index.ts
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

serve(async (req) => {
    // Handle CORS
    if (req.method === 'OPTIONS') {
        return new Response('ok', { headers: corsHeaders })
    }

    try {
        // Create Supabase client
        const supabaseClient = createClient(
            Deno.env.get('SUPABASE_URL') ?? '',
            Deno.env.get('SUPABASE_ANON_KEY') ?? '',
            {
                global: {
                    headers: { Authorization: req.headers.get('Authorization')! },
                },
            }
        )

        // Verify user
        const { data: { user }, error: userError } = await supabaseClient.auth.getUser()
        if (userError || !user) {
            throw new Error('Unauthorized')
        }

        const { to, subject, body } = await req.json()

        // Send email using Resend/SendGrid/etc
        const response = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${Deno.env.get('RESEND_API_KEY')}`
            },
            body: JSON.stringify({
                from: 'noreply@yourdomain.com',
                to,
                subject,
                html: body
            })
        })

        const result = await response.json()

        return new Response(
            JSON.stringify({ success: true, data: result }),
            { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        )

    } catch (error) {
        return new Response(
            JSON.stringify({ success: false, error: error.message }),
            { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        )
    }
})
```

```typescript
// supabase/functions/process-order/index.ts
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

serve(async (req) => {
    if (req.method === 'OPTIONS') {
        return new Response('ok', { headers: corsHeaders })
    }

    try {
        // Use service role for admin operations
        const supabaseAdmin = createClient(
            Deno.env.get('SUPABASE_URL') ?? '',
            Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
        )

        const { orderId } = await req.json()

        // Get order with items
        const { data: order, error: orderError } = await supabaseAdmin
            .from('orders')
            .select('*, order_items(*)')
            .eq('id', orderId)
            .single()

        if (orderError) throw orderError

        // Update inventory
        for (const item of order.order_items) {
            await supabaseAdmin
                .from('products')
                .update({ 
                    quantity: supabaseAdmin.rpc('decrement_quantity', {
                        product_id: item.product_id,
                        amount: item.quantity
                    })
                })
                .eq('id', item.product_id)
        }

        // Update order status
        await supabaseAdmin
            .from('orders')
            .update({ status: 'processing' })
            .eq('id', orderId)

        // Send confirmation email
        await fetch(`${Deno.env.get('SUPABASE_URL')}/functions/v1/send-email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')}`
            },
            body: JSON.stringify({
                to: order.user.email,
                subject: `Order ${order.order_number} Confirmed`,
                body: `<h1>Thank you for your order!</h1>`
            })
        })

        return new Response(
            JSON.stringify({ success: true, order }),
            { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        )

    } catch (error) {
        return new Response(
            JSON.stringify({ error: error.message }),
            { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        )
    }
})
```

### 7.3 Webhook Handler

```typescript
// supabase/functions/stripe-webhook/index.ts
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import Stripe from 'https://esm.sh/stripe@12.0.0'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const stripe = new Stripe(Deno.env.get('STRIPE_SECRET_KEY')!, {
    apiVersion: '2023-10-16',
})

const webhookSecret = Deno.env.get('STRIPE_WEBHOOK_SECRET')!

serve(async (req) => {
    const signature = req.headers.get('stripe-signature')!
    const body = await req.text()

    let event: Stripe.Event

    try {
        event = stripe.webhooks.constructEvent(body, signature, webhookSecret)
    } catch (err) {
        return new Response(`Webhook Error: ${err.message}`, { status: 400 })
    }

    const supabaseAdmin = createClient(
        Deno.env.get('SUPABASE_URL')!,
        Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    )

    switch (event.type) {
        case 'payment_intent.succeeded':
            const paymentIntent = event.data.object as Stripe.PaymentIntent
            
            await supabaseAdmin
                .from('orders')
                .update({ 
                    status: 'paid',
                    metadata: { payment_intent: paymentIntent.id }
                })
                .eq('metadata->>payment_intent_id', paymentIntent.id)
            break

        case 'customer.subscription.created':
        case 'customer.subscription.updated':
            const subscription = event.data.object as Stripe.Subscription
            
            await supabaseAdmin
                .from('subscriptions')
                .upsert({
                    stripe_subscription_id: subscription.id,
                    status: subscription.status,
                    price_id: subscription.items.data[0].price.id,
                    current_period_end: new Date(subscription.current_period_end * 1000)
                })
            break
    }

    return new Response(JSON.stringify({ received: true }), { status: 200 })
})
```

### 7.4 Deploy Edge Functions

```bash
# Deploy single function
supabase functions deploy send-email

# Deploy all functions
supabase functions deploy

# Set secrets
supabase secrets set RESEND_API_KEY=your-key
supabase secrets set STRIPE_SECRET_KEY=your-key
```

### 7.5 Invoke Edge Functions

```typescript
// Client-side
const { data, error } = await supabase.functions.invoke('send-email', {
    body: { to: 'user@example.com', subject: 'Hello', body: '<p>Hi</p>' }
})

// With custom headers
const { data, error } = await supabase.functions.invoke('process-order', {
    body: { orderId: '123' },
    headers: { 'x-custom-header': 'value' }
})
```

---

## 8. Security Layers

### 8.1 API Security

```sql
-- Rate limiting table
CREATE TABLE public.rate_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address INET NOT NULL,
    endpoint TEXT NOT NULL,
    request_count INTEGER DEFAULT 1,
    window_start TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(ip_address, endpoint)
);

-- Rate limiting function
CREATE OR REPLACE FUNCTION check_rate_limit(
    p_ip INET,
    p_endpoint TEXT,
    p_max_requests INTEGER DEFAULT 100,
    p_window_minutes INTEGER DEFAULT 15
)
RETURNS BOOLEAN AS $$
DECLARE
    v_request_count INTEGER;
BEGIN
    -- Clean old entries
    DELETE FROM public.rate_limits 
    WHERE window_start < NOW() - INTERVAL '1 hour';

    -- Get or create rate limit entry
    INSERT INTO public.rate_limits (ip_address, endpoint, request_count, window_start)
    VALUES (p_ip, p_endpoint, 1, NOW())
    ON CONFLICT (ip_address, endpoint) DO UPDATE SET
        request_count = CASE
            WHEN rate_limits.window_start < NOW() - (p_window_minutes || ' minutes')::INTERVAL
            THEN 1
            ELSE rate_limits.request_count + 1
        END,
        window_start = CASE
            WHEN rate_limits.window_start < NOW() - (p_window_minutes || ' minutes')::INTERVAL
            THEN NOW()
            ELSE rate_limits.window_start
        END
    RETURNING request_count INTO v_request_count;

    RETURN v_request_count <= p_max_requests;
END;
$$ LANGUAGE plpgsql;
```

### 8.2 Input Validation

```typescript
// src/lib/validation.ts
import { z } from 'zod'

export const productSchema = z.object({
    name: z.string().min(2).max(200),
    slug: z.string().regex(/^[a-z0-9-]+$/).optional(),
    description: z.string().max(5000).optional(),
    price: z.number().positive().max(999999.99),
    quantity: z.number().int().min(0).default(0),
    category_id: z.string().uuid().optional(),
    is_active: z.boolean().default(true),
    images: z.array(z.string().url()).max(10).optional()
})

export const orderSchema = z.object({
    items: z.array(z.object({
        product_id: z.string().uuid(),
        quantity: z.number().int().positive().max(100)
    })).min(1),
    shipping_address: z.object({
        street: z.string().min(5),
        city: z.string().min(2),
        state: z.string().min(2),
        postal_code: z.string().min(3),
        country: z.string().length(2)
    }),
    notes: z.string().max(1000).optional()
})

// Usage
export function validateProduct(data: unknown) {
    return productSchema.parse(data)
}
```

### 8.3 SQL Injection Prevention

```typescript
// NEVER do this - SQL injection vulnerable
const { data } = await supabase
    .from('products')
    .select()
    .filter('name', 'eq', userInput) // Safe - parameterized

// For raw SQL, use parameterized queries
const { data } = await supabase.rpc('search_products', {
    search_term: userInput // Parameter passed safely
})
```

### 8.4 Security Headers in Edge Functions

```typescript
const securityHeaders = {
    'Content-Security-Policy': "default-src 'self'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
}
```

### 8.5 Audit Logging

```sql
-- Audit log table
CREATE TABLE public.audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    table_name TEXT NOT NULL,
    record_id UUID NOT NULL,
    action TEXT NOT NULL, -- INSERT, UPDATE, DELETE
    old_data JSONB,
    new_data JSONB,
    user_id UUID REFERENCES auth.users(id),
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Generic audit trigger function
CREATE OR REPLACE FUNCTION audit_trigger()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        INSERT INTO public.audit_logs (table_name, record_id, action, old_data, user_id)
        VALUES (TG_TABLE_NAME, OLD.id, 'DELETE', to_jsonb(OLD), auth.uid());
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO public.audit_logs (table_name, record_id, action, old_data, new_data, user_id)
        VALUES (TG_TABLE_NAME, NEW.id, 'UPDATE', to_jsonb(OLD), to_jsonb(NEW), auth.uid());
        RETURN NEW;
    ELSIF TG_OP = 'INSERT' THEN
        INSERT INTO public.audit_logs (table_name, record_id, action, new_data, user_id)
        VALUES (TG_TABLE_NAME, NEW.id, 'INSERT', to_jsonb(NEW), auth.uid());
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Apply to tables
CREATE TRIGGER audit_products
    AFTER INSERT OR UPDATE OR DELETE ON public.products
    FOR EACH ROW EXECUTE FUNCTION audit_trigger();

CREATE TRIGGER audit_orders
    AFTER INSERT OR UPDATE OR DELETE ON public.orders
    FOR EACH ROW EXECUTE FUNCTION audit_trigger();
```

---

## 9. Migrations & Seeders

### 9.1 Create Migration

```bash
# Create new migration
supabase migration new create_products_table
```

### 9.2 Migration File Structure

```sql
-- supabase/migrations/20240101000000_create_products_table.sql

-- Up Migration
CREATE TABLE IF NOT EXISTS public.products (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    quantity INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_products_slug ON public.products(slug);
CREATE INDEX IF NOT EXISTS idx_products_active ON public.products(is_active);

-- Enable RLS
ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;

-- Create policies
CREATE POLICY "Products are viewable by everyone"
ON public.products FOR SELECT
USING (is_active = true);
```

### 9.3 Rollback Migration

```sql
-- supabase/migrations/20240101000000_create_products_table.sql

-- Add rollback at the bottom (commented)
-- ROLLBACK:
-- DROP POLICY IF EXISTS "Products are viewable by everyone" ON public.products;
-- DROP TABLE IF EXISTS public.products;
```

### 9.4 Run Migrations

```bash
# Apply migrations locally
supabase db reset  # Reset and apply all migrations

# Apply migrations to remote
supabase db push

# Check migration status
supabase migration list

# Create migration from remote changes
supabase db diff -f migration_name
```

### 9.5 Seed Data

```sql
-- supabase/seed.sql

-- Clear existing data (optional)
TRUNCATE public.products CASCADE;
TRUNCATE public.categories CASCADE;

-- Seed categories
INSERT INTO public.categories (id, name, slug, description) VALUES
('cat-1', 'Electronics', 'electronics', 'Electronic devices'),
('cat-2', 'Clothing', 'clothing', 'Fashion items'),
('cat-3', 'Books', 'books', 'Books and publications');

-- Seed products
INSERT INTO public.products (name, slug, description, price, quantity, category_id, is_active) VALUES
('iPhone 15', 'iphone-15', 'Latest Apple smartphone', 999.00, 100, 'cat-1', true),
('MacBook Pro', 'macbook-pro', '14-inch laptop', 1999.00, 50, 'cat-1', true),
('T-Shirt', 't-shirt', 'Cotton t-shirt', 29.99, 200, 'cat-2', true),
('Clean Code', 'clean-code', 'Robert C. Martin', 45.00, 75, 'cat-3', true);

-- Seed test users (for development only)
INSERT INTO auth.users (id, email, encrypted_password, email_confirmed_at, role)
VALUES 
('user-1', 'admin@test.com', crypt('password123', gen_salt('bf')), NOW(), 'authenticated'),
('user-2', 'user@test.com', crypt('password123', gen_salt('bf')), NOW(), 'authenticated');

-- Seed profiles
INSERT INTO public.profiles (id, email, full_name, role) VALUES
('user-1', 'admin@test.com', 'Admin User', 'admin'),
('user-2', 'user@test.com', 'Regular User', 'user');
```

### 9.6 Run Seeders

```bash
# Run seed file (during db reset)
supabase db reset  # Automatically runs seed.sql

# Run seed manually
psql -h localhost -p 54322 -U postgres -d postgres -f supabase/seed.sql
```

### 9.7 Environment-Specific Seeds

```typescript
// scripts/seed.ts
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
    process.env.SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!
)

async function seed() {
    console.log('Seeding database...')

    // Seed categories
    const { error: catError } = await supabase.from('categories').upsert([
        { name: 'Electronics', slug: 'electronics' },
        { name: 'Clothing', slug: 'clothing' }
    ])
    if (catError) throw catError

    // Seed products
    const { error: prodError } = await supabase.from('products').upsert([
        { name: 'Test Product', slug: 'test-product', price: 99.99 }
    ])
    if (prodError) throw prodError

    console.log('Seeding complete!')
}

seed().catch(console.error)
```

```bash
# Run TypeScript seeder
npx ts-node scripts/seed.ts
```

---

## 10. Prisma ORM Integration

### 10.1 Setup Prisma with Supabase

```bash
# Install Prisma
npm install prisma @prisma/client
npm install -D prisma

# Initialize Prisma
npx prisma init
```

### 10.2 Prisma Configuration

```prisma
// prisma/schema.prisma

generator client {
  provider        = "prisma-client-js"
  previewFeatures = ["multiSchema"]
}

datasource db {
  provider  = "postgresql"
  url       = env("DATABASE_URL")
  directUrl = env("DIRECT_URL")
  schemas   = ["public", "auth"]
}

// ============================================
// MODELS
// ============================================

model Profile {
  id        String   @id @db.Uuid
  email     String   @unique
  fullName  String?  @map("full_name")
  avatarUrl String?  @map("avatar_url")
  role      Role     @default(user)
  phone     String?
  metadata  Json     @default("{}")
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @updatedAt @map("updated_at")

  // Relations
  products         Product[]
  orders           Order[]
  organizations    OrganizationMember[]
  createdOrganizations Organization[] @relation("CreatedBy")

  @@map("profiles")
  @@schema("public")
}

enum Role {
  admin
  manager
  user
  guest

  @@schema("public")
}

model Organization {
  id        String   @id @default(uuid()) @db.Uuid
  name      String
  slug      String   @unique
  logoUrl   String?  @map("logo_url")
  settings  Json     @default("{}")
  createdBy String?  @map("created_by") @db.Uuid
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @updatedAt @map("updated_at")

  // Relations
  creator Profile?             @relation("CreatedBy", fields: [createdBy], references: [id])
  members OrganizationMember[]

  @@map("organizations")
  @@schema("public")
}

model OrganizationMember {
  id             String   @id @default(uuid()) @db.Uuid
  organizationId String   @map("organization_id") @db.Uuid
  userId         String   @map("user_id") @db.Uuid
  role           String   @default("member")
  permissions    Json     @default("[]")
  joinedAt       DateTime @default(now()) @map("joined_at")

  organization Organization @relation(fields: [organizationId], references: [id], onDelete: Cascade)
  user         Profile      @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@unique([organizationId, userId])
  @@map("organization_members")
  @@schema("public")
}

model Category {
  id          String   @id @default(uuid()) @db.Uuid
  name        String
  slug        String   @unique
  description String?
  parentId    String?  @map("parent_id") @db.Uuid
  imageUrl    String?  @map("image_url")
  sortOrder   Int      @default(0) @map("sort_order")
  isActive    Boolean  @default(true) @map("is_active")
  createdAt   DateTime @default(now()) @map("created_at")
  updatedAt   DateTime @updatedAt @map("updated_at")

  // Self-relation for nested categories
  parent   Category?  @relation("CategoryHierarchy", fields: [parentId], references: [id])
  children Category[] @relation("CategoryHierarchy")
  products Product[]

  @@map("categories")
  @@schema("public")
}

model Product {
  id           String   @id @default(uuid()) @db.Uuid
  name         String
  slug         String   @unique
  description  String?
  price        Decimal  @db.Decimal(10, 2)
  comparePrice Decimal? @map("compare_price") @db.Decimal(10, 2)
  costPrice    Decimal? @map("cost_price") @db.Decimal(10, 2)
  sku          String?  @unique
  barcode      String?
  quantity     Int      @default(0)
  categoryId   String?  @map("category_id") @db.Uuid
  images       Json     @default("[]")
  attributes   Json     @default("{}")
  isActive     Boolean  @default(true) @map("is_active")
  isFeatured   Boolean  @default(false) @map("is_featured")
  createdBy    String?  @map("created_by") @db.Uuid
  createdAt    DateTime @default(now()) @map("created_at")
  updatedAt    DateTime @updatedAt @map("updated_at")

  // Relations
  category   Category?   @relation(fields: [categoryId], references: [id])
  creator    Profile?    @relation(fields: [createdBy], references: [id])
  orderItems OrderItem[]

  @@index([categoryId])
  @@index([isActive])
  @@map("products")
  @@schema("public")
}

model Order {
  id              String      @id @default(uuid()) @db.Uuid
  orderNumber     String      @unique @map("order_number")
  userId          String?     @map("user_id") @db.Uuid
  status          OrderStatus @default(pending)
  subtotal        Decimal     @db.Decimal(10, 2)
  tax             Decimal     @default(0) @db.Decimal(10, 2)
  shipping        Decimal     @default(0) @db.Decimal(10, 2)
  discount        Decimal     @default(0) @db.Decimal(10, 2)
  total           Decimal     @db.Decimal(10, 2)
  shippingAddress Json?       @map("shipping_address")
  billingAddress  Json?       @map("billing_address")
  notes           String?
  metadata        Json        @default("{}")
  createdAt       DateTime    @default(now()) @map("created_at")
  updatedAt       DateTime    @updatedAt @map("updated_at")

  // Relations
  user  Profile?    @relation(fields: [userId], references: [id])
  items OrderItem[]

  @@index([userId])
  @@index([status])
  @@map("orders")
  @@schema("public")
}

enum OrderStatus {
  pending
  processing
  shipped
  delivered
  cancelled

  @@schema("public")
}

model OrderItem {
  id        String  @id @default(uuid()) @db.Uuid
  orderId   String  @map("order_id") @db.Uuid
  productId String? @map("product_id") @db.Uuid
  quantity  Int
  price     Decimal @db.Decimal(10, 2)
  total     Decimal @db.Decimal(10, 2)
  metadata  Json    @default("{}")

  order   Order    @relation(fields: [orderId], references: [id], onDelete: Cascade)
  product Product? @relation(fields: [productId], references: [id])

  @@map("order_items")
  @@schema("public")
}
```

### 10.3 Environment Variables

```env
# .env
DATABASE_URL="postgresql://postgres.[project-ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres?pgbouncer=true"
DIRECT_URL="postgresql://postgres.[project-ref]:[password]@aws-0-[region].pooler.supabase.com:5432/postgres"
```

### 10.4 Prisma Client

```typescript
// src/lib/prisma.ts
import { PrismaClient } from '@prisma/client'

const globalForPrisma = globalThis as unknown as {
    prisma: PrismaClient | undefined
}

export const prisma = globalForPrisma.prisma ?? new PrismaClient({
    log: process.env.NODE_ENV === 'development' 
        ? ['query', 'error', 'warn'] 
        : ['error']
})

if (process.env.NODE_ENV !== 'production') {
    globalForPrisma.prisma = prisma
}
```

### 10.5 Prisma CRUD Operations

```typescript
// src/services/prisma-products.ts
import { prisma } from '@/lib/prisma'
import { Prisma } from '@prisma/client'

// ============================================
// CREATE
// ============================================

export async function createProduct(data: Prisma.ProductCreateInput) {
    return prisma.product.create({
        data,
        include: { category: true }
    })
}

// ============================================
// READ
// ============================================

export async function getProducts({
    page = 1,
    limit = 10,
    categoryId,
    search,
    orderBy = 'createdAt',
    order = 'desc'
}: {
    page?: number
    limit?: number
    categoryId?: string
    search?: string
    orderBy?: string
    order?: 'asc' | 'desc'
}) {
    const where: Prisma.ProductWhereInput = {
        isActive: true,
        ...(categoryId && { categoryId }),
        ...(search && {
            OR: [
                { name: { contains: search, mode: 'insensitive' } },
                { description: { contains: search, mode: 'insensitive' } }
            ]
        })
    }

    const [products, total] = await prisma.$transaction([
        prisma.product.findMany({
            where,
            include: { category: true },
            orderBy: { [orderBy]: order },
            skip: (page - 1) * limit,
            take: limit
        }),
        prisma.product.count({ where })
    ])

    return {
        data: products,
        pagination: {
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit)
        }
    }
}

export async function getProductById(id: string) {
    return prisma.product.findUnique({
        where: { id },
        include: {
            category: true,
            creator: {
                select: { id: true, fullName: true, avatarUrl: true }
            }
        }
    })
}

// ============================================
// UPDATE
// ============================================

export async function updateProduct(id: string, data: Prisma.ProductUpdateInput) {
    return prisma.product.update({
        where: { id },
        data,
        include: { category: true }
    })
}

// ============================================
// DELETE
// ============================================

export async function deleteProduct(id: string) {
    return prisma.product.delete({
        where: { id }
    })
}

// ============================================
// TRANSACTIONS
// ============================================

export async function createOrderWithItems(
    orderData: Prisma.OrderCreateInput,
    items: { productId: string; quantity: number }[]
) {
    return prisma.$transaction(async (tx) => {
        // Get products and calculate totals
        const products = await tx.product.findMany({
            where: { id: { in: items.map(i => i.productId) } }
        })

        let subtotal = 0
        const orderItems = items.map(item => {
            const product = products.find(p => p.id === item.productId)!
            const itemTotal = Number(product.price) * item.quantity
            subtotal += itemTotal

            return {
                productId: item.productId,
                quantity: item.quantity,
                price: product.price,
                total: itemTotal
            }
        })

        // Create order
        const order = await tx.order.create({
            data: {
                ...orderData,
                subtotal,
                total: subtotal + Number(orderData.tax || 0) + Number(orderData.shipping || 0),
                items: { create: orderItems }
            },
            include: { items: true }
        })

        // Update inventory
        for (const item of items) {
            await tx.product.update({
                where: { id: item.productId },
                data: { quantity: { decrement: item.quantity } }
            })
        }

        return order
    })
}
```

### 10.6 Prisma Migrations

```bash
# Pull existing database schema
npx prisma db pull

# Generate Prisma Client
npx prisma generate

# Create migration from schema changes
npx prisma migrate dev --name add_products_table

# Apply migrations to production
npx prisma migrate deploy

# Reset database
npx prisma migrate reset
```

---

## 11. React.js Integration

### 11.1 Setup React App

```bash
# Using Vite
npm create vite@latest my-app -- --template react-ts
cd my-app
npm install @supabase/supabase-js @tanstack/react-query zustand
```

### 11.2 Supabase Provider

```typescript
// src/providers/SupabaseProvider.tsx
import { createContext, useContext, useEffect, useState } from 'react'
import { Session, User } from '@supabase/supabase-js'
import { supabase } from '@/lib/supabase'

interface SupabaseContextType {
    supabase: typeof supabase
    session: Session | null
    user: User | null
    loading: boolean
}

const SupabaseContext = createContext<SupabaseContextType | undefined>(undefined)

export function SupabaseProvider({ children }: { children: React.ReactNode }) {
    const [session, setSession] = useState<Session | null>(null)
    const [user, setUser] = useState<User | null>(null)
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        supabase.auth.getSession().then(({ data: { session } }) => {
            setSession(session)
            setUser(session?.user ?? null)
            setLoading(false)
        })

        const { data: { subscription } } = supabase.auth.onAuthStateChange(
            (_event, session) => {
                setSession(session)
                setUser(session?.user ?? null)
            }
        )

        return () => subscription.unsubscribe()
    }, [])

    return (
        <SupabaseContext.Provider value={{ supabase, session, user, loading }}>
            {children}
        </SupabaseContext.Provider>
    )
}

export const useSupabase = () => {
    const context = useContext(SupabaseContext)
    if (!context) throw new Error('useSupabase must be used within SupabaseProvider')
    return context
}
```

### 11.3 React Query Setup

```typescript
// src/providers/QueryProvider.tsx
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'

const queryClient = new QueryClient({
    defaultOptions: {
        queries: {
            staleTime: 1000 * 60 * 5, // 5 minutes
            gcTime: 1000 * 60 * 30, // 30 minutes (previously cacheTime)
            retry: 1,
            refetchOnWindowFocus: false
        }
    }
})

export function QueryProvider({ children }: { children: React.ReactNode }) {
    return (
        <QueryClientProvider client={queryClient}>
            {children}
            <ReactQueryDevtools />
        </QueryClientProvider>
    )
}
```

### 11.4 Custom Hooks for Data Fetching

```typescript
// src/hooks/useProducts.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { supabase } from '@/lib/supabase'

interface ProductFilters {
    page?: number
    limit?: number
    category?: string
    search?: string
}

// Fetch products
export function useProducts(filters: ProductFilters = {}) {
    const { page = 1, limit = 10, category, search } = filters

    return useQuery({
        queryKey: ['products', filters],
        queryFn: async () => {
            let query = supabase
                .from('products')
                .select('*, category:categories(*)', { count: 'exact' })
                .eq('is_active', true)
                .order('created_at', { ascending: false })
                .range((page - 1) * limit, page * limit - 1)

            if (category) query = query.eq('category_id', category)
            if (search) query = query.ilike('name', `%${search}%`)

            const { data, error, count } = await query
            if (error) throw error

            return {
                data,
                pagination: {
                    page,
                    limit,
                    total: count || 0,
                    totalPages: Math.ceil((count || 0) / limit)
                }
            }
        }
    })
}

// Fetch single product
export function useProduct(id: string) {
    return useQuery({
        queryKey: ['products', id],
        queryFn: async () => {
            const { data, error } = await supabase
                .from('products')
                .select('*, category:categories(*)')
                .eq('id', id)
                .single()

            if (error) throw error
            return data
        },
        enabled: !!id
    })
}

// Create product
export function useCreateProduct() {
    const queryClient = useQueryClient()

    return useMutation({
        mutationFn: async (product: any) => {
            const { data, error } = await supabase
                .from('products')
                .insert(product)
                .select()
                .single()

            if (error) throw error
            return data
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['products'] })
        }
    })
}

// Update product
export function useUpdateProduct() {
    const queryClient = useQueryClient()

    return useMutation({
        mutationFn: async ({ id, ...updates }: any) => {
            const { data, error } = await supabase
                .from('products')
                .update(updates)
                .eq('id', id)
                .select()
                .single()

            if (error) throw error
            return data
        },
        onSuccess: (data) => {
            queryClient.invalidateQueries({ queryKey: ['products'] })
            queryClient.setQueryData(['products', data.id], data)
        }
    })
}

// Delete product
export function useDeleteProduct() {
    const queryClient = useQueryClient()

    return useMutation({
        mutationFn: async (id: string) => {
            const { error } = await supabase
                .from('products')
                .delete()
                .eq('id', id)

            if (error) throw error
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['products'] })
        }
    })
}
```

### 11.5 Real-time Subscriptions

```typescript
// src/hooks/useRealtimeProducts.ts
import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { supabase } from '@/lib/supabase'

export function useRealtimeProducts() {
    const queryClient = useQueryClient()

    useEffect(() => {
        const channel = supabase
            .channel('products-changes')
            .on(
                'postgres_changes',
                { event: '*', schema: 'public', table: 'products' },
                (payload) => {
                    console.log('Change received:', payload)
                    
                    switch (payload.eventType) {
                        case 'INSERT':
                            queryClient.invalidateQueries({ queryKey: ['products'] })
                            break
                        case 'UPDATE':
                            queryClient.setQueryData(
                                ['products', payload.new.id],
                                payload.new
                            )
                            queryClient.invalidateQueries({ queryKey: ['products'] })
                            break
                        case 'DELETE':
                            queryClient.invalidateQueries({ queryKey: ['products'] })
                            break
                    }
                }
            )
            .subscribe()

        return () => {
            supabase.removeChannel(channel)
        }
    }, [queryClient])
}
```

### 11.6 Component Examples

```typescript
// src/components/ProductList.tsx
import { useState } from 'react'
import { useProducts, useDeleteProduct } from '@/hooks/useProducts'
import { useRealtimeProducts } from '@/hooks/useRealtimeProducts'

export function ProductList() {
    const [page, setPage] = useState(1)
    const [search, setSearch] = useState('')
    
    const { data, isLoading, error } = useProducts({ page, search, limit: 10 })
    const deleteProduct = useDeleteProduct()
    
    // Enable real-time updates
    useRealtimeProducts()

    if (isLoading) return <div>Loading...</div>
    if (error) return <div>Error: {error.message}</div>

    return (
        <div>
            <input
                type="search"
                placeholder="Search products..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
            />

            <div className="grid grid-cols-3 gap-4">
                {data?.data.map((product) => (
                    <div key={product.id} className="border p-4 rounded">
                        <h3>{product.name}</h3>
                        <p>${product.price}</p>
                        <p>{product.category?.name}</p>
                        <button
                            onClick={() => deleteProduct.mutate(product.id)}
                            disabled={deleteProduct.isPending}
                        >
                            Delete
                        </button>
                    </div>
                ))}
            </div>

            {/* Pagination */}
            <div className="flex gap-2 mt-4">
                <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                >
                    Previous
                </button>
                <span>Page {page} of {data?.pagination.totalPages}</span>
                <button
                    onClick={() => setPage(p => p + 1)}
                    disabled={page >= (data?.pagination.totalPages || 1)}
                >
                    Next
                </button>
            </div>
        </div>
    )
}
```

```typescript
// src/components/ProductForm.tsx
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useCreateProduct, useUpdateProduct } from '@/hooks/useProducts'

const productSchema = z.object({
    name: z.string().min(2, 'Name must be at least 2 characters'),
    slug: z.string().regex(/^[a-z0-9-]+$/, 'Invalid slug format'),
    description: z.string().optional(),
    price: z.number().positive('Price must be positive'),
    quantity: z.number().int().min(0),
    category_id: z.string().uuid().optional(),
    is_active: z.boolean().default(true)
})

type ProductFormData = z.infer<typeof productSchema>

interface ProductFormProps {
    product?: ProductFormData & { id: string }
    onSuccess?: () => void
}

export function ProductForm({ product, onSuccess }: ProductFormProps) {
    const createProduct = useCreateProduct()
    const updateProduct = useUpdateProduct()

    const {
        register,
        handleSubmit,
        formState: { errors, isSubmitting }
    } = useForm<ProductFormData>({
        resolver: zodResolver(productSchema),
        defaultValues: product || {
            is_active: true,
            quantity: 0
        }
    })

    const onSubmit = async (data: ProductFormData) => {
        try {
            if (product?.id) {
                await updateProduct.mutateAsync({ id: product.id, ...data })
            } else {
                await createProduct.mutateAsync(data)
            }
            onSuccess?.()
        } catch (error) {
            console.error('Failed to save product:', error)
        }
    }

    return (
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div>
                <label>Name</label>
                <input {...register('name')} />
                {errors.name && <span>{errors.name.message}</span>}
            </div>

            <div>
                <label>Slug</label>
                <input {...register('slug')} />
                {errors.slug && <span>{errors.slug.message}</span>}
            </div>

            <div>
                <label>Description</label>
                <textarea {...register('description')} />
            </div>

            <div>
                <label>Price</label>
                <input
                    type="number"
                    step="0.01"
                    {...register('price', { valueAsNumber: true })}
                />
                {errors.price && <span>{errors.price.message}</span>}
            </div>

            <div>
                <label>Quantity</label>
                <input
                    type="number"
                    {...register('quantity', { valueAsNumber: true })}
                />
            </div>

            <div>
                <label>
                    <input type="checkbox" {...register('is_active')} />
                    Active
                </label>
            </div>

            <button type="submit" disabled={isSubmitting}>
                {isSubmitting ? 'Saving...' : product ? 'Update' : 'Create'}
            </button>
        </form>
    )
}
```

### 11.7 Protected Routes

```typescript
// src/components/ProtectedRoute.tsx
import { Navigate, useLocation } from 'react-router-dom'
import { useSupabase } from '@/providers/SupabaseProvider'

interface ProtectedRouteProps {
    children: React.ReactNode
    requiredRole?: string
}

export function ProtectedRoute({ children, requiredRole }: ProtectedRouteProps) {
    const { user, loading } = useSupabase()
    const location = useLocation()

    if (loading) {
        return <div>Loading...</div>
    }

    if (!user) {
        return <Navigate to="/login" state={{ from: location }} replace />
    }

    // Check role if required
    if (requiredRole) {
        const userRole = user.user_metadata?.role
        if (userRole !== requiredRole && userRole !== 'admin') {
            return <Navigate to="/unauthorized" replace />
        }
    }

    return <>{children}</>
}

// Usage in routes
function App() {
    return (
        <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route
                path="/dashboard"
                element={
                    <ProtectedRoute>
                        <DashboardPage />
                    </ProtectedRoute>
                }
            />
            <Route
                path="/admin"
                element={
                    <ProtectedRoute requiredRole="admin">
                        <AdminPage />
                    </ProtectedRoute>
                }
            />
        </Routes>
    )
}
```

---

## 12. Caching & Optimization

### 12.1 Database Optimization

```sql
-- ============================================
-- MATERIALIZED VIEWS
-- ============================================

-- Product summary view
CREATE MATERIALIZED VIEW product_summary AS
SELECT 
    p.id,
    p.name,
    p.slug,
    p.price,
    p.quantity,
    c.name as category_name,
    c.slug as category_slug,
    COUNT(oi.id) as total_orders,
    COALESCE(SUM(oi.quantity), 0) as total_sold
FROM products p
LEFT JOIN categories c ON p.category_id = c.id
LEFT JOIN order_items oi ON p.id = oi.product_id
WHERE p.is_active = true
GROUP BY p.id, c.id;

-- Create index on materialized view
CREATE UNIQUE INDEX idx_product_summary_id ON product_summary(id);
CREATE INDEX idx_product_summary_category ON product_summary(category_slug);

-- Refresh view (call periodically or on changes)
REFRESH MATERIALIZED VIEW CONCURRENTLY product_summary;

-- ============================================
-- INDEXES FOR COMMON QUERIES
-- ============================================

-- Composite indexes
CREATE INDEX idx_products_category_active 
ON products(category_id, is_active) 
WHERE is_active = true;

CREATE INDEX idx_orders_user_status 
ON orders(user_id, status, created_at DESC);

-- Partial indexes
CREATE INDEX idx_products_featured 
ON products(id) 
WHERE is_featured = true AND is_active = true;

CREATE INDEX idx_orders_pending 
ON orders(id, created_at) 
WHERE status = 'pending';

-- ============================================
-- QUERY OPTIMIZATION
-- ============================================

-- Analyze tables for query planning
ANALYZE products;
ANALYZE orders;
ANALYZE order_items;

-- Check query plan
EXPLAIN ANALYZE
SELECT * FROM products 
WHERE category_id = 'some-uuid' AND is_active = true;
```

### 12.2 Application-Level Caching

```typescript
// src/lib/cache.ts
import { LRUCache } from 'lru-cache'

// In-memory cache
const cache = new LRUCache<string, any>({
    max: 500,
    ttl: 1000 * 60 * 5, // 5 minutes
})

export const cacheService = {
    get<T>(key: string): T | undefined {
        return cache.get(key)
    },

    set<T>(key: string, value: T, ttl?: number): void {
        cache.set(key, value, { ttl })
    },

    delete(key: string): void {
        cache.delete(key)
    },

    clear(): void {
        cache.clear()
    },

    // Pattern-based invalidation
    invalidatePattern(pattern: RegExp): void {
        for (const key of cache.keys()) {
            if (pattern.test(key)) {
                cache.delete(key)
            }
        }
    }
}

// Cached data fetcher
export async function cachedFetch<T>(
    key: string,
    fetcher: () => Promise<T>,
    ttl?: number
): Promise<T> {
    const cached = cacheService.get<T>(key)
    if (cached !== undefined) {
        return cached
    }

    const data = await fetcher()
    cacheService.set(key, data, ttl)
    return data
}
```

### 12.3 React Query Caching

```typescript
// src/hooks/useOptimizedProducts.ts
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { supabase } from '@/lib/supabase'

export function useOptimizedProducts(categorySlug?: string) {
    return useQuery({
        queryKey: ['products', 'list', categorySlug],
        queryFn: async () => {
            // Use materialized view for better performance
            const { data, error } = await supabase
                .from('product_summary')
                .select('*')
                .eq(categorySlug ? 'category_slug' : 'id', categorySlug || undefined)
                .order('total_sold', { ascending: false })

            if (error) throw error
            return data
        },
        staleTime: 1000 * 60 * 5, // Consider fresh for 5 minutes
        gcTime: 1000 * 60 * 30,   // Keep in cache for 30 minutes
        placeholderData: (previousData) => previousData, // Show old data while fetching
    })
}

// Prefetch for route transitions
export function usePrefetchProducts() {
    const queryClient = useQueryClient()

    return (categorySlug: string) => {
        queryClient.prefetchQuery({
            queryKey: ['products', 'list', categorySlug],
            queryFn: async () => {
                const { data } = await supabase
                    .from('product_summary')
                    .select('*')
                    .eq('category_slug', categorySlug)

                return data
            },
            staleTime: 1000 * 60 * 5
        })
    }
}
```

### 12.4 Edge Caching with Supabase

```typescript
// Edge function with caching headers
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'

serve(async (req) => {
    const url = new URL(req.url)
    const cacheKey = url.pathname + url.search

    // Check cache
    const cache = caches.default
    let response = await cache.match(req)

    if (response) {
        return response
    }

    // Fetch fresh data
    const data = await fetchData()

    response = new Response(JSON.stringify(data), {
        headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'public, max-age=300, s-maxage=600',
            'CDN-Cache-Control': 'max-age=600',
            'Vercel-CDN-Cache-Control': 'max-age=3600'
        }
    })

    // Store in cache
    await cache.put(req, response.clone())

    return response
})
```

### 12.5 Connection Pooling

```typescript
// For Prisma with Supabase
// Use connection pooling URL for queries
DATABASE_URL="postgresql://postgres.[ref]:[pass]@aws-0-[region].pooler.supabase.com:6543/postgres?pgbouncer=true"

// Use direct connection for migrations
DIRECT_URL="postgresql://postgres.[ref]:[pass]@aws-0-[region].pooler.supabase.com:5432/postgres"
```

### 12.6 Query Optimization Tips

```typescript
// ❌ Bad: Multiple queries
const products = await supabase.from('products').select('*')
const categories = await supabase.from('categories').select('*')

// ✅ Good: Single query with joins
const { data } = await supabase
    .from('products')
    .select('*, category:categories(*)')

// ❌ Bad: Select all columns
const { data } = await supabase.from('products').select('*')

// ✅ Good: Select only needed columns
const { data } = await supabase
    .from('products')
    .select('id, name, price, slug')

// ❌ Bad: No pagination
const { data } = await supabase.from('products').select('*')

// ✅ Good: Always paginate
const { data } = await supabase
    .from('products')
    .select('*', { count: 'exact' })
    .range(0, 9) // First 10 items

// ✅ Good: Use database functions for complex operations
const { data } = await supabase.rpc('get_dashboard_stats')
```

---

## 13. VS Code Setup

### 13.1 Required Extensions

```json
// .vscode/extensions.json
{
    "recommendations": [
        "supabase.vscode-supabase",
        "prisma.prisma",
        "dbaeumer.vscode-eslint",
        "esbenp.prettier-vscode",
        "bradlc.vscode-tailwindcss",
        "mikestead.dotenv",
        "GraphQL.vscode-graphql",
        "mtxr.sqltools",
        "ckolkman.vscode-postgres"
    ]
}
```

### 13.2 VS Code Settings

```json
// .vscode/settings.json
{
    "editor.formatOnSave": true,
    "editor.defaultFormatter": "esbenp.prettier-vscode",
    "editor.codeActionsOnSave": {
        "source.fixAll.eslint": true,
        "source.organizeImports": true
    },
    "[sql]": {
        "editor.defaultFormatter": "mtxr.sqltools"
    },
    "[prisma]": {
        "editor.defaultFormatter": "Prisma.prisma"
    },
    "typescript.preferences.importModuleSpecifier": "non-relative",
    "typescript.suggest.autoImports": true,
    "files.associations": {
        "*.sql": "sql"
    },
    "sqltools.connections": [
        {
            "name": "Supabase Local",
            "driver": "PostgreSQL",
            "server": "localhost",
            "port": 54322,
            "database": "postgres",
            "username": "postgres",
            "password": "postgres"
        }
    ]
}
```

### 13.3 Debug Configuration

```json
// .vscode/launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Next.js: debug server-side",
            "type": "node-terminal",
            "request": "launch",
            "command": "npm run dev"
        },
        {
            "name": "Debug Edge Function",
            "type": "node",
            "request": "launch",
            "program": "${workspaceFolder}/supabase/functions/${input:functionName}/index.ts",
            "runtimeExecutable": "deno",
            "runtimeArgs": [
                "run",
                "--inspect-brk",
                "--allow-all"
            ],
            "attachSimplePort": 9229
        }
    ],
    "inputs": [
        {
            "id": "functionName",
            "type": "promptString",
            "description": "Edge function name"
        }
    ]
}
```

### 13.4 Tasks

```json
// .vscode/tasks.json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Supabase: Start",
            "type": "shell",
            "command": "supabase start",
            "problemMatcher": [],
            "group": "build"
        },
        {
            "label": "Supabase: Stop",
            "type": "shell",
            "command": "supabase stop",
            "problemMatcher": []
        },
        {
            "label": "Supabase: Reset DB",
            "type": "shell",
            "command": "supabase db reset",
            "problemMatcher": []
        },
        {
            "label": "Supabase: Generate Types",
            "type": "shell",
            "command": "supabase gen types typescript --local > src/lib/database.types.ts",
            "problemMatcher": []
        },
        {
            "label": "Prisma: Generate",
            "type": "shell",
            "command": "npx prisma generate",
            "problemMatcher": []
        },
        {
            "label": "Prisma: Migrate Dev",
            "type": "shell",
            "command": "npx prisma migrate dev",
            "problemMatcher": []
        }
    ]
}
```

### 13.5 Snippets

```json
// .vscode/supabase.code-snippets
{
    "Supabase Select Query": {
        "prefix": "sbsel",
        "body": [
            "const { data, error } = await supabase",
            "    .from('${1:table}')",
            "    .select('${2:*}')",
            "    ${3:.eq('${4:column}', ${5:value})}",
            "",
            "if (error) throw error",
            "return data"
        ]
    },
    "Supabase Insert": {
        "prefix": "sbins",
        "body": [
            "const { data, error } = await supabase",
            "    .from('${1:table}')",
            "    .insert(${2:data})",
            "    .select()",
            "    .single()",
            "",
            "if (error) throw error",
            "return data"
        ]
    },
    "Supabase Update": {
        "prefix": "sbupd",
        "body": [
            "const { data, error } = await supabase",
            "    .from('${1:table}')",
            "    .update(${2:updates})",
            "    .eq('${3:id}', ${4:value})",
            "    .select()",
            "    .single()",
            "",
            "if (error) throw error",
            "return data"
        ]
    },
    "RLS Policy": {
        "prefix": "rls",
        "body": [
            "CREATE POLICY \"${1:policy_name}\"",
            "ON ${2:public}.${3:table_name}",
            "FOR ${4|SELECT,INSERT,UPDATE,DELETE,ALL|}",
            "${5|USING,WITH CHECK|}(",
            "    ${6:auth.uid() = user_id}",
            ");"
        ]
    },
    "React Query Hook": {
        "prefix": "rqhook",
        "body": [
            "export function use${1:Resource}(${2:id}: string) {",
            "    return useQuery({",
            "        queryKey: ['${3:resource}', ${2}],",
            "        queryFn: async () => {",
            "            const { data, error } = await supabase",
            "                .from('${4:table}')",
            "                .select('*')",
            "                .eq('id', ${2})",
            "                .single()",
            "",
            "            if (error) throw error",
            "            return data",
            "        },",
            "        enabled: !!${2}",
            "    })",
            "}"
        ]
    }
}
```

---

## 14. Best Practices

### 14.1 Project Structure

```
my-supabase-app/
├── supabase/
│   ├── config.toml
│   ├── migrations/
│   │   ├── 20240101000000_initial_schema.sql
│   │   └── 20240102000000_add_products.sql
│   ├── functions/
│   │   ├── send-email/
│   │   │   └── index.ts
│   │   └── process-order/
│   │       └── index.ts
│   ├── seed.sql
│   └── tests/
│       └── database.test.sql
├── src/
│   ├── lib/
│   │   ├── supabase.ts           # Supabase client
│   │   ├── prisma.ts             # Prisma client
│   │   ├── database.types.ts     # Generated types
│   │   └── validation.ts         # Zod schemas
│   ├── services/
│   │   ├── products.ts
│   │   ├── orders.ts
│   │   └── auth.ts
│   ├── hooks/
│   │   ├── useProducts.ts
│   │   ├── useAuth.ts
│   │   └── usePermissions.ts
│   ├── components/
│   ├── pages/ or app/
│   └── providers/
├── prisma/
│   └── schema.prisma
├── .env.local
├── .env.example
└── package.json
```

### 14.2 Environment Management

```env
# .env.example
# Supabase
NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_ANON_KEY=
SUPABASE_SERVICE_ROLE_KEY=

# Database (for Prisma)
DATABASE_URL=
DIRECT_URL=

# External Services
STRIPE_SECRET_KEY=
RESEND_API_KEY=
```

### 14.3 Error Handling

```typescript
// src/lib/errors.ts
export class AppError extends Error {
    constructor(
        message: string,
        public code: string,
        public statusCode: number = 400,
        public details?: unknown
    ) {
        super(message)
        this.name = 'AppError'
    }
}

export function handleSupabaseError(error: any): never {
    if (error.code === 'PGRST116') {
        throw new AppError('Resource not found', 'NOT_FOUND', 404)
    }
    if (error.code === '23505') {
        throw new AppError('Duplicate entry', 'DUPLICATE', 409)
    }
    if (error.code === '42501') {
        throw new AppError('Permission denied', 'FORBIDDEN', 403)
    }
    throw new AppError(error.message, error.code || 'UNKNOWN', 500)
}

// Usage
try {
    const { data, error } = await supabase.from('products').select()
    if (error) handleSupabaseError(error)
    return data
} catch (error) {
    if (error instanceof AppError) {
        // Handle known errors
    }
    throw error
}
```

### 14.4 Testing

```typescript
// src/__tests__/products.test.ts
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
    process.env.SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!
)

describe('Products', () => {
    beforeEach(async () => {
        // Clean up test data
        await supabase.from('products').delete().like('name', 'Test%')
    })

    test('should create a product', async () => {
        const { data, error } = await supabase
            .from('products')
            .insert({
                name: 'Test Product',
                slug: 'test-product',
                price: 99.99
            })
            .select()
            .single()

        expect(error).toBeNull()
        expect(data?.name).toBe('Test Product')
    })

    test('should enforce RLS', async () => {
        // Use anon client
        const anonClient = createClient(
            process.env.SUPABASE_URL!,
            process.env.SUPABASE_ANON_KEY!
        )

        const { error } = await anonClient
            .from('products')
            .insert({ name: 'Test', slug: 'test', price: 10 })

        expect(error).not.toBeNull()
        expect(error?.code).toBe('42501') // Permission denied
    })
})
```

### 14.5 Security Checklist

```markdown
## Security Checklist

### Database
- [ ] RLS enabled on all tables
- [ ] Policies tested for all operations
- [ ] Service role key only used server-side
- [ ] No sensitive data in public schema without RLS
- [ ] Database functions use SECURITY DEFINER carefully

### Authentication
- [ ] Email confirmation enabled
- [ ] Password requirements configured
- [ ] JWT expiry time appropriate
- [ ] Refresh token rotation enabled

### API
- [ ] Rate limiting implemented
- [ ] Input validation on all endpoints
- [ ] CORS configured properly
- [ ] API keys never exposed client-side

### Edge Functions
- [ ] Authentication verified
- [ ] Environment secrets used
- [ ] Error messages don't leak info
- [ ] CORS headers set

### General
- [ ] Audit logging enabled
- [ ] Regular security reviews
- [ ] Backup strategy in place
- [ ] Monitoring and alerts configured
```

### 14.6 Performance Checklist

```markdown
## Performance Checklist

### Database
- [ ] Proper indexes on queried columns
- [ ] Materialized views for complex aggregations
- [ ] Connection pooling enabled
- [ ] Query analysis with EXPLAIN ANALYZE
- [ ] Vacuum and analyze scheduled

### Application
- [ ] React Query caching configured
- [ ] Pagination on all lists
- [ ] Only select needed columns
- [ ] Debounced search inputs
- [ ] Optimistic updates where appropriate

### Caching
- [ ] CDN caching for static assets
- [ ] API response caching headers
- [ ] Client-side cache invalidation strategy
- [ ] Materialized views refreshed appropriately
```

---

## Quick Reference Commands

```bash
# ============================================
# SUPABASE CLI
# ============================================
supabase init                    # Initialize project
supabase start                   # Start local development
supabase stop                    # Stop local development
supabase db reset                # Reset database with migrations and seeds
supabase db push                 # Push migrations to remote
supabase migration new <name>    # Create new migration
supabase gen types typescript    # Generate TypeScript types
supabase functions new <name>    # Create edge function
supabase functions deploy        # Deploy all functions
supabase secrets set KEY=value   # Set secret for functions

# ============================================
# PRISMA
# ============================================
npx prisma init                  # Initialize Prisma
npx prisma db pull               # Pull schema from database
npx prisma generate              # Generate Prisma Client
npx prisma migrate dev           # Create and apply migration
npx prisma migrate deploy        # Apply migrations (production)
npx prisma studio                # Open database GUI

# ============================================
# DATABASE
# ============================================
psql -h localhost -p 54322 -U postgres -d postgres  # Connect to local DB
```

---

## Conclusion

This guide covers the complete Supabase stack from setup to production. Key takeaways:

1. **Use RLS** - Always enable Row Level Security
2. **Type Safety** - Generate types and use TypeScript
3. **Optimize Queries** - Index properly, paginate, select only needed columns
4. **Cache Strategically** - Use React Query, materialized views, and CDN caching
5. **Secure Everything** - Validate inputs, audit actions, follow security checklist
6. **Test Thoroughly** - Test RLS policies, integration tests, load testing

For more details, refer to:
- [Supabase Documentation](https://supabase.com/docs)
- [Prisma Documentation](https://www.prisma.io/docs)
- [React Query Documentation](https://tanstack.com/query)
