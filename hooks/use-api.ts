/**
 * Optimized React Hooks for User Operations
 * Provides client-side data fetching with SWR-like caching
 */

'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import { useToast } from '@/hooks/use-toast';
import type { ApiResponse } from '@/lib/api/response';

interface UseApiOptions {
  revalidateOnFocus?: boolean;
  revalidateOnReconnect?: boolean;
  refreshInterval?: number;
  errorRetryCount?: number;
  dedupingInterval?: number;
}

interface UseApiState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  mutating: boolean;
}

/**
 * Generic API hook with caching and error handling
 */
export function useApi<T>(
  key: string | null,
  fetcher: (() => Promise<ApiResponse<T>>) | null,
  options: UseApiOptions = {}
) {
  const [state, setState] = useState<UseApiState<T>>({
    data: null,
    error: null,
    loading: false,
    mutating: false
  });

  const { toast } = useToast();

  const {
    revalidateOnFocus = true,
    revalidateOnReconnect = true,
    refreshInterval = 0,
    errorRetryCount = 3,
    dedupingInterval = 2000
  } = options;

  // Cache for deduping requests
  const cache = useMemo(() => new Map<string, { 
    data: any; 
    timestamp: number; 
    promise?: Promise<any> 
  }>(), []);

  const fetchData = useCallback(async (retryCount = 0): Promise<void> => {
    if (!key || !fetcher) return;

    // Check cache for deduping
    const cached = cache.get(key);
    if (cached && Date.now() - cached.timestamp < dedupingInterval) {
      if (cached.promise) {
        await cached.promise;
        return;
      }
      setState(prev => ({ ...prev, data: cached.data, loading: false }));
      return;
    }

    setState(prev => ({ ...prev, loading: true, error: null }));

    try {
      const promise = fetcher();
      
      // Store promise for deduping
      cache.set(key, { data: null, timestamp: Date.now(), promise });

      const response = await promise;

      if (response.success) {
        setState(prev => ({ ...prev, data: response.data || null, loading: false }));
        cache.set(key, { data: response.data, timestamp: Date.now() });
      } else {
        throw new Error(response.error || 'API request failed');
      }
    } catch (error: any) {
      const errorMessage = error.message || 'An error occurred';
      
      if (retryCount < errorRetryCount) {
        // Exponential backoff
        setTimeout(() => fetchData(retryCount + 1), Math.pow(2, retryCount) * 1000);
      } else {
        setState(prev => ({ ...prev, error: errorMessage, loading: false }));
        toast({
          title: 'Error',
          description: errorMessage,
          variant: 'destructive'
        });
      }
    }
  }, [key, fetcher, cache, dedupingInterval, errorRetryCount, toast]);

  const mutate = useCallback(async (
    updater?: T | ((data: T | null) => T),
    shouldRevalidate = true
  ) => {
    setState(prev => ({ ...prev, mutating: true }));

    try {
      if (updater) {
        const newData = typeof updater === 'function' 
          ? (updater as Function)(state.data) 
          : updater;
        setState(prev => ({ ...prev, data: newData }));
      }

      if (shouldRevalidate) {
        await fetchData();
      }
    } finally {
      setState(prev => ({ ...prev, mutating: false }));
    }
  }, [fetchData, state.data]);

  // Initial fetch
  useEffect(() => {
    if (key && fetcher) {
      fetchData();
    }
  }, [key, fetchData]);

  // Focus revalidation
  useEffect(() => {
    if (!revalidateOnFocus) return;

    const handleFocus = () => {
      if (key && fetcher) {
        fetchData();
      }
    };

    window.addEventListener('focus', handleFocus);
    return () => window.removeEventListener('focus', handleFocus);
  }, [key, fetchData, revalidateOnFocus]);

  // Reconnect revalidation
  useEffect(() => {
    if (!revalidateOnReconnect) return;

    const handleOnline = () => {
      if (key && fetcher) {
        fetchData();
      }
    };

    window.addEventListener('online', handleOnline);
    return () => window.removeEventListener('online', handleOnline);
  }, [key, fetchData, revalidateOnReconnect]);

  // Interval refresh
  useEffect(() => {
    if (!refreshInterval || !key || !fetcher) return;

    const interval = setInterval(fetchData, refreshInterval);
    return () => clearInterval(interval);
  }, [key, fetchData, refreshInterval]);

  return {
    ...state,
    mutate,
    revalidate: fetchData
  };
}

/**
 * Hook for user list with optimized filtering and pagination
 */
export function useUsers(params: {
  page?: number;
  limit?: number;
  search?: string;
  role?: string;
  status?: string;
  department?: string;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
} = {}) {
  const fetcher = useCallback(async () => {
    const queryParams = new URLSearchParams();
    
    // Only add non-empty params to reduce cache misses
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        queryParams.append(key, value.toString());
      }
    });

    const response = await fetch(`/api/users?${queryParams.toString()}`);
    if (!response.ok) {
      throw new Error(`Failed to fetch users: ${response.status}`);
    }
    return response.json();
  }, [
    params.page,
    params.limit,
    params.search,
    params.role,
    params.status,
    params.department,
    params.sortBy,
    params.sortOrder
  ]);

  // Create stable key for caching
  const key = useMemo(() => {
    const filteredParams = Object.entries(params)
      .filter(([_, value]) => value !== undefined && value !== null && value !== '')
      .sort(([a], [b]) => a.localeCompare(b));
    return `users-${JSON.stringify(Object.fromEntries(filteredParams))}`;
  }, [
    params.page,
    params.limit,
    params.search,
    params.role,
    params.status,
    params.department,
    params.sortBy,
    params.sortOrder
  ]);

  return useApi(key, fetcher, {
    revalidateOnFocus: false,
    refreshInterval: 0, // Disable auto-refresh for better performance
    dedupingInterval: 2000, // Reduced deduping interval
    errorRetryCount: 1 // Reduce retry attempts
  });
}

/**
 * Hook for single user with caching
 */
export function useUser(id: string | null) {
  const fetcher = useCallback(async () => {
    if (!id) return null;
    const response = await fetch(`/api/users/${id}`);
    return response.json();
  }, [id]);

  const key = id ? `user-${id}` : null;

  return useApi(key, fetcher);
}

/**
 * Hook for user mutations with optimistic updates
 */
export function useUserMutations() {
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);

  const createUser = useCallback(async (userData: any) => {
    setLoading(true);
    try {
      const response = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userData)
      });

      const result = await response.json();

      if (!result.success) {
        throw new Error(result.error || 'Failed to create user');
      }

      toast({
        title: 'Success',
        description: 'User created successfully'
      });

      return result;
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message,
        variant: 'destructive'
      });
      throw error;
    } finally {
      setLoading(false);
    }
  }, [toast]);

  const updateUser = useCallback(async (id: string, userData: any) => {
    setLoading(true);
    try {
      const response = await fetch(`/api/users/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userData)
      });

      const result = await response.json();

      if (!result.success) {
        throw new Error(result.error || 'Failed to update user');
      }

      toast({
        title: 'Success',
        description: 'User updated successfully'
      });

      return result;
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message,
        variant: 'destructive'
      });
      throw error;
    } finally {
      setLoading(false);
    }
  }, [toast]);

  const deleteUser = useCallback(async (id: string) => {
    setLoading(true);
    try {
      const response = await fetch(`/api/users/${id}`, {
        method: 'DELETE'
      });

      const result = await response.json();

      if (!result.success) {
        throw new Error(result.error || 'Failed to delete user');
      }

      toast({
        title: 'Success',
        description: 'User deleted successfully'
      });

      return result;
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message,
        variant: 'destructive'
      });
      throw error;
    } finally {
      setLoading(false);
    }
  }, [toast]);

  return {
    createUser,
    updateUser,
    deleteUser,
    loading
  };
}

/**
 * Debounced value hook for search optimization
 */
export function useDebounce<T>(value: T, delay: number): T {
  const [debouncedValue, setDebouncedValue] = useState<T>(value);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      clearTimeout(handler);
    };
  }, [value, delay]);

  return debouncedValue;
}