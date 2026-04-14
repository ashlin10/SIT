import { create } from 'zustand'

interface AuthState {
  username: string | null
  isAuthenticated: boolean
  isLoading: boolean
  error: string | null
  login: (username: string, password: string) => Promise<boolean>
  checkAuth: () => Promise<void>
  logout: () => Promise<void>
  clearError: () => void
}

export const useAuthStore = create<AuthState>((set) => ({
  username: null,
  isAuthenticated: false,
  isLoading: true,
  error: null,

  login: async (username: string, password: string) => {
    set({ isLoading: true, error: null })
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })

      if (res.ok) {
        const data = await res.json()
        set({ username: data.username, isAuthenticated: true, isLoading: false, error: null })
        return true
      }

      if (res.status === 401) {
        set({ isLoading: false, error: 'Invalid credentials' })
        return false
      }

      set({ isLoading: false, error: 'Login failed. Please try again.' })
      return false
    } catch {
      set({ isLoading: false, error: 'Network error. Please check your connection.' })
      return false
    }
  },

  checkAuth: async () => {
    try {
      const res = await fetch('/api/auth/check', { credentials: 'include' })
      if (res.ok) {
        const data = await res.json()
        set({ username: data.username, isAuthenticated: true, isLoading: false })
      } else {
        set({ username: null, isAuthenticated: false, isLoading: false })
      }
    } catch {
      set({ username: null, isAuthenticated: false, isLoading: false })
    }
  },

  logout: async () => {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
      })
    } finally {
      set({ username: null, isAuthenticated: false, error: null })
    }
  },

  clearError: () => set({ error: null }),
}))
