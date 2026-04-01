import { create } from 'zustand'

type Theme = 'light' | 'dark'

interface ThemeState {
  theme: Theme
  setTheme: (theme: Theme) => void
  toggle: () => void
}

export const useThemeStore = create<ThemeState>((set, get) => ({
  theme: (localStorage.getItem('vyper-theme') as Theme) || 'dark',

  setTheme: (theme: Theme) => {
    localStorage.setItem('vyper-theme', theme)
    document.documentElement.classList.remove('light', 'dark')
    document.documentElement.classList.add(theme)
    set({ theme })
  },

  toggle: () => {
    const next = get().theme === 'dark' ? 'light' : 'dark'
    get().setTheme(next)
  },
}))

// Apply theme on load
const saved = (localStorage.getItem('vyper-theme') as Theme) || 'dark'
document.documentElement.classList.add(saved)
