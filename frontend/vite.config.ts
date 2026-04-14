import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: path.resolve(__dirname, '../web_app/spa'),
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'https://localhost:8000',
        changeOrigin: true,
        secure: false,
      },
      '/sso': {
        target: 'https://localhost:8000',
        changeOrigin: true,
        secure: false,
      },
      '/logout': {
        target: 'https://localhost:8000',
        changeOrigin: true,
        secure: false,
      },
      '/static': {
        target: 'https://localhost:8000',
        changeOrigin: true,
        secure: false,
      },
      '/strongswan': {
        target: 'https://localhost:8000',
        changeOrigin: true,
        secure: false,
      },
    },
  },
})
