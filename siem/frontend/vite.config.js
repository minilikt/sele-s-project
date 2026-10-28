import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // The dev server proxies /api to the FastAPI backend; production uses the
    // nginx reverse proxy with the same relative path.
    proxy: {
      '/api': {
        target: process.env.VITE_DEV_API || 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})
