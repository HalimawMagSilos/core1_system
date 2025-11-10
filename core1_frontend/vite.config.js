import { defineConfig } from 'vite'
import { resolve } from 'path'

export default defineConfig({
  root: '.', // Set root to current directory
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true
      }
    }
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'public_html/index.html'),
        login: resolve(__dirname, 'auth/login.html'),
        register: resolve(__dirname, 'auth/register.html'),
        forgotPassword: resolve(__dirname, 'auth/forgot-password.html'),
        resetPassword: resolve(__dirname, 'auth/reset-password.html'),
        verifyEmail: resolve(__dirname, 'auth/verify-email.html'),
        admin: resolve(__dirname, 'dashboard/admin.html'),
        doctor: resolve(__dirname, 'dashboard/doctor.html'),
        nurse: resolve(__dirname, 'dashboard/nurse.html'),
        receptionist: resolve(__dirname, 'dashboard/receptionist.html'),
        patient: resolve(__dirname, 'dashboard/patient.html')
      }
    }
  }
})