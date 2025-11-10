// Utility functions
class Utils {
    // Show notification
    static showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 transform transition-all duration-300 ${
            type === 'success' ? 'bg-green-500 text-white' :
            type === 'error' ? 'bg-red-500 text-white' :
            type === 'warning' ? 'bg-yellow-500 text-black' :
            'bg-blue-500 text-white'
        }`;
        notification.innerHTML = `
            <div class="flex items-center space-x-2">
                <span>${message}</span>
                <button onclick="this.parentElement.parentElement.remove()" class="ml-2">×</button>
            </div>
        `;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);
    }

    // Validate email
    static validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    }

    // Validate password strength
    static validatePassword(password) {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
        
        return password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar;
    }

        // Get API base URL
    static getApiBaseUrl() {
        // For development with Vite proxy
        if (import.meta.env?.MODE === 'development') {
            return '/api';
        }
        // For production
        return import.meta.env?.VITE_API_BASE_URL || 'http://localhost:5000/api';
    }

    // Get auth token from localStorage
    static getAuthToken() {
        return localStorage.getItem('authToken');
    }

    // Set auth token to localStorage
    static setAuthToken(token) {
        localStorage.setItem('authToken', token);
    }

    // Remove auth token from localStorage
    static removeAuthToken() {
        localStorage.removeItem('authToken');
        localStorage.removeItem('user');
    }

    // Get user data from localStorage
    static getUser() {
        const user = localStorage.getItem('user');
        return user ? JSON.parse(user) : null;
    }

    // Set user data to localStorage
    static setUser(user) {
        localStorage.setItem('user', JSON.stringify(user));
    }

    // Check if user is authenticated
    static isAuthenticated() {
        return !!localStorage.getItem('authToken');
    }

    // Redirect to dashboard based on role
    static redirectToDashboard(role) {
        const dashboards = {
            'admin': '/dashboard/admin.html',
            'doctor': '/dashboard/doctor.html',
            'nurse': '/dashboard/nurse.html',
            'receptionist': '/dashboard/receptionist.html',
            'patient': '/dashboard/patient.html'
        };
        
        const dashboard = dashboards[role] || '/dashboard/patient.html';
        window.location.href = dashboard;
    }

    // Show loading spinner
    static showLoading() {
        const loading = document.createElement('div');
        loading.id = 'global-loading';
        loading.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
        loading.innerHTML = `
            <div class="bg-white p-6 rounded-lg shadow-lg flex items-center space-x-3">
                <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
                <span class="text-gray-700">Loading...</span>
            </div>
        `;
        document.body.appendChild(loading);
    }

    // Hide loading spinner
    static hideLoading() {
        const loading = document.getElementById('global-loading');
        if (loading) {
            loading.remove();
        }
    }
}

// Make Utils available globally
window.Utils = Utils;