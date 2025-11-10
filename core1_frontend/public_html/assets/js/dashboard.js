// Dashboard functionality
class DashboardService {
    constructor() {
        this.apiBaseUrl = Utils.getApiBaseUrl();
    }

    // Load user profile
    async loadUserProfile() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/auth/profile`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${Utils.getAuthToken()}`,
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const data = await response.json();
                if (data.success) {
                    this.updateDashboardUI(data.user);
                }
            }
        } catch (error) {
            console.error('Error loading profile:', error);
        }
    }

    // Update dashboard UI with user data
    updateDashboardUI(user) {
        // Update welcome message
        const welcomeElement = document.getElementById('welcomeMessage');
        if (welcomeElement) {
            welcomeElement.textContent = `Welcome, ${user.username}!`;
        }

        // Update user info in sidebar
        const userEmailElement = document.getElementById('userEmail');
        if (userEmailElement) {
            userEmailElement.textContent = user.email;
        }

        const userRoleElement = document.getElementById('userRole');
        if (userRoleElement) {
            userRoleElement.textContent = user.role.charAt(0).toUpperCase() + user.role.slice(1);
        }

        // Update page title
        document.title = `${user.role.charAt(0).toUpperCase() + user.role.slice(1)} Dashboard - MediCare Pro`;
    }

    // Initialize dashboard
    initDashboard() {
        this.loadUserProfile();
        this.attachEventListeners();
    }

    // Attach event listeners
    attachEventListeners() {
        // Logout button
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => {
                authService.logout();
            });
        }

        // Mobile menu toggle
        const mobileMenuBtn = document.getElementById('mobileMenuButton');
        const sidebar = document.getElementById('sidebar');
        if (mobileMenuBtn && sidebar) {
            mobileMenuBtn.addEventListener('click', () => {
                sidebar.classList.toggle('-translate-x-full');
            });
        }
    }

    // Role-specific dashboard data
    async loadDashboardData(role) {
        try {
            // This would be expanded based on specific role requirements
            const endpoints = {
                admin: '/admin/stats',
                doctor: '/doctor/appointments',
                nurse: '/nurse/patients',
                receptionist: '/receptionist/appointments',
                patient: '/patient/records'
            };

            // Placeholder for actual API calls
            console.log(`Loading ${role} dashboard data...`);
            
        } catch (error) {
            console.error('Error loading dashboard data:', error);
        }
    }
}

// Initialize dashboard service
const dashboardService = new DashboardService();

// Make dashboardService available globally
window.dashboardService = dashboardService;

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    if (Utils.isAuthenticated()) {
        dashboardService.initDashboard();
        
        // Load role-specific data
        const user = Utils.getUser();
        if (user) {
            dashboardService.loadDashboardData(user.role);
        }
    } else {
        // Redirect to login if not authenticated
        window.location.href = '../auth/login.html';
    }
});