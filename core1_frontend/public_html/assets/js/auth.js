// Authentication functions
class AuthService {
    constructor() {
        this.apiBaseUrl = Utils.getApiBaseUrl();
    }

    // Handle login form submission
    async handleLogin(event) {
        event.preventDefault();
        
        const form = event.target;
        const email = form.email.value;
        const password = form.password.value;

        // Validation
        if (!Utils.validateEmail(email)) {
            Utils.showNotification('Please enter a valid email address', 'error');
            return;
        }

        if (!password) {
            Utils.showNotification('Please enter your password', 'error');
            return;
        }

        Utils.showLoading();

        try {
            const response = await fetch(`${this.apiBaseUrl}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (response.ok && data.success) {
                Utils.setAuthToken(data.token);
                Utils.setUser(data.user);
                Utils.showNotification('Login successful!', 'success');
                
                // Redirect to appropriate dashboard
                setTimeout(() => {
                    Utils.redirectToDashboard(data.user.role);
                }, 1000);
            } else {
                Utils.showNotification(data.message || 'Login failed', 'error');
            }
        } catch (error) {
            console.error('Login error:', error);
            Utils.showNotification('Network error. Please try again.', 'error');
        } finally {
            Utils.hideLoading();
        }
    }

    // Handle registration form submission
    async handleRegister(event) {
        event.preventDefault();
        
        const form = event.target;
        const formData = {
            username: form.username.value,
            email: form.email.value,
            password: form.password.value,
            role_id: parseInt(form.role_id.value),
            employee_id: form.employee_id?.value || ''
        };

        // Validation
        if (!Utils.validateEmail(formData.email)) {
            Utils.showNotification('Please enter a valid email address', 'error');
            return;
        }

        if (!Utils.validatePassword(formData.password)) {
            Utils.showNotification('Password must be at least 8 characters with uppercase, lowercase, number, and special character', 'error');
            return;
        }

        if (formData.username.length < 3) {
            Utils.showNotification('Username must be at least 3 characters', 'error');
            return;
        }

        Utils.showLoading();

        try {
            const response = await fetch(`${this.apiBaseUrl}/auth/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(formData)
            });

            const data = await response.json();

            if (response.ok && data.success) {
                Utils.showNotification('Registration successful! Please check your email for verification.', 'success');
                
                // Redirect to login after 3 seconds
                setTimeout(() => {
                    window.location.href = '/auth/login.html';
                }, 3000);
            } else {
                Utils.showNotification(data.message || 'Registration failed', 'error');
            }
        } catch (error) {
            console.error('Registration error:', error);
            Utils.showNotification('Network error. Please try again.', 'error');
        } finally {
            Utils.hideLoading();
        }
    }

    // Auto-attach form handlers
    init() {
        // Auto-attach form handlers based on current page
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        const forgotPasswordForm = document.getElementById('forgotPasswordForm');
        const resetPasswordForm = document.getElementById('resetPasswordForm');
        
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }
        
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => this.handleRegister(e));
        }
        
        if (forgotPasswordForm) {
            forgotPasswordForm.addEventListener('submit', (e) => this.handleForgotPassword(e));
        }
        
        if (resetPasswordForm) {
            resetPasswordForm.addEventListener('submit', (e) => this.handleResetPassword(e));
        }
    }
}

// Initialize auth service when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    const authService = new AuthService();
    authService.init();
});