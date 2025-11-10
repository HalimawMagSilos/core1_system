const jwt = require('jsonwebtoken');
const UserModel = require('../models/userModel');

// =============================================
// AUTHENTICATION MIDDLEWARE
// =============================================

const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({
            error: 'Access token required',
            message: 'Please provide a valid authentication token'
        });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret-key');
        
        // Use UserModel to check if user exists and is active
        const user = await UserModel.findUserById(decoded.userId);

        if (!user) {
            return res.status(401).json({
                error: 'Invalid token',
                message: 'User account not found'
            });
        }

        if (!user.is_active) {
            return res.status(401).json({
                error: 'Account deactivated',
                message: 'Your account has been deactivated. Please contact administrator.'
            });
        }

        if (user.is_locked) {
            return res.status(401).json({
                error: 'Account locked',
                message: 'Your account has been locked. Please contact administrator or reset your password.'
            });
        }

        // Add user info to request
        req.user = {
            user_id: user.user_id,
            email: user.email,
            role_id: user.role_id,
            role_name: user.role_name,
            is_verified: user.is_verified,
            is_sso_user: user.is_sso_user,
            employee_id: user.employee_id
        };

        // Log access activity for sensitive endpoints
        if (req.originalUrl.includes('/admin/') || req.originalUrl.includes('/secure/')) {
            await UserModel.logUserActivity(
                user.user_id,
                null,
                null,
                'api_access',
                `Accessed protected endpoint: ${req.method} ${req.originalUrl}`,
                req.ip,
                req.get('User-Agent'),
                req.originalUrl,
                req.method
            );
        }

        next();
    } catch (error) {
        console.error('Token authentication error:', error);

        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                error: 'Token expired',
                message: 'Your session has expired. Please log in again.'
            });
        }

        if (error.name === 'JsonWebTokenError') {
            return res.status(403).json({
                error: 'Invalid token',
                message: 'Failed to authenticate token'
            });
        }
        
        return res.status(500).json({
            error: 'Authentication error',
            message: 'An error occurred during authentication'
        });
    }
};

// =============================================
// ROLE-BASED AUTHORIZATION MIDDLEWARE
// =============================================

const requireRole = (allowedRoles) => {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                return res.status(401).json({
                    error: 'Authentication required',
                    message: 'Please authenticate before accessing this resource'
                });
            }

            // Convert single role to array for consistency
            const rolesArray = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
            
            // Check if user's role is in allowed roles
            if (!rolesArray.includes(req.user.role_name)) {
                // Log unauthorized access attempt
                await UserModel.logSecurityEvent(
                    req.user.user_id,
                    null,
                    'unauthorized_access',
                    `User attempted to access restricted resource: ${req.method} ${req.originalUrl}. Required roles: ${rolesArray.join(', ')}, User role: ${req.user.role_name}`,
                    'medium',
                    req.ip,
                    req.get('User-Agent')
                );

                return res.status(403).json({
                    error: 'Insufficient permissions',
                    message: 'You do not have permission to access this resource'
                });
            }

            next();
        } catch (error) {
            console.error('Role verification error:', error);
            return res.status(500).json({
                error: 'Role verification failed',
                message: 'Failed to verify user permissions'
            });
        }
    };
};

// =============================================
// ADMIN-ONLY ACCESS MIDDLEWARE
// =============================================

const requireAdmin = async (req, res, next) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please authenticate before accessing this resource'
            });
        }

        if (req.user.role_name !== 'admin') {
            // Log unauthorized admin access attempt
            await UserModel.logSecurityEvent(
                req.user.user_id,
                null,
                'admin_access_denied',
                `Non-admin user attempted to access admin resource: ${req.method} ${req.originalUrl}`,
                'high',
                req.ip,
                req.get('User-Agent')
            );

            return res.status(403).json({
                error: 'Admin access required',
                message: 'Administrator privileges are required to access this resource'
            });
        }

        // Verify admin status in database for additional security
        const isAdmin = await UserModel.validateAdminRole(req.user.user_id);
        if (!isAdmin) {
            await UserModel.logSecurityEvent(
                req.user.user_id,
                null,
                'admin_privilege_escalation',
                'User with admin claim failed admin validation',
                'critical',
                req.ip,
                req.get('User-Agent')
            );

            return res.status(403).json({
                error: 'Admin verification failed',
                message: 'Failed to verify administrator privileges'
            });
        }

        next();
    } catch (error) {
        console.error('Admin verification error:', error);
        return res.status(500).json({
            error: 'Admin verification failed',
            message: 'Failed to verify administrator access'
        });
    }
};

// =============================================
// STAFF-ONLY ACCESS MIDDLEWARE
// =============================================

const requireStaff = async (req, res, next) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please authenticate before accessing this resource'
            });
        }

        const staffRoles = ['admin', 'doctor', 'nurse', 'receptionist'];
        
        if (!staffRoles.includes(req.user.role_name)) {
            await UserModel.logSecurityEvent(
                req.user.user_id,
                null,
                'staff_access_denied',
                `Patient user attempted to access staff resource: ${req.method} ${req.originalUrl}`,
                'medium',
                req.ip,
                req.get('User-Agent')
            );

            return res.status(403).json({
                error: 'Staff access required',
                message: 'Staff privileges are required to access this resource'
            });
        }

        next();
    } catch (error) {
        console.error('Staff verification error:', error);
        return res.status(500).json({
            error: 'Staff verification failed',
            message: 'Failed to verify staff access'
        });
    }
};

// =============================================
// EMAIL VERIFICATION REQUIREMENT MIDDLEWARE
// =============================================

const requireVerifiedEmail = async (req, res, next) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please authenticate before accessing this resource'
            });
        }

        if (!req.user.is_verified) {
            return res.status(403).json({
                error: 'Email verification required',
                message: 'Please verify your email address to access this resource'
            });
        }

        next();
    } catch (error) {
        console.error('Email verification check error:', error);
        return res.status(500).json({
            error: 'Verification check failed',
            message: 'Failed to verify email status'
        });
    }
};

// =============================================
// ACCOUNT ACTIVITY MIDDLEWARE
// =============================================

const logUserActivity = (activityType, description) => {
    return async (req, res, next) => {
        try {
            if (req.user) {
                await UserModel.logUserActivity(
                    req.user.user_id,
                    null,
                    null,
                    activityType,
                    description,
                    req.ip,
                    req.get('User-Agent'),
                    req.originalUrl,
                    req.method
                );
            }
            next();
        } catch (error) {
            console.error('Activity logging error:', error);
            // Don't block the request if logging fails
            next();
        }
    };
};

// =============================================
// RATE LIMITING MIDDLEWARE
// =============================================

const rateLimit = (maxAttempts = 5, windowMs = 900000, action = 'api_call') => {
    return async (req, res, next) => {
        try {
            const identifier = req.user ? req.user.user_id : req.ip;
            const rateLimit = UserModel.checkRateLimit(identifier, action, maxAttempts, windowMs);
            
            if (!rateLimit.allowed) {
                // Log rate limit violation
                if (req.user) {
                    await UserModel.logSecurityEvent(
                        req.user.user_id,
                        null,
                        'rate_limit_exceeded',
                        `User exceeded rate limit for ${action}. Max: ${maxAttempts} per ${windowMs/60000} minutes`,
                        'medium',
                        req.ip,
                        req.get('User-Agent')
                    );
                }

                return res.status(429).json({
                    error: 'Too many requests',
                    message: `Rate limit exceeded. Try again after ${rateLimit.resetTime.toLocaleTimeString()}`,
                    retryAfter: Math.ceil((rateLimit.resetTime - new Date()) / 1000)
                });
            }

            // Add rate limit info to response headers
            res.set({
                'X-RateLimit-Limit': maxAttempts,
                'X-RateLimit-Remaining': rateLimit.remaining,
                'X-RateLimit-Reset': Math.floor(rateLimit.resetTime.getTime() / 1000)
            });

            next();
        } catch (error) {
            console.error('Rate limiting error:', error);
            // Allow request to proceed if rate limiting fails
            next();
        }
    };
};

// =============================================
// CSRF PROTECTION MIDDLEWARE
// =============================================

const requireCSRFToken = async (req, res, next) => {
    try {
        // Skip CSRF for GET, HEAD, OPTIONS requests
        if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
            return next();
        }

        const csrfToken = req.headers['x-csrf-token'] || req.body.csrfToken;
        
        if (!csrfToken) {
            return res.status(403).json({
                error: 'CSRF token required',
                message: 'CSRF token is required for this request'
            });
        }

        // Validate CSRF token using UserModel
        if (!UserModel.validateCSRFToken(csrfToken)) {
            await UserModel.logSecurityEvent(
                req.user?.user_id,
                null,
                'csrf_validation_failed',
                'Invalid CSRF token provided',
                'high',
                req.ip,
                req.get('User-Agent')
            );

            return res.status(403).json({
                error: 'Invalid CSRF token',
                message: 'The provided CSRF token is invalid'
            });
        }

        next();
    } catch (error) {
        console.error('CSRF validation error:', error);
        return res.status(500).json({
            error: 'CSRF validation failed',
            message: 'Failed to validate CSRF token'
        });
    }
};

// =============================================
// DEVICE AUTHORIZATION MIDDLEWARE
// =============================================

const requireDeviceAuthorization = async (req, res, next) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please authenticate before accessing this resource'
            });
        }

        const deviceFingerprint = req.headers['x-device-fingerprint'];
        const userAgent = req.get('User-Agent');

        if (!deviceFingerprint) {
            return res.status(400).json({
                error: 'Device identification required',
                message: 'Device fingerprint is required for this resource'
            });
        }

        // Check device authorization
        const deviceAuth = await UserModel.checkDeviceAuthorization(
            req.user.user_id,
            deviceFingerprint,
            req.ip
        );

        if (!deviceAuth || !deviceAuth.is_authorized) {
            await UserModel.logSecurityEvent(
                req.user.user_id,
                null,
                'device_authorization_failed',
                `User attempted access from unauthorized device: ${deviceFingerprint}`,
                'high',
                req.ip,
                userAgent
            );

            return res.status(403).json({
                error: 'Device not authorized',
                message: 'This device is not authorized to access this resource. Please contact administrator.'
            });
        }

        // Check if device requires hospital network
        if (deviceAuth.require_hospital_network) {
            // Implement hospital network IP validation here
            const isHospitalNetwork = await validateHospitalNetwork(req.ip);
            if (!isHospitalNetwork) {
                await UserModel.logSecurityEvent(
                    req.user.user_id,
                    null,
                    'network_violation',
                    `User attempted access from non-hospital network. IP: ${req.ip}`,
                    'high',
                    req.ip,
                    userAgent
                );

                return res.status(403).json({
                    error: 'Network restriction',
                    message: 'This resource can only be accessed from hospital network'
                });
            }
        }

        // Check device usage limits
        if (deviceAuth.max_usage_count && deviceAuth.usage_count >= deviceAuth.max_usage_count) {
            await UserModel.logSecurityEvent(
                req.user.user_id,
                null,
                'device_usage_limit_exceeded',
                `Device usage limit exceeded: ${deviceAuth.usage_count}/${deviceAuth.max_usage_count}`,
                'medium',
                req.ip,
                userAgent
            );

            return res.status(403).json({
                error: 'Device usage limit exceeded',
                message: 'This device has reached its maximum usage limit. Please contact administrator.'
            });
        }

        // Check device expiration
        if (deviceAuth.valid_until && new Date(deviceAuth.valid_until) < new Date()) {
            await UserModel.logSecurityEvent(
                req.user.user_id,
                null,
                'device_authorization_expired',
                `Device authorization expired: ${deviceAuth.valid_until}`,
                'medium',
                req.ip,
                userAgent
            );

            return res.status(403).json({
                error: 'Device authorization expired',
                message: 'This device authorization has expired. Please contact administrator.'
            });
        }

        // Add device info to request
        req.device = deviceAuth;

        next();
    } catch (error) {
        console.error('Device authorization error:', error);
        return res.status(500).json({
            error: 'Device authorization failed',
            message: 'Failed to verify device authorization'
        });
    }
};

// Helper function for hospital network validation
async function validateHospitalNetwork(ip) {
    // Implement hospital network IP range validation
    // This would typically check against a list of hospital network IP ranges
    // For now, return true as a placeholder
    return true;
}

// =============================================
// POLICY ACCEPTANCE MIDDLEWARE
// =============================================

const requirePolicyAcceptance = async (req, res, next) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please authenticate before accessing this resource'
            });
        }

        // Check if user has accepted all required policies
        const compliance = await UserModel.getUserPolicyCompliance(req.user.user_id);
        const nonCompliant = compliance.filter(p => p.compliance_status === 'non_compliant');

        if (nonCompliant.length > 0) {
            return res.status(403).json({
                error: 'Policy acceptance required',
                message: 'You must accept all required hospital policies to access this resource',
                requiredPolicies: nonCompliant.map(p => ({
                    policy_type: p.policy_type,
                    policy_version: p.policy_version
                }))
            });
        }

        next();
    } catch (error) {
        console.error('Policy compliance check error:', error);
        return res.status(500).json({
            error: 'Policy check failed',
            message: 'Failed to verify policy compliance'
        });
    }
};

// =============================================
// TWO-FACTOR AUTHENTICATION MIDDLEWARE
// =============================================

const require2FA = async (req, res, next) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please authenticate before accessing this resource'
            });
        }

        // Check if 2FA is required for this user
        const twoFASettings = await UserModel.get2FASettings(req.user.user_id);
        
        if (twoFASettings && twoFASettings.require_2fa_for_login) {
            // Check if 2FA was completed in this session
            const twoFAToken = req.headers['x-2fa-token'];
            
            if (!twoFAToken) {
                return res.status(403).json({
                    error: '2FA required',
                    message: 'Two-factor authentication is required to access this resource'
                });
            }

            // Validate 2FA token
            const is2FAValid = await validate2FAToken(req.user.user_id, twoFAToken);
            if (!is2FAValid) {
                await UserModel.logSecurityEvent(
                    req.user.user_id,
                    null,
                    '2fa_validation_failed',
                    'Invalid 2FA token provided',
                    'medium',
                    req.ip,
                    req.get('User-Agent')
                );

                return res.status(403).json({
                    error: 'Invalid 2FA token',
                    message: 'The provided two-factor authentication token is invalid'
                });
            }
        }

        next();
    } catch (error) {
        console.error('2FA verification error:', error);
        return res.status(500).json({
            error: '2FA verification failed',
            message: 'Failed to verify two-factor authentication'
        });
    }
};

// Helper function for 2FA token validation
async function validate2FAToken(user_id, token) {
    // Implement 2FA token validation logic
    // This would typically verify TOTP codes, backup codes, or session tokens
    // For now, return true as a placeholder
    return true;
}

// =============================================
// SSO-ONLY ACCESS MIDDLEWARE
// =============================================

const requireSSO = async (req, res, next) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please authenticate before accessing this resource'
            });
        }

        if (!req.user.is_sso_user) {
            return res.status(403).json({
                error: 'SSO account required',
                message: 'This resource is only accessible to SSO-authenticated accounts'
            });
        }

        next();
    } catch (error) {
        console.error('SSO verification error:', error);
        return res.status(500).json({
            error: 'SSO verification failed',
            message: 'Failed to verify SSO authentication'
        });
    }
};

// =============================================
// PASSWORD-BASED ACCOUNT MIDDLEWARE
// =============================================

const requirePasswordAccount = async (req, res, next) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please authenticate before accessing this resource'
            });
        }

        if (req.user.is_sso_user) {
            return res.status(403).json({
                error: 'Password account required',
                message: 'This resource is only accessible to password-based accounts'
            });
        }

        next();
    } catch (error) {
        console.error('Password account verification error:', error);
        return res.status(500).json({
            error: 'Account verification failed',
            message: 'Failed to verify account type'
        });
    }
};

// =============================================
// RECAPTCHA VERIFICATION MIDDLEWARE
// =============================================

const requireRecaptcha = async (req, res, next) => {
    try {
        const recaptchaToken = req.headers['x-recaptcha-token'] || req.body.recaptchaToken;
        
        if (!recaptchaToken) {
            return res.status(400).json({
                error: 'reCAPTCHA required',
                message: 'reCAPTCHA verification is required for this action'
            });
        }

        // Here you would typically verify the reCAPTCHA token with Google
        // For now, we'll assume the verification happens in the controller
        // This middleware just ensures the token is present

        next();
    } catch (error) {
        console.error('reCAPTCHA verification error:', error);
        return res.status(500).json({
            error: 'reCAPTCHA verification failed',
            message: 'Failed to verify reCAPTCHA token'
        });
    }
};

// =============================================
// SESSION VALIDATION MIDDLEWARE
// =============================================

const validateSession = async (req, res, next) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please authenticate before accessing this resource'
            });
        }

        // Check if user session is still valid
        // This could check against the user_sessions table
        // For now, we rely on JWT expiration

        next();
    } catch (error) {
        console.error('Session validation error:', error);
        return res.status(500).json({
            error: 'Session validation failed',
            message: 'Failed to validate user session'
        });
    }
};

// =============================================
// IP WHITELISTING MIDDLEWARE
// =============================================

const requireWhitelistedIP = (allowedIPs = []) => {
    return async (req, res, next) => {
        try {
            const clientIP = req.ip;
            
            if (allowedIPs.length > 0 && !allowedIPs.includes(clientIP)) {
                await UserModel.logSecurityEvent(
                    req.user?.user_id,
                    null,
                    'ip_not_whitelisted',
                    `Access attempt from non-whitelisted IP: ${clientIP}`,
                    'high',
                    clientIP,
                    req.get('User-Agent')
                );

                return res.status(403).json({
                    error: 'IP not allowed',
                    message: 'Access from your IP address is not permitted'
                });
            }

            next();
        } catch (error) {
            console.error('IP whitelist check error:', error);
            return res.status(500).json({
                error: 'IP verification failed',
                message: 'Failed to verify IP address'
            });
        }
    };
};

// =============================================
// AUDIT LOGGING MIDDLEWARE
// =============================================

const auditLog = (action) => {
    return async (req, res, next) => {
        try {
            if (req.user) {
                await UserModel.logUserActivity(
                    req.user.user_id,
                    null,
                    null,
                    'audit_' + action,
                    `User performed action: ${action} on ${req.originalUrl}`,
                    req.ip,
                    req.get('User-Agent'),
                    req.originalUrl,
                    req.method,
                    res.statusCode,
                    req.originalUrl,
                    req.params.id || req.body.id || null
                );
            }
            next();
        } catch (error) {
            console.error('Audit logging error:', error);
            next();
        }
    };
};

module.exports = {
    authenticateToken,
    requireRole,
    requireAdmin,
    requireStaff,
    requireVerifiedEmail,
    requireCSRFToken,
    requireDeviceAuthorization,
    requirePolicyAcceptance,
    require2FA,
    requireSSO,
    requirePasswordAccount,
    requireRecaptcha,
    requireWhitelistedIP,
    validateSession,
    logUserActivity,
    rateLimit,
    auditLog
};