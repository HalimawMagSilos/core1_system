const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const UserModel = require('../models/userModel');

// =============================================
// RATE LIMITING STORE WITH USERMODEL INTEGRATION
// =============================================

const customRateLimitStore = {
    // In-memory store for rate limiting data
    client: new Map(),

    // Required method for express-rate-limit
    increment: function (key, options, weight) {
        return new Promise((resolve) => {
            const now = Date.now();
            const windowMs = options.windowMs;
            const max = options.max;
            
            if (!this.client.has(key)) {
                this.client.set(key, {
                    totalHits: 0,
                    resetTime: new Date(now + windowMs)
                });
            }
            
            const entry = this.client.get(key);
            
            // Reset if window has passed
            if (entry.resetTime.getTime() <= now) {
                entry.totalHits = 0;
                entry.resetTime = new Date(now + windowMs);
            }
            
            // Increment hits
            entry.totalHits += (weight || 1);
            
            const resetTime = entry.resetTime.getTime();
            const retryAfter = Math.ceil((resetTime - now) / 1000);
            
            resolve({
                totalHits: entry.totalHits,
                resetTime: resetTime,
                retryAfter: retryAfter
            });
        });
    },

    // Clean up expired entries
    cleanup: function () {
        const now = Date.now();
        for (const [key, entry] of this.client.entries()) {
            if (entry.resetTime.getTime() <= now) {
                this.client.delete(key);
            }
        }
    }
};

// Run cleanup every minute
setInterval(() => {
    customRateLimitStore.cleanup();
}, 60000);

// =============================================
// RATE LIMITING MIDDLEWARE
// =============================================

// General API rate limiter with UserModel integration
const generalLimiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
    max: async (req) => {
        // Dynamic limits based on user role
        if (req.user) {
            switch (req.user.role_name) {
                case 'admin':
                    return parseInt(process.env.ADMIN_RATE_LIMIT) || 1000;
                case 'doctor':
                    return parseInt(process.env.DOCTOR_RATE_LIMIT) || 500;
                case 'nurse':
                    return parseInt(process.env.NURSE_RATE_LIMIT) || 300;
                case 'receptionist':
                    return parseInt(process.env.RECEPTIONIST_RATE_LIMIT) || 200;
                default:
                    return parseInt(process.env.PATIENT_RATE_LIMIT) || 100;
            }
        }
        return parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100;
    },
    message: {
        success: false,
        error: 'Rate limit exceeded',
        message: 'Too many requests from this IP, please try again later.',
        retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting for health checks and static files
        return req.path === '/health' || 
               req.path.startsWith('/static/') ||
               req.path === '/favicon.ico';
    },
    handler: async (req, res) => {
        // Log rate limit violation
        if (req.user) {
            await UserModel.logSecurityEvent(
                req.user.user_id,
                null,
                'rate_limit_exceeded',
                `User exceeded general API rate limit. IP: ${req.ip}, Path: ${req.path}`,
                'medium',
                req.ip,
                req.get('User-Agent')
            );
        }

        res.status(429).json({
            success: false,
            error: 'Rate limit exceeded',
            message: 'Too many requests from this IP, please try again later.',
            retryAfter: '15 minutes'
        });
    }
});

// Login rate limiter - stricter limits with security integration
const loginLimiter = rateLimit({
    windowMs: parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
    max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX_ATTEMPTS) || 5, // Limit each IP to 5 login attempts per windowMs
    message: {
        success: false,
        error: 'Too many login attempts',
        message: 'Too many login attempts from this IP, please try again after 15 minutes.',
        retryAfter: '15 minutes'
    },
    skipSuccessfulRequests: true, // Don't count successful logins
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        // Use both IP and email for more precise limiting
        const email = req.body.email || 'unknown';
        return `login:${req.ip}:${email}`;
    },
    handler: async (req, res) => {
        const email = req.body.email;
        
        // Log security event for login rate limiting
        await UserModel.logSecurityEvent(
            null, // No user ID yet
            null,
            'login_rate_limit_exceeded',
            `Excessive login attempts for email: ${email || 'unknown'} from IP: ${req.ip}`,
            'high',
            req.ip,
            req.get('User-Agent')
        );

        // If we have an email, check if account exists and lock it if necessary
        if (email) {
            try {
                const user = await UserModel.findUserByEmail(email);
                if (user) {
                    await UserModel.lockUserAccount(user.user_id, req.ip);
                }
            } catch (error) {
                console.error('Error locking account during rate limit:', error);
            }
        }

        res.status(429).json({
            success: false,
            error: 'Too many login attempts',
            message: 'Too many login attempts from this IP, please try again after 15 minutes.',
            retryAfter: '15 minutes'
        });
    }
});

// Registration rate limiter with enhanced security
const registrationLimiter = rateLimit({
    windowMs: parseInt(process.env.REGISTRATION_LIMIT_WINDOW_MS) || 60 * 60 * 1000, // 1 hour
    max: parseInt(process.env.REGISTRATION_LIMIT_MAX_ATTEMPTS) || 3, // Limit each IP to 3 registrations per hour
    message: {
        success: false,
        error: 'Too many registration attempts',
        message: 'Too many registration attempts from this IP, please try again later.',
        retryAfter: '1 hour'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        // Use IP and email for registration limiting
        const email = req.body.email || 'unknown';
        return `registration:${req.ip}:${email}`;
    },
    handler: async (req, res) => {
        const email = req.body.email;
        
        await UserModel.logSecurityEvent(
            null,
            null,
            'registration_rate_limit_exceeded',
            `Excessive registration attempts for email: ${email || 'unknown'} from IP: ${req.ip}`,
            'medium',
            req.ip,
            req.get('User-Agent')
        );

        res.status(429).json({
            success: false,
            error: 'Too many registration attempts',
            message: 'Too many registration attempts from this IP, please try again later.',
            retryAfter: '1 hour'
        });
    }
});

// Password reset rate limiter with security integration
const passwordResetLimiter = rateLimit({
    windowMs: parseInt(process.env.PASSWORD_RESET_LIMIT_WINDOW_MS) || 60 * 60 * 1000, // 1 hour
    max: parseInt(process.env.PASSWORD_RESET_LIMIT_MAX_ATTEMPTS) || 3, // Limit each IP to 3 password reset attempts per hour
    message: {
        success: false,
        error: 'Too many password reset attempts',
        message: 'Too many password reset attempts from this IP, please try again later.',
        retryAfter: '1 hour'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        const email = req.body.email || 'unknown';
        return `password_reset:${req.ip}:${email}`;
    },
    handler: async (req, res) => {
        const email = req.body.email;
        
        await UserModel.logSecurityEvent(
            null,
            null,
            'password_reset_rate_limit_exceeded',
            `Excessive password reset attempts for email: ${email || 'unknown'} from IP: ${req.ip}`,
            'medium',
            req.ip,
            req.get('User-Agent')
        );

        res.status(429).json({
            success: false,
            error: 'Too many password reset attempts',
            message: 'Too many password reset attempts from this IP, please try again later.',
            retryAfter: '1 hour'
        });
    }
});

// Email verification rate limiter
const emailVerificationLimiter = rateLimit({
    windowMs: parseInt(process.env.EMAIL_VERIFICATION_LIMIT_WINDOW_MS) || 60 * 60 * 1000, // 1 hour
    max: parseInt(process.env.EMAIL_VERIFICATION_LIMIT_MAX_ATTEMPTS) || 5, // Limit each IP to 5 verification attempts per hour
    message: {
        success: false,
        error: 'Too many email verification attempts',
        message: 'Too many email verification attempts, please try again later.',
        retryAfter: '1 hour'
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: async (req, res) => {
        await UserModel.logSecurityEvent(
            req.user?.user_id || null,
            null,
            'email_verification_rate_limit_exceeded',
            `Excessive email verification attempts from IP: ${req.ip}`,
            'low',
            req.ip,
            req.get('User-Agent')
        );

        res.status(429).json({
            success: false,
            error: 'Too many email verification attempts',
            message: 'Too many email verification attempts, please try again later.',
            retryAfter: '1 hour'
        });
    }
});

// Admin operations rate limiter - more generous limits
const adminLimiter = rateLimit({
    windowMs: parseInt(process.env.ADMIN_RATE_LIMIT_WINDOW_MS) || 5 * 60 * 1000, // 5 minutes
    max: parseInt(process.env.ADMIN_RATE_LIMIT_MAX_REQUESTS) || 200, // 200 requests per 5 minutes
    message: {
        success: false,
        error: 'Admin rate limit exceeded',
        message: 'Too many admin operations, please slow down.',
        retryAfter: '5 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Only apply to admin routes
        return !req.path.startsWith('/admin/');
    },
    handler: async (req, res) => {
        if (req.user) {
            await UserModel.logSecurityEvent(
                req.user.user_id,
                null,
                'admin_rate_limit_exceeded',
                `Admin user exceeded operation rate limit. Path: ${req.path}`,
                'medium',
                req.ip,
                req.get('User-Agent')
            );
        }

        res.status(429).json({
            success: false,
            error: 'Admin rate limit exceeded',
            message: 'Too many admin operations, please slow down.',
            retryAfter: '5 minutes'
        });
    }
});

// Data export rate limiter - very strict for large operations
const exportLimiter = rateLimit({
    windowMs: parseInt(process.env.EXPORT_RATE_LIMIT_WINDOW_MS) || 60 * 60 * 1000, // 1 hour
    max: parseInt(process.env.EXPORT_RATE_LIMIT_MAX_REQUESTS) || 5, // 5 exports per hour
    message: {
        success: false,
        error: 'Export rate limit exceeded',
        message: 'Too many data export requests, please try again later.',
        retryAfter: '1 hour'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        return !req.path.includes('/export') && !req.path.includes('/download');
    },
    handler: async (req, res) => {
        if (req.user) {
            await UserModel.logSecurityEvent(
                req.user.user_id,
                null,
                'export_rate_limit_exceeded',
                `User exceeded data export rate limit. Path: ${req.path}`,
                'medium',
                req.ip,
                req.get('User-Agent')
            );
        }

        res.status(429).json({
            success: false,
            error: 'Export rate limit exceeded',
            message: 'Too many data export requests, please try again later.',
            retryAfter: '1 hour'
        });
    }
});

// API key rate limiter for external integrations
const apiKeyLimiter = rateLimit({
    windowMs: parseInt(process.env.API_KEY_RATE_LIMIT_WINDOW_MS) || 60 * 1000, // 1 minute
    max: parseInt(process.env.API_KEY_RATE_LIMIT_MAX_REQUESTS) || 60, // 60 requests per minute
    message: {
        success: false,
        error: 'API rate limit exceeded',
        message: 'Too many API requests, please slow down.',
        retryAfter: '1 minute'
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        // Use API key for limiting if provided
        const apiKey = req.headers['x-api-key'] || 'unknown';
        return `api:${apiKey}`;
    },
    skip: (req) => {
        // Only apply to API routes with API keys
        return !req.path.startsWith('/api/') || !req.headers['x-api-key'];
    }
});

// =============================================
// SPEED LIMITING (SLOW DOWN) MIDDLEWARE
// =============================================

// General speed limiter for additional protection
const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: 50, // Allow 50 requests per 15 minutes, then...
    delayMs: 500, // Begin adding 500ms of delay per request above 50
    maxDelayMs: 20000, // Maximum delay of 20 seconds
    skip: (req) => {
        // Skip speed limiting for certain paths
        return req.path === '/health' || 
               req.path.startsWith('/static/') ||
               (req.user && req.user.role_name === 'admin');
    }
});

// Aggressive speed limiter for sensitive endpoints
const aggressiveSpeedLimiter = slowDown({
    windowMs: 5 * 60 * 1000, // 5 minutes
    delayAfter: 10, // Allow 10 requests per 5 minutes
    delayMs: 1000, // Add 1 second delay per request above limit
    maxDelayMs: 30000, // Maximum delay of 30 seconds
    skip: (req) => {
        return !req.path.includes('/admin/') && 
               !req.path.includes('/export') &&
               !req.path.includes('/download');
    }
});

// =============================================
// CUSTOM RATE LIMITING UTILITIES
// =============================================

// Dynamic rate limiting based on user behavior
const adaptiveLimiter = (req, res, next) => {
    // This would integrate with UserModel's rate limiting system
    // for more sophisticated adaptive rate limiting
    next();
};

// Rate limiting for specific user actions
const createActionRateLimiter = (action, maxAttempts, windowMs) => {
    return rateLimit({
        windowMs: windowMs,
        max: maxAttempts,
        keyGenerator: (req) => {
            const userId = req.user ? req.user.user_id : req.ip;
            return `action:${action}:${userId}`;
        },
        handler: async (req, res) => {
            if (req.user) {
                await UserModel.logSecurityEvent(
                    req.user.user_id,
                    null,
                    'action_rate_limit_exceeded',
                    `User exceeded rate limit for action: ${action}`,
                    'medium',
                    req.ip,
                    req.get('User-Agent')
                );
            }

            res.status(429).json({
                success: false,
                error: 'Action rate limit exceeded',
                message: `Too many ${action} attempts, please try again later.`,
                action: action
            });
        }
    });
};

// =============================================
// RATE LIMITING FOR SPECIFIC ACTIONS
// =============================================

// Profile update rate limiter
const profileUpdateLimiter = createActionRateLimiter('profile_update', 10, 15 * 60 * 1000);

// Password change rate limiter
const passwordChangeLimiter = createActionRateLimiter('password_change', 3, 60 * 60 * 1000);

// Device authorization rate limiter
const deviceAuthorizationLimiter = createActionRateLimiter('device_authorization', 5, 60 * 60 * 1000);

// Policy acceptance rate limiter
const policyAcceptanceLimiter = createActionRateLimiter('policy_acceptance', 10, 5 * 60 * 1000);

// =============================================
// RATE LIMITING CONFIGURATION VALIDATION
// =============================================

const validateRateLimitConfig = () => {
    const configs = [
        { env: 'RATE_LIMIT_WINDOW_MS', default: 900000, min: 60000, max: 3600000 },
        { env: 'RATE_LIMIT_MAX_REQUESTS', default: 100, min: 10, max: 10000 },
        { env: 'LOGIN_RATE_LIMIT_MAX_ATTEMPTS', default: 5, min: 3, max: 20 },
        { env: 'REGISTRATION_LIMIT_MAX_ATTEMPTS', default: 3, min: 1, max: 10 }
    ];

    for (const config of configs) {
        const value = parseInt(process.env[config.env]) || config.default;
        if (value < config.min || value > config.max) {
            console.warn(`Rate limit config ${config.env} value ${value} is outside recommended range (${config.min}-${config.max})`);
        }
    }
};

// Validate configuration on startup
validateRateLimitConfig();

module.exports = {
    generalLimiter,
    loginLimiter,
    registrationLimiter,
    passwordResetLimiter,
    emailVerificationLimiter,
    adminLimiter,
    exportLimiter,
    apiKeyLimiter,
    speedLimiter,
    aggressiveSpeedLimiter,
    profileUpdateLimiter,
    passwordChangeLimiter,
    deviceAuthorizationLimiter,
    policyAcceptanceLimiter,
    createActionRateLimiter,
    adaptiveLimiter
};