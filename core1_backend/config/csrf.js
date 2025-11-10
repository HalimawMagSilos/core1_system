const crypto = require('crypto');
const redis = require('./redis');

class CSRFProtection {
    constructor() {
        this.tokenExpiry = 3600; // 1 hour in seconds
        this.secretLength = 32;
    }

    // Generate a new CSRF token
    async generateToken(userId, sessionId) {
        if (!userId || !sessionId) {
            throw new Error('User ID and Session ID are required for CSRF token generation');
        }

        const secret = crypto.randomBytes(this.secretLength).toString('hex');
        const token = crypto.randomBytes(32).toString('hex');
        
        // Create token hash
        const tokenHash = crypto
            .createHash('sha256')
            .update(token + secret)
            .digest('hex');

        const tokenData = {
            userId,
            sessionId,
            tokenHash,
            createdAt: Date.now(),
            expiresAt: Date.now() + (this.tokenExpiry * 1000)
        };

        // Store in Redis
        const redisKey = `csrf:${userId}:${sessionId}`;
        await redis.setex(redisKey, this.tokenExpiry, JSON.stringify(tokenData));

        return token;
    }

    // Validate CSRF token
    async validateToken(userId, sessionId, token) {
        if (!userId || !sessionId || !token) {
            return false;
        }

        try {
            const redisKey = `csrf:${userId}:${sessionId}`;
            const tokenDataStr = await redis.get(redisKey);
            
            if (!tokenDataStr) {
                return false;
            }

            const tokenData = JSON.parse(tokenDataStr);

            // Check expiration
            if (Date.now() > tokenData.expiresAt) {
                await redis.del(redisKey);
                return false;
            }

            // Recreate the hash to validate
            const testHash = crypto
                .createHash('sha256')
                .update(token + tokenData.tokenHash)
                .digest('hex');

            // Constant-time comparison
            const isValid = this.constantTimeCompare(testHash, tokenData.tokenHash);
            
            if (!isValid) {
                await this.logSecurityEvent(userId, 'csrf_validation_failed', 'Invalid CSRF token provided');
            }

            return isValid;
        } catch (error) {
            console.error('CSRF token validation error:', error);
            await this.logSecurityEvent(userId, 'csrf_validation_error', 'CSRF token validation error');
            return false;
        }
    }

    // Revoke CSRF token (useful for logout)
    async revokeToken(userId, sessionId) {
        if (!userId || !sessionId) {
            return false;
        }

        try {
            const redisKey = `csrf:${userId}:${sessionId}`;
            await redis.del(redisKey);
            return true;
        } catch (error) {
            console.error('CSRF token revocation error:', error);
            return false;
        }
    }

    // Revoke all tokens for a user (useful for password change, etc.)
    async revokeAllUserTokens(userId) {
        if (!userId) {
            return false;
        }

        try {
            const pattern = `csrf:${userId}:*`;
            const keys = await redis.keys(pattern);
            
            if (keys.length > 0) {
                await redis.del(...keys);
            }
            
            return true;
        } catch (error) {
            console.error('Error revoking all user CSRF tokens:', error);
            return false;
        }
    }

    // Middleware for CSRF protection
    middleware() {
        return async (req, res, next) => {
            // Skip CSRF for GET, HEAD, OPTIONS requests
            if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
                return next();
            }

            // Skip for API routes that use other authentication
            if (req.path.startsWith('/api/') && req.headers['x-api-key']) {
                return next();
            }

            // Skip for webhook endpoints
            if (req.path.startsWith('/webhook/')) {
                return next();
            }

            try {
                const userId = req.user?.user_id;
                const sessionId = req.session?.id || req.headers['x-session-id'];
                const csrfToken = req.headers['x-csrf-token'] || req.body._csrf;

                if (!userId || !sessionId) {
                    return res.status(401).json({
                        success: false,
                        error: 'Authentication required',
                        message: 'User authentication required for CSRF protection'
                    });
                }

                if (!csrfToken) {
                    await this.logSecurityEvent(userId, 'csrf_missing', 'CSRF token missing from request');
                    return res.status(403).json({
                        success: false,
                        error: 'CSRF token required',
                        message: 'CSRF token is required for this request'
                    });
                }

                const isValid = await this.validateToken(userId, sessionId, csrfToken);
                if (!isValid) {
                    await this.logSecurityEvent(userId, 'csrf_invalid', 'Invalid CSRF token provided');
                    return res.status(403).json({
                        success: false,
                        error: 'Invalid CSRF token',
                        message: 'The provided CSRF token is invalid or expired'
                    });
                }

                next();
            } catch (error) {
                console.error('CSRF middleware error:', error);
                return res.status(500).json({
                    success: false,
                    error: 'CSRF validation error',
                    message: 'An error occurred during CSRF validation'
                });
            }
        };
    }

    // Generate and attach CSRF token to response
    async attachToken(req, res) {
        try {
            const userId = req.user?.user_id;
            const sessionId = req.session?.id || req.headers['x-session-id'];

            if (!userId || !sessionId) {
                return null;
            }

            const token = await this.generateToken(userId, sessionId);
            
            // Attach to response header
            res.setHeader('X-CSRF-Token', token);
            
            // Also include in response body for forms
            res.locals.csrfToken = token;
            
            return token;
        } catch (error) {
            console.error('Error attaching CSRF token:', error);
            return null;
        }
    }

    // Constant-time comparison to prevent timing attacks
    constantTimeCompare(a, b) {
        if (a.length !== b.length) {
            return false;
        }
        
        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a.charCodeAt(i) ^ b.charCodeAt(i);
        }
        return result === 0;
    }

    // Security event logging
    async logSecurityEvent(userId, eventType, description) {
        try {
            const UserModel = require('../models/userModel');
            await UserModel.logSecurityEvent(
                userId,
                null,
                eventType,
                description,
                'medium'
            );
        } catch (error) {
            console.error('Error logging CSRF security event:', error);
        }
    }

    // Get token info (for debugging/admin purposes)
    async getTokenInfo(userId, sessionId) {
        if (!userId || !sessionId) {
            return null;
        }

        try {
            const redisKey = `csrf:${userId}:${sessionId}`;
            const tokenDataStr = await redis.get(redisKey);
            
            if (!tokenDataStr) {
                return null;
            }

            const tokenData = JSON.parse(tokenDataStr);
            return {
                userId: tokenData.userId,
                sessionId: tokenData.sessionId,
                createdAt: new Date(tokenData.createdAt),
                expiresAt: new Date(tokenData.expiresAt),
                expiresIn: Math.max(0, tokenData.expiresAt - Date.now())
            };
        } catch (error) {
            console.error('Error getting CSRF token info:', error);
            return null;
        }
    }

    // Clean up expired tokens
    async cleanupExpiredTokens() {
        try {
            const pattern = 'csrf:*';
            const keys = await redis.keys(pattern);
            let cleanedCount = 0;

            for (const key of keys) {
                const tokenDataStr = await redis.get(key);
                if (tokenDataStr) {
                    const tokenData = JSON.parse(tokenDataStr);
                    if (Date.now() > tokenData.expiresAt) {
                        await redis.del(key);
                        cleanedCount++;
                    }
                }
            }

            console.log(`CSRF cleanup: Removed ${cleanedCount} expired tokens`);
            return cleanedCount;
        } catch (error) {
            console.error('Error cleaning up expired CSRF tokens:', error);
            return 0;
        }
    }
}

// Create singleton instance
const csrfProtection = new CSRFProtection();

// Export functions for direct use
module.exports = {
    // Middleware
    middleware: csrfProtection.middleware.bind(csrfProtection),
    attachToken: csrfProtection.attachToken.bind(csrfProtection),
    
    // Token management
    generateToken: csrfProtection.generateToken.bind(csrfProtection),
    validateToken: csrfProtection.validateToken.bind(csrfProtection),
    revokeToken: csrfProtection.revokeToken.bind(csrfProtection),
    revokeAllUserTokens: csrfProtection.revokeAllUserTokens.bind(csrfProtection),
    
    // Utility functions
    getTokenInfo: csrfProtection.getTokenInfo.bind(csrfProtection),
    cleanupExpiredTokens: csrfProtection.cleanupExpiredTokens.bind(csrfProtection),
    
    // Class for extension
    CSRFProtection
};