const database = require('../config/database');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const ExcelJS = require('exceljs');
const PDFDocument = require('pdfkit');
const crypto = require('crypto');
const redis = require('../config/redis');
const { encryptData, decryptData } = require('../config/encryption');

// Security utility functions
class SecurityUtils {
    static sanitizeInput(input) {
        if (typeof input === 'string') {
            return input.replace(/[<>"'`;()&|$\\]/g, '');
        }
        return input;
    }

    static validateUUID(uuid) {
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        return uuidRegex.test(uuid);
    }

    static validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    static validateIP(ip) {
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    }

    static generateSecureRandomString(length = 32) {
        return crypto.randomBytes(length).toString('hex');
    }

    // Generate 6-digit numeric token
    static generate6DigitToken() {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }

    // Hash 6-digit token for secure storage
    static hash6DigitToken(token) {
        return crypto.createHash('sha256').update(token).digest('hex');
    }

    // Validate 6-digit token format
    static validate6DigitToken(token) {
        return /^\d{6}$/.test(token);
    }

    // Constant-time comparison to prevent timing attacks
    static constantTimeCompare(a, b) {
        if (a.length !== b.length) {
            return false;
        }
        
        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a.charCodeAt(i) ^ b.charCodeAt(i);
        }
        return result === 0;
    }
}

class UserModel {
    // Password validation regex
    static passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

    // Role constants
    static ROLES = {
        ADMIN: 1,
        DOCTOR: 2,
        NURSE: 3,
        RECEPTIONIST: 4,
        PATIENT: 5
    };

    // Redis cache keys
    static CACHE_KEYS = {
        ADMIN_DASHBOARD: 'admin_dashboard',
        USERS_TABLE: 'users_table',
        SESSIONS_TABLE: 'sessions_table',
        SECURITY_EVENTS_TABLE: 'security_events_table',
        LOGIN_ATTEMPTS_TABLE: 'login_attempts_table',
        DEVICES_TABLE: 'devices_table'
    };

    static CACHE_TTL = 30000; // 30 seconds

    // =============================================
    // REDIS-BASED CACHE MANAGEMENT
    // =============================================

    static getCacheKey(table, filters = {}) {
        return `${table}:${JSON.stringify(filters)}`;
    }

    static async setCache(key, data) {
        try {
            await redis.setex(key, this.CACHE_TTL / 1000, JSON.stringify(data));
        } catch (error) {
            console.error('Redis cache set error:', error);
        }
    }

    static async getCache(key) {
        try {
            const cached = await redis.get(key);
            return cached ? JSON.parse(cached) : null;
        } catch (error) {
            console.error('Redis cache get error:', error);
            return null;
        }
    }

    static async clearCache(pattern = null) {
        try {
            if (pattern) {
                const keys = await redis.keys(`${pattern}*`);
                if (keys.length > 0) {
                    await redis.del(...keys);
                }
            } else {
                // Clear all user-related caches
                const cachePatterns = [
                    this.CACHE_KEYS.ADMIN_DASHBOARD + '*',
                    this.CACHE_KEYS.USERS_TABLE + '*',
                    this.CACHE_KEYS.SESSIONS_TABLE + '*',
                    this.CACHE_KEYS.SECURITY_EVENTS_TABLE + '*',
                    this.CACHE_KEYS.LOGIN_ATTEMPTS_TABLE + '*',
                    this.CACHE_KEYS.DEVICES_TABLE + '*'
                ];
                
                for (const pattern of cachePatterns) {
                    const keys = await redis.keys(pattern);
                    if (keys.length > 0) {
                        await redis.del(...keys);
                    }
                }
            }
        } catch (error) {
            console.error('Redis cache clear error:', error);
        }
    }

    // =============================================
    // SECURITY MIDDLEWARE & UTILITIES
    // =============================================

    static sanitizeUserInput(input) {
        if (typeof input === 'string') {
            return SecurityUtils.sanitizeInput(input);
        } else if (Array.isArray(input)) {
            return input.map(item => this.sanitizeUserInput(item));
        } else if (typeof input === 'object' && input !== null) {
            const sanitized = {};
            for (const [key, value] of Object.entries(input)) {
                sanitized[key] = this.sanitizeUserInput(value);
            }
            return sanitized;
        }
        return input;
    }

    static validateQueryParams(params, allowedParams) {
        const validated = {};
        for (const [key, value] of Object.entries(params)) {
            if (allowedParams.includes(key) && value !== undefined && value !== null && value !== '') {
                validated[key] = this.sanitizeUserInput(value);
            }
        }
        return validated;
    }

    // =============================================
    // ENCRYPTED TOKEN MANAGEMENT (FIXED)
    // =============================================

    async createEmailToken(user_id, token_type, token, token_hash, expires_at, ip_address, user_agent, metadata = null) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        if (!['email_verification', 'password_reset', '2fa_code', 'device_verification', 'account_activation', 'sso_linking'].includes(token_type)) {
            throw new Error('Invalid token type');
        }

        if (!SecurityUtils.validate6DigitToken(token)) {
            throw new Error('Invalid token format. Must be 6 digits.');
        }

        if (ip_address && !SecurityUtils.validateIP(ip_address)) {
            throw new Error('Invalid IP address format');
        }

        const token_id = uuidv4();
        
        // ENCRYPT the token before storage
        const encryptedToken = encryptData(token);
        
        const sql = `
            INSERT INTO email_tokens (
                token_id, user_id, token_type, token, token_hash, 
                expires_at, ip_address, user_agent, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        await database.query(sql, [
            token_id, user_id, token_type, encryptedToken, token_hash, 
            expires_at, ip_address, user_agent, metadata ? JSON.stringify(metadata) : null
        ]);
        
        return token_id;
    }

    async findEmailToken(token, token_type) {
        if (!token || typeof token !== 'string') {
            return null;
        }

        if (!SecurityUtils.validate6DigitToken(token)) {
            return null;
        }

        if (!['email_verification', 'password_reset', '2fa_code', 'device_verification', 'account_activation', 'sso_linking'].includes(token_type)) {
            return null;
        }

        const sanitizedToken = SecurityUtils.sanitizeInput(token);
        const token_hash = SecurityUtils.hash6DigitToken(sanitizedToken);
        
        const sql = `
            SELECT et.*, u.user_id, u.email, u.is_verified 
            FROM email_tokens et 
            JOIN users u ON et.user_id = u.user_id 
            WHERE et.token_hash = ? AND et.token_type = ? AND et.expires_at > NOW() AND et.is_used = false
        `;
        
        const tokens = await database.query(sql, [token_hash, token_type]);
        
        if (tokens[0]) {
            // DECRYPT the token for verification
            tokens[0].token = decryptData(tokens[0].token);
        }
        
        return tokens[0] || null;
    }

    async findEmailTokenByUserId(user_id, token_type) {
        if (!SecurityUtils.validateUUID(user_id)) {
            return null;
        }

        if (!['email_verification', 'password_reset', '2fa_code', 'device_verification', 'account_activation', 'sso_linking'].includes(token_type)) {
            return null;
        }

        const sql = `
            SELECT et.*, u.user_id, u.email, u.is_verified 
            FROM email_tokens et 
            JOIN users u ON et.user_id = u.user_id 
            WHERE et.user_id = ? AND et.token_type = ? AND et.expires_at > NOW() AND et.is_used = false
            ORDER BY et.created_at DESC 
            LIMIT 1
        `;
        
        const tokens = await database.query(sql, [user_id, token_type]);
        
        if (tokens[0]) {
            // DECRYPT the token
            tokens[0].token = decryptData(tokens[0].token);
        }
        
        return tokens[0] || null;
    }

    async markTokenUsed(token_id) {
        if (!SecurityUtils.validateUUID(token_id)) {
            throw new Error('Invalid token ID format');
        }

        const sql = `UPDATE email_tokens SET is_used = true, used_at = CURRENT_TIMESTAMP WHERE token_id = ?`;
        await database.query(sql, [token_id]);
    }

    async invalidateUserTokens(user_id, token_type) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        const sql = `
            UPDATE email_tokens 
            SET is_used = true, used_at = CURRENT_TIMESTAMP 
            WHERE user_id = ? AND token_type = ? AND is_used = false
        `;
        await database.query(sql, [user_id, token_type]);
    }

    async cleanupExpiredTokens() {
        const sql = `DELETE FROM email_tokens WHERE expires_at < NOW()`;
        await database.query(sql);
    }

    // =============================================
    // REAL-TIME ADMIN DASHBOARD DATA (REDIS-ENABLED)
    // =============================================

    async getAdminDashboardData(admin_user_id) {
        if (!SecurityUtils.validateUUID(admin_user_id)) {
            throw new Error('Invalid admin user ID');
        }

        // Verify admin role
        const admin = await this.findUserById(admin_user_id);
        if (!admin || admin.role_id !== UserModel.ROLES.ADMIN) {
            throw new Error('Access denied: Admin privileges required');
        }

        const cacheKey = UserModel.getCacheKey(UserModel.CACHE_KEYS.ADMIN_DASHBOARD, { admin_id: admin_user_id });
        const cached = await UserModel.getCache(cacheKey);
        if (cached) return cached;

        const [
            userStats,
            securityStats,
            sessionStats,
            deviceStats,
            recentActivities,
            securityAlerts
        ] = await Promise.all([
            this.getUserStatistics(),
            this.getSecurityStatistics(),
            this.getSessionStatistics(),
            this.getDeviceStatistics(),
            this.getRecentActivities(10),
            this.getSecurityAlerts(5)
        ]);

        const dashboardData = {
            userStats,
            securityStats,
            sessionStats,
            deviceStats,
            recentActivities,
            securityAlerts,
            lastUpdated: new Date().toISOString()
        };

        await UserModel.setCache(cacheKey, dashboardData);
        return dashboardData;
    }

    async getUserStatistics() {
        const sql = `
            SELECT 
                COUNT(*) as total_users,
                SUM(CASE WHEN is_active = true THEN 1 ELSE 0 END) as active_users,
                SUM(CASE WHEN is_locked = true THEN 1 ELSE 0 END) as locked_users,
                SUM(CASE WHEN is_verified = true THEN 1 ELSE 0 END) as verified_users,
                SUM(CASE WHEN is_sso_user = true THEN 1 ELSE 0 END) as sso_users,
                COUNT(DISTINCT role_id) as unique_roles,
                (SELECT COUNT(*) FROM users WHERE DATE(created_at) = CURDATE()) as new_today,
                (SELECT COUNT(*) FROM users WHERE last_login_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)) as active_week
            FROM users
        `;
        const result = await database.query(sql);
        return result[0] || {};
    }

    async getSecurityStatistics() {
        const sql = `
            SELECT 
                (SELECT COUNT(*) FROM login_attempts WHERE DATE(attempted_at) = CURDATE()) as login_attempts_today,
                (SELECT COUNT(*) FROM login_attempts WHERE DATE(attempted_at) = CURDATE() AND attempt_result = 'success') as successful_logins_today,
                (SELECT COUNT(*) FROM login_attempts WHERE DATE(attempted_at) = CURDATE() AND is_suspicious = true) as suspicious_attempts_today,
                (SELECT COUNT(*) FROM security_events WHERE DATE(created_at) = CURDATE() AND severity = 'high') as high_security_events_today,
                (SELECT COUNT(*) FROM user_sessions WHERE is_active = true AND expires_at > NOW()) as active_sessions_now,
                (SELECT COUNT(*) FROM authorized_devices WHERE is_authorized = true) as authorized_devices_total,
                (SELECT COUNT(*) FROM two_factor_auth WHERE is_totp_enabled = true) as users_with_2fa
            FROM DUAL
        `;
        const result = await database.query(sql);
        return result[0] || {};
    }

    async getSessionStatistics() {
        const sql = `
            SELECT 
                COUNT(*) as total_sessions,
                SUM(CASE WHEN is_active = true THEN 1 ELSE 0 END) as active_sessions,
                SUM(CASE WHEN policies_accepted = true THEN 1 ELSE 0 END) as compliant_sessions,
                COUNT(DISTINCT user_id) as unique_users_with_sessions,
                AVG(TIMESTAMPDIFF(MINUTE, created_at, expires_at)) as avg_session_duration_minutes,
                (SELECT COUNT(*) FROM user_sessions WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)) as sessions_last_hour
            FROM user_sessions
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        `;
        const result = await database.query(sql);
        return result[0] || {};
    }

    async getDeviceStatistics() {
        const sql = `
            SELECT 
                COUNT(*) as total_devices,
                SUM(CASE WHEN is_authorized = true THEN 1 ELSE 0 END) as authorized_devices,
                COUNT(DISTINCT device_type) as unique_device_types,
                COUNT(DISTINCT operating_system) as unique_os_types,
                (SELECT COUNT(*) FROM device_usage_log WHERE DATE(used_at) = CURDATE()) as device_logins_today,
                (SELECT COUNT(*) FROM device_usage_log WHERE is_compliant = false AND DATE(used_at) = CURDATE()) as non_compliant_logins_today
            FROM authorized_devices
        `;
        const result = await database.query(sql);
        return result[0] || {};
    }

    async getRecentActivities(limit = 10) {
        const sql = `
            SELECT 
                ual.activity_id,
                ual.user_id,
                u.email,
                r.role_name,
                ual.activity_type,
                ual.activity_description,
                ual.ip_address,
                ual.performed_at,
                ual.security_level
            FROM user_activity_log ual
            JOIN users u ON ual.user_id = u.user_id
            JOIN roles r ON u.role_id = r.role_id
            ORDER BY ual.performed_at DESC
            LIMIT ?
        `;
        return await database.query(sql, [limit]);
    }

    async getSecurityAlerts(limit = 5) {
        const sql = `
            SELECT 
                se.event_id,
                se.user_id,
                u.email,
                se.event_type,
                se.event_description,
                se.severity,
                se.ip_address,
                se.created_at
            FROM security_events se
            LEFT JOIN users u ON se.user_id = u.user_id
            WHERE se.severity IN ('high', 'critical')
            ORDER BY se.created_at DESC
            LIMIT ?
        `;
        return await database.query(sql, [limit]);
    }

    // =============================================
    // REAL-TIME DATA TABLES FOR ADMIN
    // =============================================

    async getRealTimeUsersTable(filters = {}, admin_user_id) {
        if (!SecurityUtils.validateUUID(admin_user_id)) {
            throw new Error('Invalid admin user ID');
        }

        // Verify admin role
        const admin = await this.findUserById(admin_user_id);
        if (!admin || admin.role_id !== UserModel.ROLES.ADMIN) {
            throw new Error('Access denied: Admin privileges required');
        }

        const cacheKey = UserModel.getCacheKey(UserModel.CACHE_KEYS.USERS_TABLE, filters);
        const cached = await UserModel.getCache(cacheKey);
        if (cached) return cached;

        const allowedFilters = ['page', 'limit', 'role_id', 'role_name', 'is_active', 'is_locked', 'is_verified', 'is_sso_user', 'search', 'date_from', 'date_to', 'last_login_from', 'last_login_to', 'sort_by', 'sort_order'];
        const validatedFilters = UserModel.validateQueryParams(filters, allowedFilters);
        
        const {
            page = 1,
            limit = 50,
            role_id = null,
            role_name = null,
            is_active = null,
            is_locked = null,
            is_verified = null,
            is_sso_user = null,
            search = null,
            date_from = null,
            date_to = null,
            last_login_from = null,
            last_login_to = null,
            sort_by = 'created_at',
            sort_order = 'DESC'
        } = validatedFilters;

        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(Math.max(1, parseInt(limit)), 1000);

        let whereConditions = ['1=1'];
        let params = [];

        if (role_id) {
            const roleIdNum = parseInt(role_id);
            if (roleIdNum >= 1 && roleIdNum <= 5) {
                whereConditions.push('u.role_id = ?');
                params.push(roleIdNum);
            }
        }
        if (role_name) {
            const allowedRoles = ['admin', 'doctor', 'nurse', 'receptionist', 'patient'];
            if (allowedRoles.includes(role_name)) {
                whereConditions.push('r.role_name = ?');
                params.push(role_name);
            }
        }

        if (is_active !== null) {
            whereConditions.push('u.is_active = ?');
            params.push(is_active === 'true' || is_active === true);
        }
        if (is_locked !== null) {
            whereConditions.push('u.is_locked = ?');
            params.push(is_locked === 'true' || is_locked === true);
        }
        if (is_verified !== null) {
            whereConditions.push('u.is_verified = ?');
            params.push(is_verified === 'true' || is_verified === true);
        }
        if (is_sso_user !== null) {
            whereConditions.push('u.is_sso_user = ?');
            params.push(is_sso_user === 'true' || is_sso_user === true);
        }

        if (search && search.length <= 100) {
            whereConditions.push('(u.email LIKE ? OR u.employee_id LIKE ? OR r.role_name LIKE ?)');
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm);
        }

        if (date_from) {
            whereConditions.push('u.created_at >= ?');
            params.push(date_from);
        }
        if (date_to) {
            whereConditions.push('u.created_at <= ?');
            params.push(date_to);
        }
        if (last_login_from) {
            whereConditions.push('u.last_login_at >= ?');
            params.push(last_login_from);
        }
        if (last_login_to) {
            whereConditions.push('u.last_login_at <= ?');
            params.push(last_login_to);
        }

        const whereClause = whereConditions.join(' AND ');
        const offset = (pageNum - 1) * limitNum;

        const allowedSortColumns = ['email', 'role_name', 'created_at', 'last_login_at', 'is_active', 'is_locked'];
        const safeSortBy = allowedSortColumns.includes(sort_by) ? sort_by : 'created_at';
        const safeSortOrder = sort_order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

        const sql = `
            SELECT 
                u.user_id,
                u.email,
                u.role_id,
                r.role_name,
                u.is_active,
                u.is_locked,
                u.is_verified,
                u.is_sso_user,
                u.sso_provider,
                u.failed_login_attempts,
                u.lock_until,
                u.last_login_at,
                u.last_login_ip,
                u.employee_id,
                u.created_at,
                u.updated_at,
                (SELECT COUNT(*) FROM user_sessions us WHERE us.user_id = u.user_id AND us.is_active = true) as active_sessions_count,
                (SELECT COUNT(*) FROM authorized_devices ad WHERE ad.user_id = u.user_id AND ad.is_authorized = true) as authorized_devices_count,
                (SELECT COUNT(*) FROM policy_acceptances pa WHERE pa.user_id = u.user_id) as policies_accepted_count,
                (SELECT COUNT(*) FROM sso_identities si WHERE si.user_id = u.user_id AND si.is_active = true) as sso_identities_count,
                (SELECT MAX(attempted_at) FROM login_attempts la WHERE la.user_id = u.user_id AND la.attempt_result = 'success') as last_successful_login
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            WHERE ${whereClause}
            ORDER BY ${safeSortBy} ${safeSortOrder}
            LIMIT ? OFFSET ?
        `;

        const countSql = `
            SELECT COUNT(*) as total
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            WHERE ${whereClause}
        `;

        const [users, countResult] = await Promise.all([
            database.query(sql, [...params, limitNum, offset]),
            database.query(countSql, params)
        ]);

        const result = {
            users,
            total: countResult[0]?.total || 0,
            page: pageNum,
            limit: limitNum,
            totalPages: Math.ceil((countResult[0]?.total || 0) / limitNum),
            lastUpdated: new Date().toISOString()
        };

        await UserModel.setCache(cacheKey, result);
        return result;
    }

    async getRealTimeSessionsTable(filters = {}, admin_user_id) {
        if (!SecurityUtils.validateUUID(admin_user_id)) {
            throw new Error('Invalid admin user ID');
        }

        const admin = await this.findUserById(admin_user_id);
        if (!admin || admin.role_id !== UserModel.ROLES.ADMIN) {
            throw new Error('Access denied: Admin privileges required');
        }

        const cacheKey = UserModel.getCacheKey(UserModel.CACHE_KEYS.SESSIONS_TABLE, filters);
        const cached = await UserModel.getCache(cacheKey);
        if (cached) return cached;

        const allowedFilters = ['page', 'limit', 'user_id', 'is_active', 'auth_method', 'policies_accepted', 'date_from', 'date_to', 'sort_by', 'sort_order'];
        const validatedFilters = UserModel.validateQueryParams(filters, allowedFilters);
        
        const {
            page = 1,
            limit = 50,
            user_id = null,
            is_active = null,
            auth_method = null,
            policies_accepted = null,
            date_from = null,
            date_to = null,
            sort_by = 'last_activity_at',
            sort_order = 'DESC'
        } = validatedFilters;

        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(Math.max(1, parseInt(limit)), 1000);

        let whereConditions = ['1=1'];
        let params = [];

        if (user_id && SecurityUtils.validateUUID(user_id)) {
            whereConditions.push('us.user_id = ?');
            params.push(user_id);
        }

        if (is_active !== null) {
            whereConditions.push('us.is_active = ?');
            params.push(is_active === 'true' || is_active === true);
        }

        if (auth_method) {
            const allowedMethods = ['password', 'sso', 'password_with_2fa', 'sso_with_2fa'];
            if (allowedMethods.includes(auth_method)) {
                whereConditions.push('us.auth_method = ?');
                params.push(auth_method);
            }
        }

        if (policies_accepted !== null) {
            whereConditions.push('us.policies_accepted = ?');
            params.push(policies_accepted === 'true' || policies_accepted === true);
        }

        if (date_from) {
            whereConditions.push('us.created_at >= ?');
            params.push(date_from);
        }
        if (date_to) {
            whereConditions.push('us.created_at <= ?');
            params.push(date_to);
        }

        const whereClause = whereConditions.join(' AND ');
        const offset = (pageNum - 1) * limitNum;

        const allowedSortColumns = ['last_activity_at', 'created_at', 'expires_at', 'email', 'role_name', 'auth_method'];
        const safeSortBy = allowedSortColumns.includes(sort_by) ? sort_by : 'last_activity_at';
        const safeSortOrder = sort_order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

        const sql = `
            SELECT 
                us.session_id,
                us.user_id,
                u.email,
                r.role_name,
                us.auth_method,
                us.sso_identity_id,
                us.ip_address,
                us.device_type,
                us.browser_name,
                us.country_code,
                us.city,
                us.is_active,
                us.policies_accepted,
                us.last_activity_at,
                us.created_at,
                us.expires_at,
                TIMESTAMPDIFF(MINUTE, us.created_at, us.expires_at) as session_duration_minutes,
                TIMESTAMPDIFF(MINUTE, us.last_activity_at, NOW()) as minutes_since_last_activity,
                ad.device_name,
                ad.is_authorized as device_authorized
            FROM user_sessions us
            JOIN users u ON us.user_id = u.user_id
            JOIN roles r ON u.role_id = r.role_id
            LEFT JOIN authorized_devices ad ON us.user_id = ad.user_id 
                AND ad.device_fingerprint = SHA2(us.user_agent, 256)
            WHERE ${whereClause}
            ORDER BY ${safeSortBy} ${safeSortOrder}
            LIMIT ? OFFSET ?
        `;

        const countSql = `
            SELECT COUNT(*) as total
            FROM user_sessions us
            WHERE ${whereClause}
        `;

        const [sessions, countResult] = await Promise.all([
            database.query(sql, [...params, limitNum, offset]),
            database.query(countSql, params)
        ]);

        const result = {
            sessions,
            total: countResult[0]?.total || 0,
            page: pageNum,
            limit: limitNum,
            totalPages: Math.ceil((countResult[0]?.total || 0) / limitNum),
            lastUpdated: new Date().toISOString()
        };

        await UserModel.setCache(cacheKey, result);
        return result;
    }

    async getRealTimeSecurityEventsTable(filters = {}, admin_user_id) {
        if (!SecurityUtils.validateUUID(admin_user_id)) {
            throw new Error('Invalid admin user ID');
        }

        const admin = await this.findUserById(admin_user_id);
        if (!admin || admin.role_id !== UserModel.ROLES.ADMIN) {
            throw new Error('Access denied: Admin privileges required');
        }

        const cacheKey = UserModel.getCacheKey(UserModel.CACHE_KEYS.SECURITY_EVENTS_TABLE, filters);
        const cached = await UserModel.getCache(cacheKey);
        if (cached) return cached;

        const allowedFilters = ['page', 'limit', 'event_type', 'severity', 'user_id', 'date_from', 'date_to', 'sort_by', 'sort_order'];
        const validatedFilters = UserModel.validateQueryParams(filters, allowedFilters);
        
        const {
            page = 1,
            limit = 50,
            event_type = null,
            severity = null,
            user_id = null,
            date_from = null,
            date_to = null,
            sort_by = 'created_at',
            sort_order = 'DESC'
        } = validatedFilters;

        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(Math.max(1, parseInt(limit)), 1000);

        let whereConditions = ['1=1'];
        let params = [];

        if (event_type) {
            const allowedEvents = [
                'password_change', 'password_reset_request', 'password_reset_success',
                'email_change', 'profile_update', '2fa_enabled', '2fa_disabled', '2fa_method_changed',
                'device_authorized', 'device_revoked', 'device_blocked', 'suspicious_activity',
                'account_lockout', 'account_unlock', 'session_revoked', 'forced_logout',
                'brute_force_detected', 'admin_device_management', 'user_role_changed',
                'sso_linked', 'sso_unlinked', 'sso_login', 'policy_accepted', 'policy_declined',
                'policy_updated', 'recaptcha_failed', 'recaptcha_bypassed'
            ];
            if (allowedEvents.includes(event_type)) {
                whereConditions.push('se.event_type = ?');
                params.push(event_type);
            }
        }

        if (severity) {
            const allowedSeverities = ['low', 'medium', 'high', 'critical'];
            if (allowedSeverities.includes(severity)) {
                whereConditions.push('se.severity = ?');
                params.push(severity);
            }
        }

        if (user_id && SecurityUtils.validateUUID(user_id)) {
            whereConditions.push('(se.user_id = ? OR se.affected_user_id = ?)');
            params.push(user_id, user_id);
        }

        if (date_from) {
            whereConditions.push('se.created_at >= ?');
            params.push(date_from);
        }
        if (date_to) {
            whereConditions.push('se.created_at <= ?');
            params.push(date_to);
        }

        const whereClause = whereConditions.join(' AND ');
        const offset = (pageNum - 1) * limitNum;

        const allowedSortColumns = ['created_at', 'severity', 'event_type'];
        const safeSortBy = allowedSortColumns.includes(sort_by) ? sort_by : 'created_at';
        const safeSortOrder = sort_order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

        const sql = `
            SELECT 
                se.event_id,
                se.user_id,
                u1.email as user_email,
                se.event_type,
                se.event_description,
                se.severity,
                se.ip_address,
                se.user_agent,
                se.affected_user_id,
                u2.email as affected_user_email,
                se.session_id,
                se.metadata,
                se.created_at
            FROM security_events se
            LEFT JOIN users u1 ON se.user_id = u1.user_id
            LEFT JOIN users u2 ON se.affected_user_id = u2.user_id
            WHERE ${whereClause}
            ORDER BY ${safeSortBy} ${safeSortOrder}
            LIMIT ? OFFSET ?
        `;

        const countSql = `
            SELECT COUNT(*) as total
            FROM security_events se
            WHERE ${whereClause}
        `;

        const [events, countResult] = await Promise.all([
            database.query(sql, [...params, limitNum, offset]),
            database.query(countSql, params)
        ]);

        const result = {
            events,
            total: countResult[0]?.total || 0,
            page: pageNum,
            limit: limitNum,
            totalPages: Math.ceil((countResult[0]?.total || 0) / limitNum),
            lastUpdated: new Date().toISOString()
        };

        await UserModel.setCache(cacheKey, result);
        return result;
    }

    async getRealTimeLoginAttemptsTable(filters = {}, admin_user_id) {
        if (!SecurityUtils.validateUUID(admin_user_id)) {
            throw new Error('Invalid admin user ID');
        }

        const admin = await this.findUserById(admin_user_id);
        if (!admin || admin.role_id !== UserModel.ROLES.ADMIN) {
            throw new Error('Access denied: Admin privileges required');
        }

        const cacheKey = UserModel.getCacheKey(UserModel.CACHE_KEYS.LOGIN_ATTEMPTS_TABLE, filters);
        const cached = await UserModel.getCache(cacheKey);
        if (cached) return cached;

        const allowedFilters = ['page', 'limit', 'email', 'attempt_result', 'auth_method', 'sso_provider', 'is_suspicious', 'date_from', 'date_to', 'sort_by', 'sort_order'];
        const validatedFilters = UserModel.validateQueryParams(filters, allowedFilters);
        
        const {
            page = 1,
            limit = 50,
            email = null,
            attempt_result = null,
            auth_method = null,
            sso_provider = null,
            is_suspicious = null,
            date_from = null,
            date_to = null,
            sort_by = 'attempted_at',
            sort_order = 'DESC'
        } = validatedFilters;

        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(Math.max(1, parseInt(limit)), 1000);

        let whereConditions = ['1=1'];
        let params = [];

        if (email) {
            whereConditions.push('la.email LIKE ?');
            params.push(`%${email}%`);
        }

        if (attempt_result) {
            const allowedResults = [
                'success', 'invalid_password', 'user_not_found', 'account_locked',
                '2fa_required', '2fa_failed', 'device_not_authorized',
                'hospital_network_required', 'sso_failed', 'recaptcha_failed',
                'policies_not_accepted'
            ];
            if (allowedResults.includes(attempt_result)) {
                whereConditions.push('la.attempt_result = ?');
                params.push(attempt_result);
            }
        }

        if (auth_method) {
            const allowedMethods = ['password', 'sso', 'password_with_2fa', 'sso_with_2fa'];
            if (allowedMethods.includes(auth_method)) {
                whereConditions.push('la.auth_method = ?');
                params.push(auth_method);
            }
        }

        if (sso_provider) {
            const allowedProviders = ['google', 'microsoft', 'apple', 'saml', 'oidc'];
            if (allowedProviders.includes(sso_provider)) {
                whereConditions.push('la.sso_provider = ?');
                params.push(sso_provider);
            }
        }

        if (is_suspicious !== null) {
            whereConditions.push('la.is_suspicious = ?');
            params.push(is_suspicious === 'true' || is_suspicious === true);
        }

        if (date_from) {
            whereConditions.push('la.attempted_at >= ?');
            params.push(date_from);
        }
        if (date_to) {
            whereConditions.push('la.attempted_at <= ?');
            params.push(date_to);
        }

        const whereClause = whereConditions.join(' AND ');
        const offset = (pageNum - 1) * limitNum;

        const allowedSortColumns = ['attempted_at', 'risk_score', 'email', 'attempt_result'];
        const safeSortBy = allowedSortColumns.includes(sort_by) ? sort_by : 'attempted_at';
        const safeSortOrder = sort_order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

        const sql = `
            SELECT 
                la.attempt_id,
                la.email,
                la.ip_address,
                la.user_agent,
                la.country_code,
                la.city,
                la.auth_method,
                la.sso_provider,
                la.attempt_result,
                la.recaptcha_score,
                la.risk_score,
                la.is_suspicious,
                la.suspicious_reasons,
                la.user_id,
                u.email as user_email,
                r.role_name,
                la.session_id,
                la.device_id,
                la.attempted_at
            FROM login_attempts la
            LEFT JOIN users u ON la.user_id = u.user_id
            LEFT JOIN roles r ON u.role_id = r.role_id
            WHERE ${whereClause}
            ORDER BY ${safeSortBy} ${safeSortOrder}
            LIMIT ? OFFSET ?
        `;

        const countSql = `
            SELECT COUNT(*) as total
            FROM login_attempts la
            WHERE ${whereClause}
        `;

        const [attempts, countResult] = await Promise.all([
            database.query(sql, [...params, limitNum, offset]),
            database.query(countSql, params)
        ]);

        const result = {
            attempts,
            total: countResult[0]?.total || 0,
            page: pageNum,
            limit: limitNum,
            totalPages: Math.ceil((countResult[0]?.total || 0) / limitNum),
            lastUpdated: new Date().toISOString()
        };

        await UserModel.setCache(cacheKey, result);
        return result;
    }

    async getRealTimeDevicesTable(filters = {}, admin_user_id) {
        if (!SecurityUtils.validateUUID(admin_user_id)) {
            throw new Error('Invalid admin user ID');
        }

        const admin = await this.findUserById(admin_user_id);
        if (!admin || admin.role_id !== UserModel.ROLES.ADMIN) {
            throw new Error('Access denied: Admin privileges required');
        }

        const cacheKey = UserModel.getCacheKey(UserModel.CACHE_KEYS.DEVICES_TABLE, filters);
        const cached = await UserModel.getCache(cacheKey);
        if (cached) return cached;

        const allowedFilters = ['page', 'limit', 'user_id', 'is_authorized', 'device_type', 'require_hospital_network', 'sort_by', 'sort_order'];
        const validatedFilters = UserModel.validateQueryParams(filters, allowedFilters);
        
        const {
            page = 1,
            limit = 50,
            user_id = null,
            is_authorized = null,
            device_type = null,
            require_hospital_network = null,
            sort_by = 'last_used_at',
            sort_order = 'DESC'
        } = validatedFilters;

        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(Math.max(1, parseInt(limit)), 1000);

        let whereConditions = ['1=1'];
        let params = [];

        if (user_id && SecurityUtils.validateUUID(user_id)) {
            whereConditions.push('ad.user_id = ?');
            params.push(user_id);
        }

        if (is_authorized !== null) {
            whereConditions.push('ad.is_authorized = ?');
            params.push(is_authorized === 'true' || is_authorized === true);
        }

        if (device_type) {
            whereConditions.push('ad.device_type LIKE ?');
            params.push(`%${device_type}%`);
        }

        if (require_hospital_network !== null) {
            whereConditions.push('ad.require_hospital_network = ?');
            params.push(require_hospital_network === 'true' || require_hospital_network === true);
        }

        const whereClause = whereConditions.join(' AND ');
        const offset = (pageNum - 1) * limitNum;

        const allowedSortColumns = ['last_used_at', 'created_at', 'device_name', 'user_id'];
        const safeSortBy = allowedSortColumns.includes(sort_by) ? sort_by : 'last_used_at';
        const safeSortOrder = sort_order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

        const sql = `
            SELECT 
                ad.device_id,
                ad.user_id,
                u.email,
                r.role_name,
                ad.device_name,
                ad.device_fingerprint,
                ad.device_type,
                ad.mac_address,
                ad.operating_system,
                ad.browser_family,
                ad.is_authorized,
                ad.authorized_by,
                auth_user.email as authorized_by_email,
                ad.authorized_at,
                ad.allowed_ips,
                ad.allowed_ip_ranges,
                ad.require_hospital_network,
                ad.last_used_at,
                ad.usage_count,
                ad.valid_until,
                ad.max_usage_count,
                ad.created_at,
                ad.updated_at,
                (SELECT COUNT(*) FROM device_usage_log dul WHERE dul.device_id = ad.device_id) as total_usage_count,
                (SELECT COUNT(*) FROM device_usage_log dul WHERE dul.device_id = ad.device_id AND dul.is_compliant = false) as non_compliant_count
            FROM authorized_devices ad
            JOIN users u ON ad.user_id = u.user_id
            JOIN roles r ON u.role_id = r.role_id
            LEFT JOIN users auth_user ON ad.authorized_by = auth_user.user_id
            WHERE ${whereClause}
            ORDER BY ${safeSortBy} ${safeSortOrder}
            LIMIT ? OFFSET ?
        `;

        const countSql = `
            SELECT COUNT(*) as total
            FROM authorized_devices ad
            WHERE ${whereClause}
        `;

        const [devices, countResult] = await Promise.all([
            database.query(sql, [...params, limitNum, offset]),
            database.query(countSql, params)
        ]);

        const result = {
            devices,
            total: countResult[0]?.total || 0,
            page: pageNum,
            limit: limitNum,
            totalPages: Math.ceil((countResult[0]?.total || 0) / limitNum),
            lastUpdated: new Date().toISOString()
        };

        await UserModel.setCache(cacheKey, result);
        return result;
    }

    // =============================================
    // USER PASSWORD MANAGEMENT
    // =============================================

    async changeUserPassword(user_id, currentPassword, newPassword, ip_address = null, user_agent = null, csrfToken = null) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
            throw new Error('Invalid password format');
        }

        // Use CSRF protection from the new module
        const { validateCSRFToken } = require('../config/csrf');
        if (csrfToken && !validateCSRFToken(user_id, csrfToken)) {
            throw new Error('Invalid CSRF token');
        }

        const user = await this.findUserById(user_id);
        if (!user) {
            throw new Error('User not found');
        }

        if (!user.password_hash) {
            throw new Error('No password set for this user (SSO user)');
        }

        const isCurrentPasswordValid = await this.verifyPassword(currentPassword, user.password_hash);
        if (!isCurrentPasswordValid) {
            await this.logSecurityEvent(
                user_id,
                null,
                'password_change_failed',
                'Failed password change attempt - incorrect current password',
                'medium',
                ip_address,
                user_agent
            );
            throw new Error('Current password is incorrect');
        }

        if (!this.validatePasswordStrength(newPassword)) {
            throw new Error('New password does not meet security requirements');
        }

        if (await this.verifyPassword(newPassword, user.password_hash)) {
            throw new Error('New password cannot be the same as current password');
        }

        const isPasswordInHistory = await this.isPasswordInHistory(user_id, newPassword);
        if (isPasswordInHistory) {
            throw new Error('New password cannot be the same as any of your previous 5 passwords');
        }

        const newPasswordHash = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_ROUNDS) || 12);

        const sql = `
            UPDATE users 
            SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP, failed_login_attempts = 0, 
                is_locked = false, lock_until = NULL
            WHERE user_id = ?
        `;
        
        await database.query(sql, [newPasswordHash, user_id]);

        await this.addPasswordHistory(user_id, newPasswordHash);

        await this.logSecurityEvent(
            user_id,
            null,
            'password_change',
            'User successfully changed password',
            'medium',
            ip_address,
            user_agent
        );

        await this.logUserActivity(
            user_id,
            null,
            null,
            'password_change',
            'User successfully changed password',
            ip_address,
            user_agent
        );

        // Clear relevant caches
        await UserModel.clearCache(UserModel.CACHE_KEYS.USERS_TABLE);
        await UserModel.clearCache(UserModel.CACHE_KEYS.SECURITY_EVENTS_TABLE);

        return {
            success: true,
            message: 'Password changed successfully'
        };
    }

    async isPasswordInHistory(user_id, newPassword, historyLimit = 5) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        const sql = `
            SELECT password_hash 
            FROM password_history 
            WHERE user_id = ? 
            ORDER BY changed_at DESC 
            LIMIT ?
        `;
        
        const history = await database.query(sql, [user_id, historyLimit]);
        
        for (const record of history) {
            if (await bcrypt.compare(newPassword, record.password_hash)) {
                return true;
            }
        }
        
        return false;
    }

    async getUserPasswordHistory(user_id, limit = 5) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        const sql = `
            SELECT ph.*, u.email as changed_by_email
            FROM password_history ph
            LEFT JOIN users u ON ph.changed_by = u.user_id
            WHERE ph.user_id = ?
            ORDER BY ph.changed_at DESC
            LIMIT ?
        `;
        
        return await database.query(sql, [user_id, limit]);
    }

    async validatePasswordRequirements(password) {
        if (typeof password !== 'string') {
            return {
                isValid: false,
                requirements: {},
                message: 'Password must be a string'
            };
        }

        const requirements = {
            minLength: password.length >= 8,
            hasUpperCase: /[A-Z]/.test(password),
            hasLowerCase: /[a-z]/.test(password),
            hasNumber: /\d/.test(password),
            hasSpecialChar: /[@$!%*?&]/.test(password),
            noSpaces: !/\s/.test(password),
            maxLength: password.length <= 128
        };

        const isValid = Object.values(requirements).every(Boolean);
        
        return {
            isValid,
            requirements,
            message: isValid ? 'Password meets all requirements' : 'Password does not meet all requirements'
        };
    }

    // =============================================
    // USER REGISTRATION & AUTHENTICATION
    // =============================================

    async createUser(userData, csrfToken = null) {
        // Use CSRF protection
        const { validateCSRFToken } = require('../config/csrf');
        if (csrfToken && !validateCSRFToken(userData.user_id, csrfToken)) {
            throw new Error('Invalid CSRF token');
        }

        const sanitizedData = UserModel.sanitizeUserInput(userData);
        
        const {
            email,
            password,
            role_id = UserModel.ROLES.PATIENT,
            employee_id = null,
            created_by = null,
            is_sso_user = false,
            sso_provider = null,
            sso_subject_id = null,
            sso_identity_data = null
        } = sanitizedData;

        if (!email) {
            throw new Error('Email is required');
        }

        if (!SecurityUtils.validateEmail(email)) {
            throw new Error('Invalid email format');
        }

        // Prevent admin role creation
        if (parseInt(role_id) === UserModel.ROLES.ADMIN) {
            throw new Error('Cannot create admin users through this method');
        }

        if (!is_sso_user && password) {
            if (!this.validatePasswordStrength(password)) {
                throw new Error('Password does not meet security requirements');
            }
        }

        const user_id = uuidv4();
        const password_hash = is_sso_user ? null : await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS) || 12);

        const sql = `
            INSERT INTO users (
                user_id, email, password_hash, 
                role_id, employee_id, created_by, is_verified, is_sso_user,
                sso_provider, sso_subject_id, sso_identity_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        try {
            await database.query(sql, [
                user_id, email, password_hash,
                role_id, employee_id, created_by, is_sso_user, is_sso_user,
                sso_provider, sso_subject_id, sso_identity_data ? JSON.stringify(sso_identity_data) : null
            ]);

            await this.logSecurityEvent(
                created_by || user_id,
                null,
                'user_created',
                `User account created: ${email}`,
                'low'
            );

            // Clear caches
            await UserModel.clearCache(UserModel.CACHE_KEYS.USERS_TABLE);
            await UserModel.clearCache(UserModel.CACHE_KEYS.ADMIN_DASHBOARD);

            return user_id;
        } catch (error) {
            if (error.code === 'ER_DUP_ENTRY') {
                throw new Error('Email already exists');
            }
            throw error;
        }
    }

    async createPatientUser(email, password, ip_address = null, user_agent = null, csrfToken = null) {
        if (!SecurityUtils.validateEmail(email)) {
            throw new Error('Invalid email format');
        }

        if (ip_address && !SecurityUtils.validateIP(ip_address)) {
            throw new Error('Invalid IP address format');
        }

        const userData = {
            email: email,
            password: password,
            role_id: UserModel.ROLES.PATIENT,
            is_sso_user: false
        };

        const user_id = await this.createUser(userData, csrfToken);

        if (ip_address) {
            await this.logUserActivity(
                user_id, 
                null, 
                null, 
                'registration', 
                'Patient account created', 
                ip_address, 
                user_agent
            );
        }

        return user_id;
    }

    async createSSOUser(ssoData, csrfToken = null) {
        const sanitizedData = UserModel.sanitizeUserInput(ssoData);
        
        const {
            email,
            sso_provider,
            provider_user_id,
            provider_identity_data,
            role_id = UserModel.ROLES.PATIENT,
            employee_id = null
        } = sanitizedData;

        if (!SecurityUtils.validateEmail(email)) {
            throw new Error('Invalid email format');
        }

        if (!['google', 'microsoft', 'apple', 'saml', 'oidc'].includes(sso_provider)) {
            throw new Error('Invalid SSO provider');
        }

        // Prevent admin role creation
        if (parseInt(role_id) === UserModel.ROLES.ADMIN) {
            throw new Error('Cannot create admin users through SSO');
        }

        const userData = {
            email: email,
            password: 'dummy_password',
            role_id: role_id,
            employee_id: employee_id,
            is_sso_user: true,
            sso_provider: sso_provider,
            sso_subject_id: provider_user_id,
            sso_identity_data: provider_identity_data
        };

        const user_id = await this.createUser(userData, csrfToken);

        await this.createSSOIdentity(user_id, sso_provider, provider_user_id, email, provider_identity_data);

        return user_id;
    }

    async createSSOIdentity(user_id, sso_provider, provider_user_id, provider_email, provider_identity_data) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        const sso_identity_id = uuidv4();
        
        const sql = `
            INSERT INTO sso_identities (
                sso_identity_id, user_id, sso_provider, provider_user_id, 
                provider_email, provider_identity_data
            ) VALUES (?, ?, ?, ?, ?, ?)
        `;

        await database.query(sql, [
            sso_identity_id, user_id, sso_provider, provider_user_id,
            provider_email, provider_identity_data ? JSON.stringify(provider_identity_data) : null
        ]);

        return sso_identity_id;
    }

    async findUserByEmail(email) {
        if (!email || typeof email !== 'string') {
            return null;
        }

        const sanitizedEmail = SecurityUtils.sanitizeInput(email);
        
        const sql = `
            SELECT u.*, r.role_name 
            FROM users u 
            JOIN roles r ON u.role_id = r.role_id 
            WHERE u.email = ?
        `;
        const users = await database.query(sql, [sanitizedEmail]);
        return users[0] || null;
    }

    async findUserById(user_id) {
        if (!SecurityUtils.validateUUID(user_id)) {
            return null;
        }

        const sql = `
            SELECT u.*, r.role_name 
            FROM users u 
            JOIN roles r ON u.role_id = r.role_id 
            WHERE u.user_id = ?
        `;
        const users = await database.query(sql, [user_id]);
        return users[0] || null;
    }

    async findUserBySSO(sso_provider, provider_user_id) {
        if (!['google', 'microsoft', 'apple', 'saml', 'oidc'].includes(sso_provider)) {
            return null;
        }

        const sanitizedProviderId = SecurityUtils.sanitizeInput(provider_user_id);
        
        const sql = `
            SELECT u.*, r.role_name, si.sso_identity_id
            FROM users u 
            JOIN roles r ON u.role_id = r.role_id 
            JOIN sso_identities si ON u.user_id = si.user_id
            WHERE si.sso_provider = ? AND si.provider_user_id = ? AND si.is_active = true
        `;
        const users = await database.query(sql, [sso_provider, sanitizedProviderId]);
        return users[0] || null;
    }

    async verifyPassword(plainPassword, hashedPassword) {
        if (!plainPassword || !hashedPassword) {
            // Use constant-time comparison even for invalid inputs
            await bcrypt.compare('dummy_password', '$2b$12$dummyhashfor timingattackprevention');
            return false;
        }

        if (typeof plainPassword !== 'string' || typeof hashedPassword !== 'string') {
            await bcrypt.compare('dummy_password', '$2b$12$dummyhashfor timingattackprevention');
            return false;
        }

        // Additional length check for bcrypt hashes
        if (hashedPassword.length !== 60) {
            await bcrypt.compare('dummy_password', '$2b$12$dummyhashfor timingattackprevention');
            return false;
        }

        return await bcrypt.compare(plainPassword, hashedPassword);
    }

    async updateUserVerification(user_id) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        const sql = `
            UPDATE users 
            SET is_verified = true, updated_at = CURRENT_TIMESTAMP 
            WHERE user_id = ?
        `;
        await database.query(sql, [user_id]);
        
        await UserModel.clearCache(UserModel.CACHE_KEYS.USERS_TABLE);
    }

    async updatePassword(user_id, newPassword) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        if (!this.validatePasswordStrength(newPassword)) {
            throw new Error('Password does not meet security requirements');
        }

        const password_hash = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_ROUNDS) || 12);
        const sql = `
            UPDATE users 
            SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP, 
                updated_at = CURRENT_TIMESTAMP, failed_login_attempts = 0, is_locked = false 
            WHERE user_id = ?
        `;
        await database.query(sql, [password_hash, user_id]);

        await this.addPasswordHistory(user_id, password_hash);
        
        await UserModel.clearCache(UserModel.CACHE_KEYS.USERS_TABLE);
    }

    async addPasswordHistory(user_id, password_hash, changed_by = null) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        if (changed_by && !SecurityUtils.validateUUID(changed_by)) {
            throw new Error('Invalid changed_by user ID format');
        }

        const password_id = uuidv4();
        const sql = `
            INSERT INTO password_history (password_id, user_id, password_hash, changed_by)
            VALUES (?, ?, ?, ?)
        `;
        await database.query(sql, [password_id, user_id, password_hash, changed_by]);
    }

    async recordLoginAttempt(loginData) {
        const sanitizedData = UserModel.sanitizeUserInput(loginData);
        
        const {
            email,
            ip_address,
            user_agent,
            attempt_result,
            user_id = null,
            session_id = null,
            device_id = null,
            auth_method = 'password',
            sso_provider = null,
            recaptcha_challenge_id = null,
            recaptcha_score = null,
            country_code = null,
            city = null,
            risk_score = 0,
            is_suspicious = false,
            suspicious_reasons = null
        } = sanitizedData;

        if (ip_address && !SecurityUtils.validateIP(ip_address)) {
            throw new Error('Invalid IP address format');
        }

        if (user_id && !SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }
        if (session_id && !SecurityUtils.validateUUID(session_id)) {
            throw new Error('Invalid session ID format');
        }
        if (device_id && !SecurityUtils.validateUUID(device_id)) {
            throw new Error('Invalid device ID format');
        }
        if (recaptcha_challenge_id && !SecurityUtils.validateUUID(recaptcha_challenge_id)) {
            throw new Error('Invalid recaptcha challenge ID format');
        }

        const sql = `
            INSERT INTO login_attempts (
                email, ip_address, user_agent, attempt_result, 
                user_id, session_id, device_id, auth_method, sso_provider,
                recaptcha_challenge_id, recaptcha_score, country_code, city,
                risk_score, is_suspicious, suspicious_reasons
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        await database.query(sql, [
            email, ip_address, user_agent, attempt_result,
            user_id, session_id, device_id, auth_method, sso_provider,
            recaptcha_challenge_id, recaptcha_score, country_code, city,
            risk_score, is_suspicious, suspicious_reasons ? JSON.stringify(suspicious_reasons) : null
        ]);

        // Clear relevant caches
        await UserModel.clearCache(UserModel.CACHE_KEYS.LOGIN_ATTEMPTS_TABLE);
        await UserModel.clearCache(UserModel.CACHE_KEYS.ADMIN_DASHBOARD);
    }

    async handleFailedLogin(user_id, ip_address = null) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        if (ip_address && !SecurityUtils.validateIP(ip_address)) {
            throw new Error('Invalid IP address format');
        }

        const sql = `
            UPDATE users 
            SET failed_login_attempts = failed_login_attempts + 1, 
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        `;
        await database.query(sql, [user_id]);

        const user = await this.findUserById(user_id);
        const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
        
        if (user && user.failed_login_attempts >= maxAttempts) {
            await this.lockUserAccount(user_id, ip_address);
        }
        
        await UserModel.clearCache(UserModel.CACHE_KEYS.USERS_TABLE);
    }

    async lockUserAccount(user_id, ip_address = null) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        const lockoutMinutes = parseInt(process.env.LOCKOUT_TIME_MINUTES) || 30;
        const lock_until = new Date(Date.now() + lockoutMinutes * 60 * 1000);
        
        const sql = `
            UPDATE users 
            SET is_locked = true, lock_until = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE user_id = ?
        `;
        await database.query(sql, [lock_until, user_id]);

        await this.logSecurityEvent(
            user_id, 
            null, 
            'account_lockout', 
            `Account locked due to multiple failed login attempts from IP: ${ip_address}`,
            'high',
            ip_address
        );

        await UserModel.clearCache(UserModel.CACHE_KEYS.USERS_TABLE);
        await UserModel.clearCache(UserModel.CACHE_KEYS.SECURITY_EVENTS_TABLE);
    }

    async unlockUserAccount(user_id, admin_user_id = null) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        if (admin_user_id && !SecurityUtils.validateUUID(admin_user_id)) {
            throw new Error('Invalid admin user ID format');
        }

        const sql = `
            UPDATE users 
            SET is_locked = false, lock_until = NULL, failed_login_attempts = 0,
                updated_at = CURRENT_TIMESTAMP 
            WHERE user_id = ?
        `;
        await database.query(sql, [user_id]);

        await this.logSecurityEvent(
            admin_user_id || user_id, 
            null, 
            'account_unlock', 
            `User account unlocked${admin_user_id ? ' by admin' : ''}`,
            'medium'
        );

        await UserModel.clearCache(UserModel.CACHE_KEYS.USERS_TABLE);
        await UserModel.clearCache(UserModel.CACHE_KEYS.SECURITY_EVENTS_TABLE);
    }

    async resetFailedAttempts(user_id, ip_address = null) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        if (ip_address && !SecurityUtils.validateIP(ip_address)) {
            throw new Error('Invalid IP address format');
        }

        const sql = `
            UPDATE users 
            SET failed_login_attempts = 0, is_locked = false, lock_until = NULL, 
                last_login_at = CURRENT_TIMESTAMP, last_login_ip = ?,
                updated_at = CURRENT_TIMESTAMP 
            WHERE user_id = ?
        `;
        await database.query(sql, [ip_address, user_id]);
        
        await UserModel.clearCache(UserModel.CACHE_KEYS.USERS_TABLE);
    }

    async isAccountLocked(user_id) {
        if (!SecurityUtils.validateUUID(user_id)) {
            return true;
        }

        const user = await this.findUserById(user_id);
        if (!user) return true;

        if (user.is_locked && user.lock_until && new Date(user.lock_until) > new Date()) {
            return true;
        }

        if (user.is_locked && (!user.lock_until || new Date(user.lock_until) <= new Date())) {
            await this.unlockUserAccount(user_id);
            return false;
        }

        return false;
    }

    async updateLastLogin(user_id, ip_address) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        if (ip_address && !SecurityUtils.validateIP(ip_address)) {
            throw new Error('Invalid IP address format');
        }

        const sql = `
            UPDATE users 
            SET last_login_at = CURRENT_TIMESTAMP, last_login_ip = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        `;
        await database.query(sql, [ip_address, user_id]);
        
        await UserModel.clearCache(UserModel.CACHE_KEYS.USERS_TABLE);
    }

    async getRoles() {
        const sql = `SELECT role_id, role_name, role_description FROM roles ORDER BY role_id`;
        return await database.query(sql);
    }

    validatePasswordStrength(password) {
        if (typeof password !== 'string') {
            return false;
        }
        return UserModel.passwordRegex.test(password);
    }

    // =============================================
    // SECURITY & ACTIVITY LOGGING
    // =============================================

    async logSecurityEvent(user_id, session_id, event_type, event_description, severity = 'medium', ip_address = null, user_agent = null, affected_user_id = null, metadata = null) {
        if (user_id && !SecurityUtils.validateUUID(user_id)) {
            user_id = null;
        }
        if (session_id && !SecurityUtils.validateUUID(session_id)) {
            session_id = null;
        }
        if (affected_user_id && !SecurityUtils.validateUUID(affected_user_id)) {
            affected_user_id = null;
        }

        if (ip_address && !SecurityUtils.validateIP(ip_address)) {
            ip_address = null;
        }

        const event_id = uuidv4();
        const sql = `
            INSERT INTO security_events (
                event_id, user_id, session_id, event_type, event_description,
                severity, ip_address, user_agent, affected_user_id, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        await database.query(sql, [
            event_id, user_id, session_id, event_type, event_description,
            severity, ip_address, user_agent, affected_user_id, metadata ? JSON.stringify(metadata) : null
        ]);

        // Clear relevant caches
        await UserModel.clearCache(UserModel.CACHE_KEYS.SECURITY_EVENTS_TABLE);
        await UserModel.clearCache(UserModel.CACHE_KEYS.ADMIN_DASHBOARD);
    }

    async logUserActivity(user_id, session_id, device_id, activity_type, activity_description, ip_address, user_agent, endpoint = null, http_method = null, http_status = null, accessed_resource = null, resource_id = null, policy_related = false, policy_id = null) {
        if (user_id && !SecurityUtils.validateUUID(user_id)) {
            return;
        }
        if (session_id && !SecurityUtils.validateUUID(session_id)) {
            session_id = null;
        }
        if (device_id && !SecurityUtils.validateUUID(device_id)) {
            device_id = null;
        }
        if (policy_id && !SecurityUtils.validateUUID(policy_id)) {
            policy_id = null;
        }

        if (ip_address && !SecurityUtils.validateIP(ip_address)) {
            ip_address = null;
        }

        const activity_id = uuidv4();
        const sql = `
            INSERT INTO user_activity_log (
                activity_id, user_id, session_id, device_id, activity_type,
                activity_description, endpoint, http_method, http_status,
                accessed_resource, resource_id, policy_related, policy_id,
                ip_address, user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        await database.query(sql, [
            activity_id, user_id, session_id, device_id, activity_type,
            activity_description, endpoint, http_method, http_status,
            accessed_resource, resource_id, policy_related, policy_id,
            ip_address, user_agent
        ]);

        // Clear relevant caches
        await UserModel.clearCache(UserModel.CACHE_KEYS.ADMIN_DASHBOARD);
    }

    async logAdminDeviceAction(admin_user_id, target_user_id, device_id, action_type, action_description, reason = null, new_restrictions = null) {
        if (!SecurityUtils.validateUUID(admin_user_id)) {
            throw new Error('Invalid admin user ID format');
        }
        if (!SecurityUtils.validateUUID(target_user_id)) {
            throw new Error('Invalid target user ID format');
        }
        if (!SecurityUtils.validateUUID(device_id)) {
            throw new Error('Invalid device ID format');
        }

        const action_id = uuidv4();
        const sql = `
            INSERT INTO admin_device_actions (
                action_id, admin_user_id, target_user_id, device_id, action_type,
                action_description, reason, new_allowed_ips, new_allowed_ip_ranges,
                new_require_hospital_network, new_valid_until
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        await database.query(sql, [
            action_id, admin_user_id, target_user_id, device_id, action_type,
            action_description, reason,
            new_restrictions ? JSON.stringify(new_restrictions.allowed_ips) : null,
            new_restrictions ? JSON.stringify(new_restrictions.allowed_ip_ranges) : null,
            new_restrictions ? new_restrictions.require_hospital_network : null,
            new_restrictions ? new_restrictions.valid_until : null
        ]);

        // Clear relevant caches
        await UserModel.clearCache(UserModel.CACHE_KEYS.DEVICES_TABLE);
        await UserModel.clearCache(UserModel.CACHE_KEYS.SECURITY_EVENTS_TABLE);
    }

    // =============================================
    // POLICY MANAGEMENT
    // =============================================

    async getActivePolicies() {
        const sql = `
            SELECT * FROM hospital_policies 
            WHERE is_active = true 
            ORDER BY policy_type, effective_date DESC
        `;
        return await database.query(sql);
    }

    async acceptPolicies(user_id, session_id, ip_address, user_agent) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        if (session_id && !SecurityUtils.validateUUID(session_id)) {
            throw new Error('Invalid session ID format');
        }

        if (ip_address && !SecurityUtils.validateIP(ip_address)) {
            throw new Error('Invalid IP address format');
        }

        const sql = `CALL AcceptPolicies(?, ?, ?, ?)`;
        await database.query(sql, [user_id, session_id, ip_address, user_agent]);
        
        await UserModel.clearCache(UserModel.CACHE_KEYS.USERS_TABLE);
        await UserModel.clearCache(UserModel.CACHE_KEYS.SESSIONS_TABLE);
    }

    async getUserPolicyCompliance(user_id) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        const sql = `
            SELECT * FROM policy_compliance WHERE user_id = ?
        `;
        return await database.query(sql, [user_id]);
    }

    // =============================================
    // TWO-FACTOR AUTHENTICATION
    // =============================================

    async setup2FA(user_id, twoFAData) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        const { is_email_2fa_enabled = false, is_totp_enabled = false, is_sms_2fa_enabled = false, totp_secret = null, totp_backup_codes = null, require_2fa_for_login = false } = twoFAData;
        
        const two_fa_id = uuidv4();
        const sql = `
            INSERT INTO two_factor_auth (
                two_fa_id, user_id, is_email_2fa_enabled, is_totp_enabled,
                is_sms_2fa_enabled, totp_secret, totp_backup_codes, require_2fa_for_login
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                is_email_2fa_enabled = VALUES(is_email_2fa_enabled),
                is_totp_enabled = VALUES(is_totp_enabled),
                is_sms_2fa_enabled = VALUES(is_sms_2fa_enabled),
                totp_secret = VALUES(totp_secret),
                totp_backup_codes = VALUES(totp_backup_codes),
                require_2fa_for_login = VALUES(require_2fa_for_login),
                updated_at = CURRENT_TIMESTAMP
        `;
        
        await database.query(sql, [
            two_fa_id, user_id, is_email_2fa_enabled, is_totp_enabled,
            is_sms_2fa_enabled, totp_secret, totp_backup_codes ? JSON.stringify(totp_backup_codes) : null, require_2fa_for_login
        ]);

        await this.logSecurityEvent(
            user_id,
            null,
            '2fa_method_changed',
            'Two-factor authentication settings updated',
            'medium'
        );

        await UserModel.clearCache(UserModel.CACHE_KEYS.USERS_TABLE);
    }

    async get2FASettings(user_id) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        const sql = `SELECT * FROM two_factor_auth WHERE user_id = ?`;
        const settings = await database.query(sql, [user_id]);
        return settings[0] || null;
    }

    // =============================================
    // DEVICE MANAGEMENT
    // =============================================

    async authorizeDevice(deviceData) {
        const { user_id, device_name, device_fingerprint, device_type, mac_address = null, operating_system = null, browser_family = null, authorized_by = null, allowed_ips = null, allowed_ip_ranges = null, require_hospital_network = true, valid_until = null, max_usage_count = null } = deviceData;

        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }
        if (authorized_by && !SecurityUtils.validateUUID(authorized_by)) {
            throw new Error('Invalid authorized_by user ID format');
        }

        const device_id = uuidv4();
        const sql = `
            INSERT INTO authorized_devices (
                device_id, user_id, device_name, device_fingerprint, device_type,
                mac_address, operating_system, browser_family, authorized_by,
                allowed_ips, allowed_ip_ranges, require_hospital_network,
                valid_until, max_usage_count, is_authorized
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        await database.query(sql, [
            device_id, user_id, device_name, device_fingerprint, device_type,
            mac_address, operating_system, browser_family, authorized_by,
            allowed_ips ? JSON.stringify(allowed_ips) : null, 
            allowed_ip_ranges ? JSON.stringify(allowed_ip_ranges) : null, 
            require_hospital_network,
            valid_until, max_usage_count, authorized_by ? true : false
        ]);

        await this.logSecurityEvent(
            authorized_by || user_id,
            null,
            'device_authorized',
            `Device authorized: ${device_name} (${device_type}) for user`,
            'medium',
            null,
            null,
            user_id
        );

        await UserModel.clearCache(UserModel.CACHE_KEYS.DEVICES_TABLE);
        await UserModel.clearCache(UserModel.CACHE_KEYS.ADMIN_DASHBOARD);

        return device_id;
    }

    async checkDeviceAuthorization(user_id, device_fingerprint, ip_address) {
        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }

        if (ip_address && !SecurityUtils.validateIP(ip_address)) {
            throw new Error('Invalid IP address format');
        }

        const sql = `CALL CheckDeviceAuthorization(?, ?, ?)`;
        const results = await database.query(sql, [user_id, device_fingerprint, ip_address]);
        return results[0] || null;
    }

    // =============================================
    // ADMIN MANAGEMENT FUNCTIONS
    // =============================================

    async createUserByAdmin(userData, admin_user_id, csrfToken = null) {
        // Use CSRF protection
        const { validateCSRFToken } = require('../config/csrf');
        if (csrfToken && !validateCSRFToken(admin_user_id, csrfToken)) {
            throw new Error('Invalid CSRF token');
        }

        if (!SecurityUtils.validateUUID(admin_user_id)) {
            throw new Error('Invalid admin user ID format');
        }

        // Verify admin role
        const admin = await this.findUserById(admin_user_id);
        if (!admin || admin.role_id !== UserModel.ROLES.ADMIN) {
            throw new Error('Access denied: Admin privileges required');
        }

        const sanitizedData = UserModel.sanitizeUserInput(userData);
        
        const {
            email,
            password,
            role_id,
            employee_id = null,
            is_active = true,
            is_verified = false
        } = sanitizedData;

        if (!email || !role_id) {
            throw new Error('Email and role_id are required');
        }

        if (!SecurityUtils.validateEmail(email)) {
            throw new Error('Invalid email format');
        }

        // Prevent admin role creation - NO ADMIN CAN CREATE ANOTHER ADMIN
        const roleIdNum = parseInt(role_id);
        if (roleIdNum === UserModel.ROLES.ADMIN) {
            throw new Error('Cannot create admin users. Admin creation is restricted.');
        }

        if (roleIdNum < 1 || roleIdNum > 5) {
            throw new Error('Invalid role ID');
        }

        if (password && !this.validatePasswordStrength(password)) {
            throw new Error('Password does not meet security requirements');
        }

        const user_id = uuidv4();
        const password_hash = password ? await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS) || 12) : null;

        const sql = `
            INSERT INTO users (
                user_id, email, password_hash, 
                role_id, employee_id, is_active, is_verified, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;

        try {
            await database.query(sql, [
                user_id, email, password_hash,
                role_id, employee_id, is_active, is_verified, admin_user_id
            ]);

            await this.logSecurityEvent(
                admin_user_id,
                null,
                'user_created',
                `Admin created user: ${email} with role: ${role_id}`,
                'medium',
                null,
                null,
                user_id
            );

            // Clear caches
            await UserModel.clearCache(UserModel.CACHE_KEYS.USERS_TABLE);
            await UserModel.clearCache(UserModel.CACHE_KEYS.ADMIN_DASHBOARD);

            return user_id;
        } catch (error) {
            if (error.code === 'ER_DUP_ENTRY') {
                throw new Error('Email already exists');
            }
            throw error;
        }
    }

    async updateUserByAdmin(user_id, updateData, admin_user_id, csrfToken = null) {
        // Use CSRF protection
        const { validateCSRFToken } = require('../config/csrf');
        if (csrfToken && !validateCSRFToken(admin_user_id, csrfToken)) {
            throw new Error('Invalid CSRF token');
        }

        if (!SecurityUtils.validateUUID(user_id)) {
            throw new Error('Invalid user ID format');
        }
        if (!SecurityUtils.validateUUID(admin_user_id)) {
            throw new Error('Invalid admin user ID format');
        }

        // Verify admin role
        const admin = await this.findUserById(admin_user_id);
        if (!admin || admin.role_id !== UserModel.ROLES.ADMIN) {
            throw new Error('Access denied: Admin privileges required');
        }

        const sanitizedData = UserModel.sanitizeUserInput(updateData);
        
        const {
            email,
            role_id,
            employee_id,
            is_active,
            is_locked,
            is_verified,
            failed_login_attempts
        } = sanitizedData;

        const currentUser = await this.findUserById(user_id);
        if (!currentUser) {
            throw new Error('User not found');
        }

        // Prevent changing role to admin
        if (role_id && parseInt(role_id) === UserModel.ROLES.ADMIN) {
            throw new Error('Cannot assign admin role. Admin role assignment is restricted.');
        }

        if (email && !SecurityUtils.validateEmail(email)) {
            throw new Error('Invalid email format');
        }

        if (role_id) {
            const roleIdNum = parseInt(role_id);
            if (roleIdNum < 1 || roleIdNum > 5) {
                throw new Error('Invalid role ID');
            }
        }

        const sql = `
            UPDATE users 
            SET email = ?, role_id = ?, 
                employee_id = ?, is_active = ?, is_locked = ?, is_verified = ?, 
                failed_login_attempts = ?, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        `;

        await database.query(sql, [
            email || currentUser.email,
            role_id || currentUser.role_id,
            employee_id !== undefined ? employee_id : currentUser.employee_id,
            is_active !== undefined ? is_active : currentUser.is_active,
            is_locked !== undefined ? is_locked : currentUser.is_locked,
            is_verified !== undefined ? is_verified : currentUser.is_verified,
            failed_login_attempts !== undefined ? failed_login_attempts : currentUser.failed_login_attempts,
            user_id
        ]);

        // Log changes
        const changes = this.getObjectChanges(currentUser, {
            email, role_id, employee_id, 
            is_active, is_locked, is_verified, failed_login_attempts
        });
        if (changes.length > 0) {
            await this.logSecurityEvent(
                admin_user_id,
                null,
                'user_updated',
                `Admin updated user ${currentUser.email}: ${changes.join(', ')}`,
                'medium',
                null,
                null,
                user_id
            );
        }

        // Clear caches
        await UserModel.clearCache(UserModel.CACHE_KEYS.USERS_TABLE);
        await UserModel.clearCache(UserModel.CACHE_KEYS.ADMIN_DASHBOARD);

        return true;
    }

    async getAllUsersWithFilters(filters = {}) {
        const allowedFilters = ['page', 'limit', 'role_id', 'role_name', 'is_active', 'is_locked', 'is_verified', 'is_sso_user', 'search', 'date_from', 'date_to', 'last_login_from', 'last_login_to', 'sort_by', 'sort_order'];
        const validatedFilters = UserModel.validateQueryParams(filters, allowedFilters);
        
        const {
            page = 1,
            limit = 50,
            role_id = null,
            role_name = null,
            is_active = null,
            is_locked = null,
            is_verified = null,
            is_sso_user = null,
            search = null,
            date_from = null,
            date_to = null,
            last_login_from = null,
            last_login_to = null,
            sort_by = 'created_at',
            sort_order = 'DESC'
        } = validatedFilters;

        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(Math.max(1, parseInt(limit)), 1000);

        let whereConditions = ['1=1'];
        let params = [];

        if (role_id) {
            const roleIdNum = parseInt(role_id);
            if (roleIdNum >= 1 && roleIdNum <= 5) {
                whereConditions.push('u.role_id = ?');
                params.push(roleIdNum);
            }
        }
        if (role_name) {
            const allowedRoles = ['admin', 'doctor', 'nurse', 'receptionist', 'patient'];
            if (allowedRoles.includes(role_name)) {
                whereConditions.push('r.role_name = ?');
                params.push(role_name);
            }
        }

        if (is_active !== null) {
            whereConditions.push('u.is_active = ?');
            params.push(is_active === 'true' || is_active === true);
        }
        if (is_locked !== null) {
            whereConditions.push('u.is_locked = ?');
            params.push(is_locked === 'true' || is_locked === true);
        }
        if (is_verified !== null) {
            whereConditions.push('u.is_verified = ?');
            params.push(is_verified === 'true' || is_verified === true);
        }
        if (is_sso_user !== null) {
            whereConditions.push('u.is_sso_user = ?');
            params.push(is_sso_user === 'true' || is_sso_user === true);
        }

        if (search && search.length <= 100) {
            whereConditions.push('(u.email LIKE ? OR u.employee_id LIKE ? OR r.role_name LIKE ?)');
            const searchTerm = `%${search}%`;
            params.push(searchTerm, searchTerm, searchTerm);
        }

        if (date_from) {
            whereConditions.push('u.created_at >= ?');
            params.push(date_from);
        }
        if (date_to) {
            whereConditions.push('u.created_at <= ?');
            params.push(date_to);
        }
        if (last_login_from) {
            whereConditions.push('u.last_login_at >= ?');
            params.push(last_login_from);
        }
        if (last_login_to) {
            whereConditions.push('u.last_login_at <= ?');
            params.push(last_login_to);
        }

        const whereClause = whereConditions.join(' AND ');
        const offset = (pageNum - 1) * limitNum;

        const allowedSortColumns = ['email', 'role_name', 'created_at', 'last_login_at', 'is_active', 'is_locked'];
        const safeSortBy = allowedSortColumns.includes(sort_by) ? sort_by : 'created_at';
        const safeSortOrder = sort_order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

        const sql = `
            SELECT 
                u.user_id,
                u.email,
                u.role_id,
                r.role_name,
                u.is_active,
                u.is_locked,
                u.is_verified,
                u.is_sso_user,
                u.sso_provider,
                u.failed_login_attempts,
                u.lock_until,
                u.last_login_at,
                u.last_login_ip,
                u.employee_id,
                u.created_at,
                u.updated_at,
                (SELECT COUNT(*) FROM user_sessions us WHERE us.user_id = u.user_id AND us.is_active = true) as active_sessions_count,
                (SELECT COUNT(*) FROM authorized_devices ad WHERE ad.user_id = u.user_id AND ad.is_authorized = true) as authorized_devices_count,
                (SELECT COUNT(*) FROM policy_acceptances pa WHERE pa.user_id = u.user_id) as policies_accepted_count,
                (SELECT COUNT(*) FROM sso_identities si WHERE si.user_id = u.user_id AND si.is_active = true) as sso_identities_count,
                (SELECT MAX(attempted_at) FROM login_attempts la WHERE la.user_id = u.user_id AND la.attempt_result = 'success') as last_successful_login
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            WHERE ${whereClause}
            ORDER BY ${safeSortBy} ${safeSortOrder}
            LIMIT ? OFFSET ?
        `;

        const countSql = `
            SELECT COUNT(*) as total
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            WHERE ${whereClause}
        `;

        const [users, countResult] = await Promise.all([
            database.query(sql, [...params, limitNum, offset]),
            database.query(countSql, params)
        ]);

        return {
            users,
            total: countResult[0]?.total || 0,
            page: pageNum,
            limit: limitNum,
            totalPages: Math.ceil((countResult[0]?.total || 0) / limitNum)
        };
    }

    // =============================================
    // HELPER METHODS
    // =============================================

    async getDeviceById(device_id) {
        if (!SecurityUtils.validateUUID(device_id)) {
            return null;
        }

        const sql = `SELECT * FROM authorized_devices WHERE device_id = ?`;
        const devices = await database.query(sql, [device_id]);
        return devices[0] || null;
    }

    async getDeviceUserId(device_id) {
        if (!SecurityUtils.validateUUID(device_id)) {
            return null;
        }

        const device = await this.getDeviceById(device_id);
        return device ? device.user_id : null;
    }

    getObjectChanges(oldObj, newObj) {
        const changes = [];
        for (const key in newObj) {
            if (oldObj[key] !== newObj[key] && newObj[key] !== undefined) {
                changes.push(`${key}: ${oldObj[key]} → ${newObj[key]}`);
            }
        }
        return changes;
    }

    // =============================================
    // DATA CLEANUP
    // =============================================

    async cleanupExpiredData() {
        const sql = `CALL CleanupExpiredData()`;
        await database.query(sql);
        
        // Clear all caches after cleanup
        await UserModel.clearCache();
    }

    // =============================================
    // EXPORT FUNCTIONS
    // =============================================

    async exportUsersToExcel(filters = {}, admin_user_id) {
        if (!SecurityUtils.validateUUID(admin_user_id)) {
            throw new Error('Invalid admin user ID');
        }

        const admin = await this.findUserById(admin_user_id);
        if (!admin || admin.role_id !== UserModel.ROLES.ADMIN) {
            throw new Error('Access denied: Admin privileges required');
        }

        const { users } = await this.getAllUsersWithFilters({ ...filters, limit: 10000 });
        
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Users');

        worksheet.columns = [
            { header: 'User ID', key: 'user_id', width: 36 },
            { header: 'Email', key: 'email', width: 30 },
            { header: 'Role', key: 'role_name', width: 15 },
            { header: 'Active', key: 'is_active', width: 10 },
            { header: 'Locked', key: 'is_locked', width: 10 },
            { header: 'Verified', key: 'is_verified', width: 10 },
            { header: 'SSO User', key: 'is_sso_user', width: 10 },
            { header: 'Failed Attempts', key: 'failed_login_attempts', width: 15 },
            { header: 'Last Login', key: 'last_login_at', width: 20 },
            { header: 'Last IP', key: 'last_login_ip', width: 15 },
            { header: 'Employee ID', key: 'employee_id', width: 15 },
            { header: 'Created At', key: 'created_at', width: 20 },
            { header: 'Active Sessions', key: 'active_sessions_count', width: 15 },
            { header: 'Authorized Devices', key: 'authorized_devices_count', width: 18 }
        ];

        worksheet.addRows(users);

        worksheet.getRow(1).font = { bold: true };
        worksheet.getRow(1).fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FFE6E6FA' }
        };

        worksheet.addRow([]);
        worksheet.addRow(['Summary', '']);
        worksheet.addRow(['Total Users', users.length]);
        worksheet.addRow(['Active Users', users.filter(u => u.is_active).length]);
        worksheet.addRow(['Locked Users', users.filter(u => u.is_locked).length]);
        worksheet.addRow(['SSO Users', users.filter(u => u.is_sso_user).length]);

        return workbook;
    }

    // =============================================
    // REAL-TIME DATA REFRESH
    // =============================================

    async refreshRealTimeData(admin_user_id) {
        if (!SecurityUtils.validateUUID(admin_user_id)) {
            throw new Error('Invalid admin user ID');
        }

        const admin = await this.findUserById(admin_user_id);
        if (!admin || admin.role_id !== UserModel.ROLES.ADMIN) {
            throw new Error('Access denied: Admin privileges required');
        }

        // Clear all caches to force fresh data
        await UserModel.clearCache();

        return {
            success: true,
            message: 'Real-time data refreshed successfully',
            timestamp: new Date().toISOString()
        };
    }

    // =============================================
    // ADMIN ROLE VALIDATION
    // =============================================

    async validateAdminRole(user_id) {
        if (!SecurityUtils.validateUUID(user_id)) {
            return false;
        }

        const user = await this.findUserById(user_id);
        return user && user.role_id === UserModel.ROLES.ADMIN;
    }

    async getAdminUsers() {
        const sql = `
            SELECT user_id, email, created_at, last_login_at, last_login_ip
            FROM users 
            WHERE role_id = ? AND is_active = true
            ORDER BY created_at DESC
        `;
        return await database.query(sql, [UserModel.ROLES.ADMIN]);
    }

    // =============================================
    // SOCKET.IO INTEGRATION FOR REAL-TIME UPDATES
    // =============================================

    async emitRealTimeUpdate(socket, event, data, admin_user_id = null) {
        try {
            const socketManager = require('../config/socket');
            if (admin_user_id) {
                // Verify admin role for sensitive data
                const admin = await this.findUserById(admin_user_id);
                if (!admin || admin.role_id !== UserModel.ROLES.ADMIN) {
                    throw new Error('Access denied: Admin privileges required');
                }
            }
            socketManager.emitToRoom('admin_dashboard', event, data);
        } catch (error) {
            console.error('Socket emit error:', error);
        }
    }

    async getRealTimeStatsForSocket(admin_user_id) {
        if (!SecurityUtils.validateUUID(admin_user_id)) {
            return null;
        }

        try {
            const admin = await this.findUserById(admin_user_id);
            if (!admin || admin.role_id !== UserModel.ROLES.ADMIN) {
                return null;
            }

            const [userStats, securityStats] = await Promise.all([
                this.getUserStatistics(),
                this.getSecurityStatistics()
            ]);

            return {
                userStats,
                securityStats,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            console.error('Error getting real-time stats for socket:', error);
            return null;
        }
    }
}

module.exports = new UserModel();