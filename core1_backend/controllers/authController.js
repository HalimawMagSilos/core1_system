const UserModel = require('../models/userModel');
const EmailService = require('../utils/emailService');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { SecurityUtils } = require('../models/userModel');
const { generateToken: generateCSRFToken, validateToken: validateCSRFToken } = require('../config/csrf');
const { generate6DigitToken, hash6DigitToken } = require('../models/userModel');

class AuthController {
    
    // =============================================
    // USER REGISTRATION
    // =============================================

    async register(req, res) {
        try {
            const { email, password, role_id = UserModel.ROLES.PATIENT, employee_id } = req.body;
            const ip_address = req.ip;
            const user_agent = req.get('User-Agent');

            // Validate required fields
            if (!email || !password) {
                return res.status(400).json({
                    error: 'Missing required fields',
                    message: 'Email and password are required'
                });
            }

            // Validate email format
            if (!SecurityUtils.validateEmail(email)) {
                return res.status(400).json({
                    error: 'Invalid email',
                    message: 'Please provide a valid email address'
                });
            }

            // Check if user already exists
            const existingUser = await UserModel.findUserByEmail(email);
            if (existingUser) {
                return res.status(409).json({
                    error: 'User already exists',
                    message: 'An account with this email already exists'
                });
            }

            // Generate CSRF token for registration
            const sessionId = uuidv4(); // Generate temporary session ID for registration
            const csrfToken = await generateCSRFToken('registration', sessionId);

            // Create user with CSRF protection
            const user_id = await UserModel.createUser({
                email,
                password,
                role_id,
                employee_id,
                created_by: null // Self-registration
            }, csrfToken);

            // Generate 6-digit email verification token
            const token = SecurityUtils.generate6DigitToken();
            const token_hash = SecurityUtils.hash6DigitToken(token);
            const expires_at = new Date(Date.now() + parseInt(process.env.TOKEN_EXPIRY_MINUTES) * 60 * 1000);

            await UserModel.createEmailToken(
                user_id, 
                'email_verification', 
                token, 
                token_hash, 
                expires_at, 
                ip_address, 
                user_agent
            );

            // Send verification email
            await EmailService.sendEmailVerification(email, token);

            // Log security event
            await UserModel.logSecurityEvent(
                user_id, 
                null, 
                'registration', 
                'User registered successfully', 
                'low', 
                ip_address, 
                user_agent
            );

            res.status(201).json({
                success: true,
                message: 'Registration successful. Please check your email for verification instructions.',
                user_id: user_id,
                csrf_token: csrfToken // Include CSRF token for subsequent requests
            });

        } catch (error) {
            console.error('Registration error:', error);
            
            if (error.message.includes('already exists')) {
                return res.status(409).json({
                    error: 'Registration failed',
                    message: error.message
                });
            }
            
            if (error.message.includes('security requirements')) {
                return res.status(400).json({
                    error: 'Weak password',
                    message: error.message
                });
            }

            if (error.message.includes('CSRF token')) {
                return res.status(403).json({
                    error: 'Security violation',
                    message: 'Invalid security token'
                });
            }

            res.status(500).json({
                error: 'Registration failed',
                message: 'An error occurred during registration. Please try again.'
            });
        }
    }

    // =============================================
    // PATIENT REGISTRATION (SPECIALIZED)
    // =============================================

    async registerPatient(req, res) {
        try {
            const { email, password } = req.body;
            const ip_address = req.ip;
            const user_agent = req.get('User-Agent');

            // Validate required fields
            if (!email || !password) {
                return res.status(400).json({
                    error: 'Missing required fields',
                    message: 'Email and password are required'
                });
            }

            // Validate email format
            if (!SecurityUtils.validateEmail(email)) {
                return res.status(400).json({
                    error: 'Invalid email',
                    message: 'Please provide a valid email address'
                });
            }

            // Check if user already exists
            const existingUser = await UserModel.findUserByEmail(email);
            if (existingUser) {
                return res.status(409).json({
                    error: 'User already exists',
                    message: 'An account with this email already exists'
                });
            }

            // Generate CSRF token
            const sessionId = uuidv4();
            const csrfToken = await generateCSRFToken('patient_registration', sessionId);

            // Create patient user with CSRF protection
            const user_id = await UserModel.createPatientUser(
                email,
                password,
                ip_address,
                user_agent,
                csrfToken
            );

            // Generate 6-digit email verification token
            const token = SecurityUtils.generate6DigitToken();
            const token_hash = SecurityUtils.hash6DigitToken(token);
            const expires_at = new Date(Date.now() + parseInt(process.env.TOKEN_EXPIRY_MINUTES) * 60 * 1000);

            await UserModel.createEmailToken(
                user_id, 
                'email_verification', 
                token, 
                token_hash, 
                expires_at, 
                ip_address, 
                user_agent
            );

            // Send verification email
            await EmailService.sendEmailVerification(email, token);

            // Log security event
            await UserModel.logSecurityEvent(
                user_id, 
                null, 
                'patient_registration', 
                'Patient registered successfully', 
                'low', 
                ip_address, 
                user_agent
            );

            res.status(201).json({
                success: true,
                message: 'Patient registration successful. Please check your email for verification instructions.',
                user_id: user_id,
                csrf_token: csrfToken
            });

        } catch (error) {
            console.error('Patient registration error:', error);
            
            if (error.message.includes('already exists')) {
                return res.status(409).json({
                    error: 'Registration failed',
                    message: error.message
                });
            }
            
            if (error.message.includes('security requirements')) {
                return res.status(400).json({
                    error: 'Weak password',
                    message: error.message
                });
            }

            if (error.message.includes('CSRF token')) {
                return res.status(403).json({
                    error: 'Security violation',
                    message: 'Invalid security token'
                });
            }

            res.status(500).json({
                error: 'Registration failed',
                message: 'An error occurred during registration. Please try again.'
            });
        }
    }

    // =============================================
    // USER LOGIN
    // =============================================

    async login(req, res) {
        try {
            const { email, password } = req.body;
            const ip_address = req.ip;
            const user_agent = req.get('User-Agent');

            if (!email || !password) {
                return res.status(400).json({
                    error: 'Missing credentials',
                    message: 'Email and password are required'
                });
            }

            // Validate email format
            if (!SecurityUtils.validateEmail(email)) {
                await UserModel.recordLoginAttempt({
                    email,
                    ip_address,
                    user_agent,
                    attempt_result: 'invalid_email_format'
                });
                return res.status(400).json({
                    error: 'Invalid email',
                    message: 'Please provide a valid email address'
                });
            }

            // Find user
            const user = await UserModel.findUserByEmail(email);
            if (!user) {
                await UserModel.recordLoginAttempt({
                    email,
                    ip_address,
                    user_agent,
                    attempt_result: 'user_not_found'
                });
                return res.status(401).json({
                    error: 'Authentication failed',
                    message: 'Invalid email or password'
                });
            }

            // Check if account is locked
            const isLocked = await UserModel.isAccountLocked(user.user_id);
            if (isLocked) {
                await UserModel.recordLoginAttempt({
                    email,
                    ip_address,
                    user_agent,
                    attempt_result: 'account_locked',
                    user_id: user.user_id
                });
                return res.status(423).json({
                    error: 'Account locked',
                    message: 'Your account has been locked due to multiple failed attempts. Please try again later or reset your password.'
                });
            }

            // Check if account is active
            if (!user.is_active) {
                await UserModel.recordLoginAttempt({
                    email,
                    ip_address,
                    user_agent,
                    attempt_result: 'account_inactive',
                    user_id: user.user_id
                });
                return res.status(401).json({
                    error: 'Account deactivated',
                    message: 'Your account has been deactivated. Please contact administrator.'
                });
            }

            // Verify password
            const isPasswordValid = await UserModel.verifyPassword(password, user.password_hash);
            if (!isPasswordValid) {
                await UserModel.handleFailedLogin(user.user_id, ip_address);
                await UserModel.recordLoginAttempt({
                    email,
                    ip_address,
                    user_agent,
                    attempt_result: 'invalid_password',
                    user_id: user.user_id
                });
                
                return res.status(401).json({
                    error: 'Authentication failed',
                    message: 'Invalid email or password'
                });
            }

            // Check if email is verified
            if (!user.is_verified) {
                await UserModel.recordLoginAttempt({
                    email,
                    ip_address,
                    user_agent,
                    attempt_result: 'email_not_verified',
                    user_id: user.user_id
                });
                return res.status(403).json({
                    error: 'Email not verified',
                    message: 'Please verify your email address before logging in'
                });
            }

            // Check if user is SSO-only (no password)
            if (user.is_sso_user && !user.password_hash) {
                await UserModel.recordLoginAttempt({
                    email,
                    ip_address,
                    user_agent,
                    attempt_result: 'sso_required',
                    user_id: user.user_id
                });
                return res.status(403).json({
                    error: 'SSO required',
                    message: 'This account requires Single Sign-On. Please use your SSO provider to login.'
                });
            }

            // Reset failed attempts and update login info
            await UserModel.resetFailedAttempts(user.user_id, ip_address);
            await UserModel.updateLastLogin(user.user_id, ip_address);
            
            await UserModel.recordLoginAttempt({
                email,
                ip_address,
                user_agent,
                attempt_result: 'success',
                user_id: user.user_id,
                auth_method: 'password'
            });

            // Generate session ID for CSRF protection
            const sessionId = uuidv4();

            // Generate JWT token with session ID
            const token = jwt.sign(
                { 
                    userId: user.user_id,
                    email: user.email,
                    role: user.role_name,
                    role_id: user.role_id,
                    sessionId: sessionId
                },
                process.env.JWT_SECRET,
                { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
            );

            // Generate CSRF token for this session
            const csrfToken = await generateCSRFToken(user.user_id, sessionId);

            // Log security event
            await UserModel.logSecurityEvent(
                user.user_id, 
                null, 
                'login_success', 
                'User logged in successfully', 
                'low', 
                ip_address, 
                user_agent
            );

            // Log user activity
            await UserModel.logUserActivity(
                user.user_id,
                null,
                null,
                'login',
                'User logged in successfully',
                ip_address,
                user_agent
            );

            res.json({
                success: true,
                message: 'Login successful',
                token: token,
                csrf_token: csrfToken,
                user: {
                    user_id: user.user_id,
                    email: user.email,
                    role: user.role_name,
                    role_id: user.role_id,
                    is_verified: user.is_verified,
                    is_sso_user: user.is_sso_user,
                    employee_id: user.employee_id
                }
            });

        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({
                error: 'Login failed',
                message: 'An error occurred during login. Please try again.'
            });
        }
    }

    // =============================================
    // SSO LOGIN
    // =============================================

    async ssoLogin(req, res) {
        try {
            const { sso_provider, provider_user_id, email, provider_identity_data } = req.body;
            const ip_address = req.ip;
            const user_agent = req.get('User-Agent');

            if (!sso_provider || !provider_user_id || !email) {
                return res.status(400).json({
                    error: 'Missing SSO data',
                    message: 'SSO provider, provider user ID, and email are required'
                });
            }

            // Validate email format
            if (!SecurityUtils.validateEmail(email)) {
                return res.status(400).json({
                    error: 'Invalid email',
                    message: 'Please provide a valid email address'
                });
            }

            // Validate SSO provider
            if (!['google', 'microsoft', 'apple', 'saml', 'oidc'].includes(sso_provider)) {
                return res.status(400).json({
                    error: 'Invalid SSO provider',
                    message: 'Unsupported SSO provider'
                });
            }

            // Generate CSRF token for SSO process
            const sessionId = uuidv4();
            const csrfToken = await generateCSRFToken('sso_login', sessionId);

            // Check if user exists with this SSO identity
            let user = await UserModel.findUserBySSO(sso_provider, provider_user_id);
            
            if (!user) {
                // Check if user exists with this email but no SSO
                user = await UserModel.findUserByEmail(email);
                
                if (user) {
                    // Link existing user with SSO
                    await UserModel.createSSOIdentity(
                        user.user_id, 
                        sso_provider, 
                        provider_user_id, 
                        email, 
                        provider_identity_data
                    );
                    
                    await UserModel.logSecurityEvent(
                        user.user_id,
                        null,
                        'sso_linked',
                        `SSO provider ${sso_provider} linked to existing account`,
                        'medium',
                        ip_address,
                        user_agent
                    );
                } else {
                    // Create new SSO user with CSRF protection
                    const user_id = await UserModel.createSSOUser({
                        email,
                        sso_provider,
                        provider_user_id,
                        provider_identity_data,
                        role_id: UserModel.ROLES.PATIENT
                    }, csrfToken);

                    user = await UserModel.findUserById(user_id);
                    
                    await UserModel.logSecurityEvent(
                        user_id,
                        null,
                        'sso_registration',
                        `New user registered via SSO ${sso_provider}`,
                        'low',
                        ip_address,
                        user_agent
                    );
                }
            }

            // Check if account is active
            if (!user.is_active) {
                await UserModel.recordLoginAttempt({
                    email,
                    ip_address,
                    user_agent,
                    attempt_result: 'account_inactive',
                    user_id: user.user_id,
                    auth_method: 'sso',
                    sso_provider: sso_provider
                });
                return res.status(401).json({
                    error: 'Account deactivated',
                    message: 'Your account has been deactivated. Please contact administrator.'
                });
            }

            // Update last login and record successful attempt
            await UserModel.resetFailedAttempts(user.user_id, ip_address);
            await UserModel.updateLastLogin(user.user_id, ip_address);
            
            await UserModel.recordLoginAttempt({
                email,
                ip_address,
                user_agent,
                attempt_result: 'success',
                user_id: user.user_id,
                auth_method: 'sso',
                sso_provider: sso_provider
            });

            // Generate session ID for CSRF protection
            const userSessionId = uuidv4();

            // Generate JWT token
            const token = jwt.sign(
                { 
                    userId: user.user_id,
                    email: user.email,
                    role: user.role_name,
                    role_id: user.role_id,
                    sessionId: userSessionId
                },
                process.env.JWT_SECRET,
                { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
            );

            // Generate CSRF token for this session
            const userCsrfToken = await generateCSRFToken(user.user_id, userSessionId);

            // Log security event
            await UserModel.logSecurityEvent(
                user.user_id, 
                null, 
                'sso_login', 
                `User logged in via SSO ${sso_provider}`, 
                'low', 
                ip_address, 
                user_agent
            );

            // Log user activity
            await UserModel.logUserActivity(
                user.user_id,
                null,
                null,
                'sso_login',
                `User logged in via SSO ${sso_provider}`,
                ip_address,
                user_agent
            );

            res.json({
                success: true,
                message: 'SSO login successful',
                token: token,
                csrf_token: userCsrfToken,
                user: {
                    user_id: user.user_id,
                    email: user.email,
                    role: user.role_name,
                    role_id: user.role_id,
                    is_verified: user.is_verified,
                    is_sso_user: user.is_sso_user,
                    sso_provider: sso_provider,
                    employee_id: user.employee_id
                }
            });

        } catch (error) {
            console.error('SSO login error:', error);

            if (error.message.includes('CSRF token')) {
                return res.status(403).json({
                    error: 'Security violation',
                    message: 'Invalid security token'
                });
            }

            res.status(500).json({
                error: 'SSO login failed',
                message: 'An error occurred during SSO login. Please try again.'
            });
        }
    }

    // =============================================
    // EMAIL VERIFICATION
    // =============================================

    async verifyEmail(req, res) {
        try {
            const { token } = req.body;
            const ip_address = req.ip;
            const user_agent = req.get('User-Agent');

            if (!token) {
                return res.status(400).json({
                    error: 'Token required',
                    message: 'Verification token is required'
                });
            }

            // Validate token format (6-digit)
            if (!SecurityUtils.validate6DigitToken(token)) {
                return res.status(400).json({
                    error: 'Invalid token format',
                    message: 'Verification token must be 6 digits'
                });
            }

            // Find valid token
            const tokenData = await UserModel.findEmailToken(token, 'email_verification');
            if (!tokenData) {
                return res.status(400).json({
                    error: 'Invalid token',
                    message: 'The verification token is invalid or has expired'
                });
            }

            // Verify user
            if (tokenData.is_verified) {
                return res.status(400).json({
                    error: 'Already verified',
                    message: 'This email has already been verified'
                });
            }

            // Mark user as verified
            await UserModel.updateUserVerification(tokenData.user_id);

            // Mark token as used
            await UserModel.markTokenUsed(tokenData.token_id);

            // Send welcome email
            await EmailService.sendWelcomeEmail(tokenData.email);

            // Log security event
            await UserModel.logSecurityEvent(
                tokenData.user_id, 
                null, 
                'email_verified', 
                'User verified email address', 
                'low', 
                ip_address, 
                user_agent
            );

            // Log user activity
            await UserModel.logUserActivity(
                tokenData.user_id,
                null,
                null,
                'email_verification',
                'User verified email address',
                ip_address,
                user_agent
            );

            res.json({
                success: true,
                message: 'Email verified successfully. You can now log in to your account.'
            });

        } catch (error) {
            console.error('Email verification error:', error);
            res.status(500).json({
                error: 'Verification failed',
                message: 'An error occurred during email verification. Please try again.'
            });
        }
    }

    // =============================================
    // PASSWORD RESET FLOW
    // =============================================

    async forgotPassword(req, res) {
        try {
            const { email } = req.body;
            const ip_address = req.ip;
            const user_agent = req.get('User-Agent');

            if (!email) {
                return res.status(400).json({
                    error: 'Email required',
                    message: 'Email address is required'
                });
            }

            // Validate email format
            if (!SecurityUtils.validateEmail(email)) {
                return res.status(400).json({
                    error: 'Invalid email',
                    message: 'Please provide a valid email address'
                });
            }

            // Find user
            const user = await UserModel.findUserByEmail(email);
            if (!user) {
                // Don't reveal if user exists for security
                return res.json({
                    success: true,
                    message: 'If an account with that email exists, a password reset link has been sent.'
                });
            }

            // Check if account is active and verified
            if (!user.is_active || !user.is_verified) {
                return res.json({
                    success: true,
                    message: 'If an account with that email exists, a password reset link has been sent.'
                });
            }

            // Check if user is SSO-only
            if (user.is_sso_user && !user.password_hash) {
                return res.status(400).json({
                    error: 'SSO account',
                    message: 'This account uses Single Sign-On. Please use your SSO provider to login.'
                });
            }

            // Generate 6-digit reset token
            const token = SecurityUtils.generate6DigitToken();
            const token_hash = SecurityUtils.hash6DigitToken(token);
            const expires_at = new Date(Date.now() + parseInt(process.env.TOKEN_EXPIRY_MINUTES) * 60 * 1000);

            await UserModel.createEmailToken(
                user.user_id, 
                'password_reset', 
                token, 
                token_hash, 
                expires_at, 
                ip_address, 
                user_agent
            );

            // Send password reset email
            await EmailService.sendPasswordReset(email, token);

            // Log security event
            await UserModel.logSecurityEvent(
                user.user_id, 
                null, 
                'password_reset_request', 
                'User requested password reset', 
                'medium', 
                ip_address, 
                user_agent
            );

            // Log user activity
            await UserModel.logUserActivity(
                user.user_id,
                null,
                null,
                'password_reset_request',
                'User requested password reset',
                ip_address,
                user_agent
            );

            res.json({
                success: true,
                message: 'If an account with that email exists, a password reset link has been sent.'
            });

        } catch (error) {
            console.error('Forgot password error:', error);
            res.status(500).json({
                error: 'Password reset failed',
                message: 'An error occurred while processing your request. Please try again.'
            });
        }
    }

    async resetPassword(req, res) {
        try {
            const { token, newPassword } = req.body;
            const ip_address = req.ip;
            const user_agent = req.get('User-Agent');

            if (!token || !newPassword) {
                return res.status(400).json({
                    error: 'Missing data',
                    message: 'Token and new password are required'
                });
            }

            // Validate token format (6-digit)
            if (!SecurityUtils.validate6DigitToken(token)) {
                return res.status(400).json({
                    error: 'Invalid token format',
                    message: 'Reset token must be 6 digits'
                });
            }

            // Find valid token
            const tokenData = await UserModel.findEmailToken(token, 'password_reset');
            if (!tokenData) {
                return res.status(400).json({
                    error: 'Invalid token',
                    message: 'The password reset token is invalid or has expired'
                });
            }

            // Update password
            await UserModel.updatePassword(tokenData.user_id, newPassword);

            // Mark token as used
            await UserModel.markTokenUsed(tokenData.token_id);

            // Log security event
            await UserModel.logSecurityEvent(
                tokenData.user_id, 
                null, 
                'password_reset_success', 
                'User reset password successfully', 
                'medium', 
                ip_address, 
                user_agent
            );

            // Log user activity
            await UserModel.logUserActivity(
                tokenData.user_id,
                null,
                null,
                'password_reset',
                'User reset password successfully',
                ip_address,
                user_agent
            );

            res.json({
                success: true,
                message: 'Password reset successfully. You can now log in with your new password.'
            });

        } catch (error) {
            console.error('Password reset error:', error);
            
            if (error.message.includes('security requirements')) {
                return res.status(400).json({
                    error: 'Weak password',
                    message: error.message
                });
            }

            res.status(500).json({
                error: 'Password reset failed',
                message: 'An error occurred while resetting your password. Please try again.'
            });
        }
    }

    // =============================================
    // PASSWORD CHANGE (AUTHENTICATED)
    // =============================================

    async changePassword(req, res) {
        try {
            const { currentPassword, newPassword, csrf_token } = req.body;
            const user_id = req.user.user_id;
            const session_id = req.user.sessionId; // From JWT token
            const ip_address = req.ip;
            const user_agent = req.get('User-Agent');

            if (!currentPassword || !newPassword) {
                return res.status(400).json({
                    error: 'Missing data',
                    message: 'Current password and new password are required'
                });
            }

            // Validate CSRF token
            if (!csrf_token || !validateCSRFToken(user_id, session_id, csrf_token)) {
                return res.status(403).json({
                    error: 'Security violation',
                    message: 'Invalid security token'
                });
            }

            const result = await UserModel.changeUserPassword(
                user_id, 
                currentPassword, 
                newPassword, 
                ip_address, 
                user_agent,
                csrf_token
            );

            // Generate new CSRF token after password change
            const newCsrfToken = await generateCSRFToken(user_id, session_id);

            res.json({
                success: true,
                message: result.message,
                csrf_token: newCsrfToken // Return new CSRF token
            });

        } catch (error) {
            console.error('Change password error:', error);
            
            if (error.message.includes('Current password is incorrect')) {
                return res.status(400).json({
                    error: 'Incorrect password',
                    message: error.message
                });
            }
            
            if (error.message.includes('security requirements') || 
                error.message.includes('cannot be the same')) {
                return res.status(400).json({
                    error: 'Invalid new password',
                    message: error.message
                });
            }

            if (error.message.includes('CSRF token')) {
                return res.status(403).json({
                    error: 'Security violation',
                    message: 'Invalid security token'
                });
            }

            res.status(500).json({
                error: 'Password change failed',
                message: 'An error occurred while changing your password. Please try again.'
            });
        }
    }

    // =============================================
    // PROFILE MANAGEMENT
    // =============================================

    async getProfile(req, res) {
        try {
            const user = await UserModel.findUserById(req.user.user_id);
            if (!user) {
                return res.status(404).json({
                    error: 'User not found',
                    message: 'User profile not found'
                });
            }

            res.json({
                success: true,
                user: {
                    user_id: user.user_id,
                    email: user.email,
                    role: user.role_name,
                    role_id: user.role_id,
                    is_verified: user.is_verified,
                    is_sso_user: user.is_sso_user,
                    sso_provider: user.sso_provider,
                    employee_id: user.employee_id,
                    last_login_at: user.last_login_at,
                    last_login_ip: user.last_login_ip,
                    created_at: user.created_at,
                    updated_at: user.updated_at
                }
            });
        } catch (error) {
            console.error('Get profile error:', error);
            res.status(500).json({
                error: 'Failed to fetch profile',
                message: 'An error occurred while fetching your profile'
            });
        }
    }

    async updateProfile(req, res) {
        try {
            const { email, employee_id, csrf_token } = req.body;
            const user_id = req.user.user_id;
            const session_id = req.user.sessionId;
            const ip_address = req.ip;
            const user_agent = req.get('User-Agent');

            if (!email && !employee_id) {
                return res.status(400).json({
                    error: 'No changes',
                    message: 'No profile changes provided'
                });
            }

            // Validate CSRF token
            if (!csrf_token || !validateCSRFToken(user_id, session_id, csrf_token)) {
                return res.status(403).json({
                    error: 'Security violation',
                    message: 'Invalid security token'
                });
            }

            const currentUser = await UserModel.findUserById(user_id);
            if (!currentUser) {
                return res.status(404).json({
                    error: 'User not found',
                    message: 'User profile not found'
                });
            }

            const updateData = {
                email: email || currentUser.email,
                employee_id: employee_id !== undefined ? employee_id : currentUser.employee_id
            };

            // Update user using admin method but with self-update context
            await UserModel.updateUserByAdmin(
                user_id, 
                updateData, 
                user_id, // Self-update
                csrf_token
            );

            // Generate new CSRF token after profile update
            const newCsrfToken = await generateCSRFToken(user_id, session_id);

            // Log user activity
            await UserModel.logUserActivity(
                user_id,
                null,
                null,
                'profile_update',
                'User updated profile information',
                ip_address,
                user_agent
            );

            res.json({
                success: true,
                message: 'Profile updated successfully',
                csrf_token: newCsrfToken
            });

        } catch (error) {
            console.error('Update profile error:', error);
            
            if (error.message.includes('already exists')) {
                return res.status(409).json({
                    error: 'Email exists',
                    message: 'An account with this email already exists'
                });
            }

            if (error.message.includes('CSRF token')) {
                return res.status(403).json({
                    error: 'Security violation',
                    message: 'Invalid security token'
                });
            }

            res.status(500).json({
                error: 'Profile update failed',
                message: 'An error occurred while updating your profile. Please try again.'
            });
        }
    }

    // =============================================
    // SYSTEM INFORMATION
    // =============================================

    async getRoles(req, res) {
        try {
            const roles = await UserModel.getRoles();
            res.json({
                success: true,
                roles: roles
            });
        } catch (error) {
            console.error('Get roles error:', error);
            res.status(500).json({
                error: 'Failed to fetch roles',
                message: 'An error occurred while fetching roles'
            });
        }
    }

    async getActivePolicies(req, res) {
        try {
            const policies = await UserModel.getActivePolicies();
            res.json({
                success: true,
                policies: policies
            });
        } catch (error) {
            console.error('Get policies error:', error);
            res.status(500).json({
                error: 'Failed to fetch policies',
                message: 'An error occurred while fetching policies'
            });
        }
    }

    async acceptPolicies(req, res) {
        try {
            const user_id = req.user.user_id;
            const session_id = req.user.sessionId;
            const ip_address = req.ip;
            const user_agent = req.get('User-Agent');

            await UserModel.acceptPolicies(user_id, session_id, ip_address, user_agent);

            res.json({
                success: true,
                message: 'Policies accepted successfully'
            });

        } catch (error) {
            console.error('Accept policies error:', error);
            res.status(500).json({
                error: 'Failed to accept policies',
                message: 'An error occurred while accepting policies. Please try again.'
            });
        }
    }

    // =============================================
    // ACCOUNT STATUS & SECURITY
    // =============================================

    async checkAccountStatus(req, res) {
        try {
            const { email } = req.body;
            
            if (!email) {
                return res.status(400).json({
                    error: 'Email required',
                    message: 'Email address is required'
                });
            }

            // Validate email format
            if (!SecurityUtils.validateEmail(email)) {
                return res.status(400).json({
                    error: 'Invalid email',
                    message: 'Please provide a valid email address'
                });
            }

            const user = await UserModel.findUserByEmail(email);
            if (!user) {
                return res.status(404).json({
                    error: 'Account not found',
                    message: 'No account found with this email address'
                });
            }

            const isLocked = await UserModel.isAccountLocked(user.user_id);

            res.json({
                success: true,
                account: {
                    exists: true,
                    is_active: user.is_active,
                    is_verified: user.is_verified,
                    is_locked: isLocked,
                    is_sso_user: user.is_sso_user,
                    failed_login_attempts: user.failed_login_attempts
                }
            });

        } catch (error) {
            console.error('Check account status error:', error);
            res.status(500).json({
                error: 'Failed to check account status',
                message: 'An error occurred while checking account status'
            });
        }
    }

    async resendVerification(req, res) {
        try {
            const { email } = req.body;
            const ip_address = req.ip;
            const user_agent = req.get('User-Agent');

            if (!email) {
                return res.status(400).json({
                    error: 'Email required',
                    message: 'Email address is required'
                });
            }

            // Validate email format
            if (!SecurityUtils.validateEmail(email)) {
                return res.status(400).json({
                    error: 'Invalid email',
                    message: 'Please provide a valid email address'
                });
            }

            const user = await UserModel.findUserByEmail(email);
            if (!user) {
                return res.status(404).json({
                    error: 'Account not found',
                    message: 'No account found with this email address'
                });
            }

            if (user.is_verified) {
                return res.status(400).json({
                    error: 'Already verified',
                    message: 'This email address is already verified'
                });
            }

            // Generate new 6-digit verification token
            const token = SecurityUtils.generate6DigitToken();
            const token_hash = SecurityUtils.hash6DigitToken(token);
            const expires_at = new Date(Date.now() + parseInt(process.env.TOKEN_EXPIRY_MINUTES) * 60 * 1000);

            await UserModel.createEmailToken(
                user.user_id, 
                'email_verification', 
                token, 
                token_hash, 
                expires_at, 
                ip_address, 
                user_agent
            );

            // Send verification email
            await EmailService.sendEmailVerification(email, token);

            // Log security event
            await UserModel.logSecurityEvent(
                user.user_id, 
                null, 
                'verification_resent', 
                'User requested verification email resend', 
                'low', 
                ip_address, 
                user_agent
            );

            res.json({
                success: true,
                message: 'Verification email sent successfully. Please check your inbox.'
            });

        } catch (error) {
            console.error('Resend verification error:', error);
            res.status(500).json({
                error: 'Failed to resend verification',
                message: 'An error occurred while resending verification email. Please try again.'
            });
        }
    }

    // =============================================
    // SESSION MANAGEMENT
    // =============================================

    async logout(req, res) {
        try {
            const user_id = req.user.user_id;
            const session_id = req.user.sessionId;
            const ip_address = req.ip;
            const user_agent = req.get('User-Agent');

            // Revoke CSRF tokens for this session
            const { revokeToken } = require('../config/csrf');
            await revokeToken(user_id, session_id);

            // Log security event
            await UserModel.logSecurityEvent(
                user_id, 
                null, 
                'logout', 
                'User logged out successfully', 
                'low', 
                ip_address, 
                user_agent
            );

            // Log user activity
            await UserModel.logUserActivity(
                user_id,
                null,
                null,
                'logout',
                'User logged out successfully',
                ip_address,
                user_agent
            );

            res.json({
                success: true,
                message: 'Logout successful'
            });

        } catch (error) {
            console.error('Logout error:', error);
            res.status(500).json({
                error: 'Logout failed',
                message: 'An error occurred during logout. Please try again.'
            });
        }
    }

    async validateToken(req, res) {
        try {
            // If middleware passed, token is valid
            const user = await UserModel.findUserById(req.user.user_id);
            
            if (!user) {
                return res.status(404).json({
                    error: 'User not found',
                    message: 'User account not found'
                });
            }

            // Generate new CSRF token for the session
            const session_id = req.user.sessionId;
            const csrfToken = await generateCSRFToken(user.user_id, session_id);

            res.json({
                success: true,
                valid: true,
                csrf_token: csrfToken,
                user: {
                    user_id: user.user_id,
                    email: user.email,
                    role: user.role_name,
                    role_id: user.role_id,
                    is_verified: user.is_verified,
                    is_sso_user: user.is_sso_user,
                    employee_id: user.employee_id
                }
            });

        } catch (error) {
            console.error('Token validation error:', error);
            res.status(500).json({
                error: 'Token validation failed',
                message: 'An error occurred while validating token'
            });
        }
    }

    // =============================================
    // PASSWORD STRENGTH VALIDATION
    // =============================================

    async validatePassword(req, res) {
        try {
            const { password } = req.body;

            if (!password) {
                return res.status(400).json({
                    error: 'Password required',
                    message: 'Password is required for validation'
                });
            }

            const validation = await UserModel.validatePasswordRequirements(password);

            res.json({
                success: true,
                validation: validation
            });

        } catch (error) {
            console.error('Password validation error:', error);
            res.status(500).json({
                error: 'Password validation failed',
                message: 'An error occurred while validating password'
            });
        }
    }

    // =============================================
    // ACCOUNT VERIFICATION STATUS
    // =============================================

    async checkVerificationStatus(req, res) {
        try {
            const user = await UserModel.findUserById(req.user.user_id);
            
            if (!user) {
                return res.status(404).json({
                    error: 'User not found',
                    message: 'User account not found'
                });
            }

            res.json({
                success: true,
                is_verified: user.is_verified,
                email: user.email
            });

        } catch (error) {
            console.error('Check verification status error:', error);
            res.status(500).json({
                error: 'Failed to check verification status',
                message: 'An error occurred while checking verification status'
            });
        }
    }

    // =============================================
    // DEVICE AUTHORIZATION CHECK
    // =============================================

    async checkDeviceAuthorization(req, res) {
        try {
            const user_id = req.user.user_id;
            const { device_fingerprint } = req.body;
            const ip_address = req.ip;

            if (!device_fingerprint) {
                return res.status(400).json({
                    error: 'Device fingerprint required',
                    message: 'Device fingerprint is required for authorization check'
                });
            }

            const deviceAuth = await UserModel.checkDeviceAuthorization(
                user_id, 
                device_fingerprint, 
                ip_address
            );

            res.json({
                success: true,
                authorized: deviceAuth ? deviceAuth.is_authorized : false,
                device: deviceAuth
            });

        } catch (error) {
            console.error('Device authorization check error:', error);
            res.status(500).json({
                error: 'Device authorization check failed',
                message: 'An error occurred while checking device authorization'
            });
        }
    }

    // =============================================
    // TWO-FACTOR AUTHENTICATION MANAGEMENT
    // =============================================

    async get2FASettings(req, res) {
        try {
            const user_id = req.user.user_id;
            const settings = await UserModel.get2FASettings(user_id);

            res.json({
                success: true,
                settings: settings || {
                    is_email_2fa_enabled: false,
                    is_totp_enabled: false,
                    is_sms_2fa_enabled: false,
                    require_2fa_for_login: false
                }
            });

        } catch (error) {
            console.error('Get 2FA settings error:', error);
            res.status(500).json({
                error: 'Failed to fetch 2FA settings',
                message: 'An error occurred while fetching 2FA settings'
            });
        }
    }

    async setup2FA(req, res) {
        try {
            const user_id = req.user.user_id;
            const { csrf_token, ...twoFAData } = req.body;
            const session_id = req.user.sessionId;
            const ip_address = req.ip;
            const user_agent = req.get('User-Agent');

            // Validate CSRF token
            if (!csrf_token || !validateCSRFToken(user_id, session_id, csrf_token)) {
                return res.status(403).json({
                    error: 'Security violation',
                    message: 'Invalid security token'
                });
            }

            await UserModel.setup2FA(user_id, twoFAData);

            // Generate new CSRF token after 2FA setup
            const newCsrfToken = await generateCSRFToken(user_id, session_id);

            // Log security event
            await UserModel.logSecurityEvent(
                user_id,
                null,
                '2fa_setup',
                'User configured two-factor authentication',
                'medium',
                ip_address,
                user_agent
            );

            res.json({
                success: true,
                message: 'Two-factor authentication configured successfully',
                csrf_token: newCsrfToken
            });

        } catch (error) {
            console.error('Setup 2FA error:', error);

            if (error.message.includes('CSRF token')) {
                return res.status(403).json({
                    error: 'Security violation',
                    message: 'Invalid security token'
                });
            }

            res.status(500).json({
                error: 'Failed to setup 2FA',
                message: 'An error occurred while setting up two-factor authentication'
            });
        }
    }

    // =============================================
    // REAL-TIME SOCKET INTEGRATION
    // =============================================

    async getSocketToken(req, res) {
        try {
            const user_id = req.user.user_id;
            const session_id = req.user.sessionId;

            // Generate socket authentication token
            const socketToken = jwt.sign(
                {
                    userId: user_id,
                    sessionId: session_id,
                    type: 'socket_auth'
                },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );

            res.json({
                success: true,
                socket_token: socketToken,
                socket_url: process.env.SOCKET_URL || 'http://localhost:3000'
            });

        } catch (error) {
            console.error('Socket token generation error:', error);
            res.status(500).json({
                error: 'Failed to generate socket token',
                message: 'An error occurred while generating socket authentication token'
            });
        }
    }
}

module.exports = new AuthController();