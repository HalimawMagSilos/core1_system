const nodemailer = require('nodemailer');
const fs = require('fs').promises;
const path = require('path');
require('dotenv').config();

class EmailService {
    constructor() {
        this.transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST || 'smtp.gmail.com',
            port: parseInt(process.env.EMAIL_PORT) || 587,
            secure: process.env.EMAIL_SECURE === 'true',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            },
            tls: {
                rejectUnauthorized: process.env.NODE_ENV === 'production'
            },
            pool: true, // Use connection pooling
            maxConnections: 5,
            maxMessages: 100
        });

        this.templates = {};
        this.loadTemplates();
    }

    async loadTemplates() {
        try {
            const templatesDir = path.join(__dirname, 'email-templates');
            try {
                await fs.access(templatesDir);
            } catch {
                // Templates directory doesn't exist, use built-in templates
                console.log('📧 Using built-in email templates');
                return;
            }

            const files = await fs.readdir(templatesDir);
            for (const file of files) {
                if (file.endsWith('.html')) {
                    const templateName = path.basename(file, '.html');
                    const content = await fs.readFile(path.join(templatesDir, file), 'utf8');
                    this.templates[templateName] = content;
                }
            }
            console.log('✅ Email templates loaded successfully');
        } catch (error) {
            console.warn('⚠️ Could not load email templates, using built-in templates:', error.message);
        }
    }

    async verifyConnection() {
        try {
            await this.transporter.verify();
            console.log('✅ Email server connection verified');
            return {
                success: true,
                message: 'Email server connection verified'
            };
        } catch (error) {
            console.error('❌ Email connection failed:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    // =============================================
    // AUTHENTICATION EMAILS (UPDATED FOR 6-DIGIT TOKENS)
    // =============================================

    async sendEmailVerification(userEmail, token, ipAddress = null) {
        // For 6-digit tokens, we don't use links - users enter the code manually
        const expiryMinutes = parseInt(process.env.TOKEN_EXPIRY_MINUTES) || 15;
        
        const templateData = {
            userEmail,
            verificationCode: token, // 6-digit code
            expiryMinutes,
            ipAddress,
            supportEmail: process.env.SUPPORT_EMAIL || 'support@hospital.com',
            currentYear: new Date().getFullYear(),
            verificationInstructions: 'Enter this code in the verification form to complete your registration.'
        };

        const mailOptions = {
            from: `"Hospital Management System" <${process.env.EMAIL_FROM}>`,
            to: userEmail,
            subject: 'Verify Your Email Address - Hospital Management System',
            html: this.renderTemplate('email-verification', templateData) || this.getDefaultVerificationTemplate(templateData),
            text: this.generateTextVersion(`
                Email Verification Request
                
                Hello,
                
                Thank you for registering with our Hospital Management System. 
                Please verify your email address using the following code:
                
                VERIFICATION CODE: ${token}
                
                Enter this code in the verification form to complete your registration.
                
                This verification code will expire in ${expiryMinutes} minutes.
                
                If you didn't create an account, please ignore this email.
                
                Security Information:
                - Email: ${userEmail}
                - IP Address: ${ipAddress || 'Not available'}
                - Request Time: ${new Date().toLocaleString()}
                
                Best regards,
                Hospital Management System Team
            `)
        };

        return await this.sendEmail(mailOptions, 'verification', userEmail);
    }

    async sendPasswordReset(userEmail, token, ipAddress = null) {
        // For 6-digit tokens, users enter the code in the reset form
        const expiryMinutes = parseInt(process.env.TOKEN_EXPIRY_MINUTES) || 15;
        
        const templateData = {
            userEmail,
            resetCode: token, // 6-digit code
            expiryMinutes,
            ipAddress,
            supportEmail: process.env.SUPPORT_EMAIL || 'support@hospital.com',
            currentYear: new Date().getFullYear(),
            resetInstructions: 'Enter this code in the password reset form to create a new password.'
        };

        const mailOptions = {
            from: `"Hospital Management System" <${process.env.EMAIL_FROM}>`,
            to: userEmail,
            subject: 'Password Reset Request - Hospital Management System',
            html: this.renderTemplate('password-reset', templateData) || this.getDefaultPasswordResetTemplate(templateData),
            text: this.generateTextVersion(`
                Password Reset Request
                
                We received a request to reset your password for the Hospital Management System.
                
                RESET CODE: ${token}
                
                Enter this code in the password reset form to create a new password.
                
                This code will expire in ${expiryMinutes} minutes.
                
                Security Information:
                - Email: ${userEmail}
                - IP Address: ${ipAddress || 'Not available'}
                - Request Time: ${new Date().toLocaleString()}
                
                If you didn't request this password reset, please ignore this email and ensure your account is secure.
                
                Best regards,
                Hospital Management System Team
            `)
        };

        return await this.sendEmail(mailOptions, 'password_reset', userEmail);
    }

    async sendWelcomeEmail(userEmail) {
        const loginLink = `${process.env.CLIENT_URL}/login`;
        
        const templateData = {
            userEmail,
            loginLink,
            supportEmail: process.env.SUPPORT_EMAIL || 'support@hospital.com',
            currentYear: new Date().getFullYear()
        };

        const mailOptions = {
            from: `"Hospital Management System" <${process.env.EMAIL_FROM}>`,
            to: userEmail,
            subject: 'Welcome to Hospital Management System',
            html: this.renderTemplate('welcome', templateData) || this.getDefaultWelcomeTemplate(templateData),
            text: this.generateTextVersion(`
                Welcome to Hospital Management System!
                
                Your email has been successfully verified and your account is now active.
                
                You can now log in here: ${loginLink}
                
                If you have any questions or need assistance, please contact our support team.
                
                Best regards,
                Hospital Management System Team
            `)
        };

        return await this.sendEmail(mailOptions, 'welcome', userEmail);
    }

    // =============================================
    // SECURITY & NOTIFICATION EMAILS
    // =============================================

    async sendAccountLockedNotification(userEmail, unlockTime, ipAddress) {
        const templateData = {
            userEmail,
            unlockTime: new Date(unlockTime).toLocaleString(),
            ipAddress,
            supportEmail: process.env.SUPPORT_EMAIL || 'support@hospital.com',
            currentYear: new Date().getFullYear()
        };

        const mailOptions = {
            from: `"Hospital Management System Security" <${process.env.EMAIL_FROM}>`,
            to: userEmail,
            subject: 'Account Locked - Hospital Management System',
            html: this.renderTemplate('account-locked', templateData) || this.getDefaultAccountLockedTemplate(templateData),
            text: this.generateTextVersion(`
                Security Alert: Account Locked
                
                Your account has been temporarily locked due to multiple failed login attempts.
                
                Locked until: ${unlockTime}
                IP Address: ${ipAddress}
                
                If this was you, you can try again after the lock period expires.
                If this wasn't you, please contact support immediately.
                
                Best regards,
                Hospital Management System Security Team
            `)
        };

        return await this.sendEmail(mailOptions, 'account_locked', userEmail);
    }

    async sendPasswordChangedNotification(userEmail, ipAddress, timestamp) {
        const templateData = {
            userEmail,
            timestamp: new Date(timestamp).toLocaleString(),
            ipAddress,
            supportEmail: process.env.SUPPORT_EMAIL || 'support@hospital.com',
            currentYear: new Date().getFullYear()
        };

        const mailOptions = {
            from: `"Hospital Management System Security" <${process.env.EMAIL_FROM}>`,
            to: userEmail,
            subject: 'Password Changed - Hospital Management System',
            html: this.renderTemplate('password-changed', templateData) || this.getDefaultPasswordChangedTemplate(templateData),
            text: this.generateTextVersion(`
                Security Notice: Password Changed
                
                Your password was successfully changed.
                
                Time: ${timestamp}
                IP Address: ${ipAddress}
                
                If you didn't make this change, please contact support immediately.
                
                Best regards,
                Hospital Management System Security Team
            `)
        };

        return await this.sendEmail(mailOptions, 'password_changed', userEmail);
    }

    async sendNewDeviceLogin(userEmail, deviceInfo, ipAddress, location) {
        const templateData = {
            userEmail,
            deviceType: deviceInfo.device_type || 'Unknown Device',
            browser: deviceInfo.browser_family || 'Unknown Browser',
            operatingSystem: deviceInfo.operating_system || 'Unknown OS',
            ipAddress,
            location: location || 'Unknown Location',
            timestamp: new Date().toLocaleString(),
            supportEmail: process.env.SUPPORT_EMAIL || 'support@hospital.com',
            currentYear: new Date().getFullYear()
        };

        const mailOptions = {
            from: `"Hospital Management System Security" <${process.env.EMAIL_FROM}>`,
            to: userEmail,
            subject: 'New Device Login Detected - Hospital Management System',
            html: this.renderTemplate('new-device-login', templateData) || this.getDefaultNewDeviceLoginTemplate(templateData),
            text: this.generateTextVersion(`
                Security Alert: New Device Login
                
                A new device has logged into your account:
                
                Device: ${deviceInfo.device_type}
                Browser: ${deviceInfo.browser_family}
                OS: ${deviceInfo.operating_system}
                IP: ${ipAddress}
                Location: ${location}
                Time: ${new Date().toLocaleString()}
                
                If this was you, you can ignore this message.
                If this wasn't you, please contact support immediately.
                
                Best regards,
                Hospital Management System Security Team
            `)
        };

        return await this.sendEmail(mailOptions, 'new_device_login', userEmail);
    }

    // =============================================
    // 2FA & SECURITY CODES
    // =============================================

    async send2FACode(userEmail, code, method = 'email', ipAddress = null) {
        const expiryMinutes = 10; // 2FA codes typically expire faster
        
        const templateData = {
            userEmail,
            twoFACode: code,
            method: this.format2FAMethod(method),
            expiryMinutes,
            ipAddress,
            supportEmail: process.env.SUPPORT_EMAIL || 'support@hospital.com',
            currentYear: new Date().getFullYear()
        };

        const mailOptions = {
            from: `"Hospital Management System Security" <${process.env.EMAIL_FROM}>`,
            to: userEmail,
            subject: `Two-Factor Authentication Code - ${this.format2FAMethod(method)}`,
            html: this.renderTemplate('2fa-code', templateData) || this.getDefault2FACodeTemplate(templateData),
            text: this.generateTextVersion(`
                Two-Factor Authentication Code
                
                Your ${method} verification code is:
                
                VERIFICATION CODE: ${code}
                
                This code will expire in ${expiryMinutes} minutes.
                
                Security Information:
                - Email: ${userEmail}
                - Method: ${method}
                - IP Address: ${ipAddress || 'Not available'}
                - Request Time: ${new Date().toLocaleString()}
                
                If you didn't request this code, please contact support immediately.
                
                Best regards,
                Hospital Management System Security Team
            `)
        };

        return await this.sendEmail(mailOptions, '2fa_code', userEmail);
    }

    async sendBackupCodes(userEmail, backupCodes, ipAddress = null) {
        const templateData = {
            userEmail,
            backupCodes: backupCodes.join('\n'),
            ipAddress,
            supportEmail: process.env.SUPPORT_EMAIL || 'support@hospital.com',
            currentYear: new Date().getFullYear(),
            securityNotice: 'Store these codes in a secure location. Each code can be used only once.'
        };

        const mailOptions = {
            from: `"Hospital Management System Security" <${process.env.EMAIL_FROM}>`,
            to: userEmail,
            subject: 'Your Two-Factor Authentication Backup Codes',
            html: this.renderTemplate('backup-codes', templateData) || this.getDefaultBackupCodesTemplate(templateData),
            text: this.generateTextVersion(`
                Two-Factor Authentication Backup Codes
                
                Here are your backup codes for two-factor authentication:
                
                ${backupCodes.map((code, index) => `${index + 1}. ${code}`).join('\n')}
                
                IMPORTANT:
                - Store these codes in a secure location
                - Each code can be used only once
                - Generate new codes if you run out or suspect compromise
                
                Security Information:
                - Email: ${userEmail}
                - IP Address: ${ipAddress || 'Not available'}
                - Generated: ${new Date().toLocaleString()}
                
                Best regards,
                Hospital Management System Security Team
            `)
        };

        return await this.sendEmail(mailOptions, 'backup_codes', userEmail);
    }

    // =============================================
    // ADMIN & SYSTEM EMAILS
    // =============================================

    async sendAdminAlert(subject, message, severity = 'medium') {
        const adminEmails = process.env.ADMIN_EMAILS ? process.env.ADMIN_EMAILS.split(',') : [];
        
        if (adminEmails.length === 0) {
            console.warn('⚠️ No admin emails configured for alerts');
            return { success: false, error: 'No admin emails configured' };
        }

        const templateData = {
            subject,
            message,
            severity,
            timestamp: new Date().toLocaleString(),
            currentYear: new Date().getFullYear()
        };

        const mailOptions = {
            from: `"Hospital Management System Alerts" <${process.env.EMAIL_FROM}>`,
            to: adminEmails,
            subject: `[${severity.toUpperCase()}] ${subject}`,
            html: this.renderTemplate('admin-alert', templateData) || this.getDefaultAdminAlertTemplate(templateData),
            text: this.generateTextVersion(`
                ADMIN ALERT - ${severity.toUpperCase()}
                
                Subject: ${subject}
                Time: ${new Date().toLocaleString()}
                
                Message:
                ${message}
                
                Please review this alert immediately.
            `)
        };

        return await this.sendEmail(mailOptions, 'admin_alert', 'admin');
    }

    async sendPolicyUpdateNotification(userEmail, policyType, policyVersion) {
        const policyLink = `${process.env.CLIENT_URL}/policies`;
        
        const templateData = {
            userEmail,
            policyType: this.formatPolicyType(policyType),
            policyVersion,
            policyLink,
            supportEmail: process.env.SUPPORT_EMAIL || 'support@hospital.com',
            currentYear: new Date().getFullYear()
        };

        const mailOptions = {
            from: `"Hospital Management System Policies" <${process.env.EMAIL_FROM}>`,
            to: userEmail,
            subject: 'Important: Policy Update Notification',
            html: this.renderTemplate('policy-update', templateData) || this.getDefaultPolicyUpdateTemplate(templateData),
            text: this.generateTextVersion(`
                Policy Update Notification
                
                An important policy has been updated: ${policyType} (Version ${policyVersion})
                
                Please review and accept the updated policy at: ${policyLink}
                
                Best regards,
                Hospital Management System Team
            `)
        };

        return await this.sendEmail(mailOptions, 'policy_update', userEmail);
    }

    // =============================================
    // SSO & ACCOUNT MANAGEMENT EMAILS
    // =============================================

    async sendSSOLinkedNotification(userEmail, ssoProvider, ipAddress) {
        const templateData = {
            userEmail,
            ssoProvider: this.formatSSOProvider(ssoProvider),
            ipAddress,
            timestamp: new Date().toLocaleString(),
            supportEmail: process.env.SUPPORT_EMAIL || 'support@hospital.com',
            currentYear: new Date().getFullYear()
        };

        const mailOptions = {
            from: `"Hospital Management System Security" <${process.env.EMAIL_FROM}>`,
            to: userEmail,
            subject: `SSO Provider Linked - ${this.formatSSOProvider(ssoProvider)}`,
            html: this.renderTemplate('sso-linked', templateData) || this.getDefaultSSOLinkedTemplate(templateData),
            text: this.generateTextVersion(`
                SSO Provider Linked
                
                Your ${ssoProvider} account has been successfully linked to your Hospital Management System account.
                
                Time: ${new Date().toLocaleString()}
                IP Address: ${ipAddress}
                
                If you didn't authorize this, please contact support immediately.
                
                Best regards,
                Hospital Management System Security Team
            `)
        };

        return await this.sendEmail(mailOptions, 'sso_linked', userEmail);
    }

    async sendAccountDeactivatedNotification(userEmail, reason, deactivatedBy = 'system') {
        const templateData = {
            userEmail,
            reason,
            deactivatedBy,
            timestamp: new Date().toLocaleString(),
            supportEmail: process.env.SUPPORT_EMAIL || 'support@hospital.com',
            currentYear: new Date().getFullYear()
        };

        const mailOptions = {
            from: `"Hospital Management System" <${process.env.EMAIL_FROM}>`,
            to: userEmail,
            subject: 'Account Deactivated - Hospital Management System',
            html: this.renderTemplate('account-deactivated', templateData) || this.getDefaultAccountDeactivatedTemplate(templateData),
            text: this.generateTextVersion(`
                Account Deactivation Notice
                
                Your Hospital Management System account has been deactivated.
                
                Reason: ${reason}
                Deactivated by: ${deactivatedBy}
                Time: ${new Date().toLocaleString()}
                
                If you believe this is an error, please contact support.
                
                Best regards,
                Hospital Management System Team
            `)
        };

        return await this.sendEmail(mailOptions, 'account_deactivated', userEmail);
    }

    async send2FAEnabledNotification(userEmail, method, ipAddress) {
        const templateData = {
            userEmail,
            method: this.format2FAMethod(method),
            ipAddress,
            timestamp: new Date().toLocaleString(),
            supportEmail: process.env.SUPPORT_EMAIL || 'support@hospital.com',
            currentYear: new Date().getFullYear()
        };

        const mailOptions = {
            from: `"Hospital Management System Security" <${process.env.EMAIL_FROM}>`,
            to: userEmail,
            subject: 'Two-Factor Authentication Enabled',
            html: this.renderTemplate('2fa-enabled', templateData) || this.getDefault2FAEnabledTemplate(templateData),
            text: this.generateTextVersion(`
                Two-Factor Authentication Enabled
                
                ${method} two-factor authentication has been enabled for your account.
                
                Time: ${new Date().toLocaleString()}
                IP Address: ${ipAddress}
                
                If you didn't enable this, please contact support immediately.
                
                Best regards,
                Hospital Management System Security Team
            `)
        };

        return await this.sendEmail(mailOptions, '2fa_enabled', userEmail);
    }

    // =============================================
    // TEMPLATE MANAGEMENT
    // =============================================

    renderTemplate(templateName, data) {
        if (!this.templates[templateName]) {
            return null;
        }

        let template = this.templates[templateName];
        
        // Replace placeholders with actual data
        for (const [key, value] of Object.entries(data)) {
            const placeholder = new RegExp(`{{${key}}}`, 'g');
            template = template.replace(placeholder, value || '');
        }

        return template;
    }

    generateTextVersion(htmlContent) {
        // Simple HTML to text conversion
        return htmlContent
            .replace(/<br\s*\/?>/gi, '\n')
            .replace(/<p>/gi, '\n')
            .replace(/<\/p>/gi, '\n')
            .replace(/<[^>]*>/g, '')
            .replace(/\n\s*\n/g, '\n\n')
            .trim();
    }

    formatPolicyType(policyType) {
        const policyNames = {
            'privacy_policy': 'Privacy Policy',
            'terms_of_service': 'Terms of Service',
            'hipaa_consent': 'HIPAA Consent Form',
            'data_processing': 'Data Processing Agreement',
            'code_of_conduct': 'Code of Conduct',
            'security_policy': 'Security Policy',
            'consent_form': 'General Consent Form'
        };
        
        return policyNames[policyType] || policyType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    formatSSOProvider(provider) {
        const providerNames = {
            'google': 'Google',
            'microsoft': 'Microsoft',
            'apple': 'Apple',
            'saml': 'SAML',
            'oidc': 'OpenID Connect'
        };
        
        return providerNames[provider] || provider.charAt(0).toUpperCase() + provider.slice(1);
    }

    format2FAMethod(method) {
        const methodNames = {
            'email': 'Email',
            'totp': 'Authenticator App',
            'sms': 'SMS'
        };
        
        return methodNames[method] || method.toUpperCase();
    }

    // =============================================
    // DEFAULT TEMPLATES (UPDATED FOR 6-DIGIT CODES)
    // =============================================

    getDefaultVerificationTemplate(data) {
        return `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif; }
                    .header { background: #2563eb; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f8fafc; padding: 30px; border-radius: 0 0 10px 10px; }
                    .code { background: #1e293b; color: white; padding: 20px; font-size: 32px; font-weight: bold; text-align: center; border-radius: 8px; margin: 20px 0; letter-spacing: 8px; }
                    .footer { text-align: center; margin-top: 20px; color: #64748b; font-size: 12px; }
                    .security { background: #f1f5f9; padding: 15px; border-radius: 5px; margin: 15px 0; font-size: 14px; }
                    .instructions { background: #dbeafe; padding: 15px; border-radius: 5px; margin: 15px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Hospital Management System</h1>
                    </div>
                    <div class="content">
                        <h2>Email Verification Required</h2>
                        <p>Thank you for registering with our Hospital Management System. Please verify your email address using the code below:</p>
                        
                        <div class="instructions">
                            <strong>Instructions:</strong><br>
                            Enter this code in the verification form to complete your registration.
                        </div>
                        
                        <div class="code">${data.verificationCode}</div>
                        
                        <div class="security">
                            <strong>Security Information:</strong><br>
                            Email: ${data.userEmail}<br>
                            IP Address: ${data.ipAddress || 'Not available'}<br>
                            Code expires in: ${data.expiryMinutes} minutes
                        </div>
                        
                        <p>This verification code will expire in ${data.expiryMinutes} minutes.</p>
                        <p>If you didn't create an account, please ignore this email.</p>
                    </div>
                    <div class="footer">
                        <p>&copy; ${data.currentYear} Hospital Management System. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
        `;
    }

    getDefaultPasswordResetTemplate(data) {
        return `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif; }
                    .header { background: #dc2626; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f8fafc; padding: 30px; border-radius: 0 0 10px 10px; }
                    .code { background: #1e293b; color: white; padding: 20px; font-size: 32px; font-weight: bold; text-align: center; border-radius: 8px; margin: 20px 0; letter-spacing: 8px; }
                    .footer { text-align: center; margin-top: 20px; color: #64748b; font-size: 12px; }
                    .warning { background: #fef2f2; border: 1px solid #fecaca; padding: 15px; border-radius: 5px; margin: 15px 0; }
                    .security { background: #f1f5f9; padding: 15px; border-radius: 5px; margin: 15px 0; font-size: 14px; }
                    .instructions { background: #fef3c7; padding: 15px; border-radius: 5px; margin: 15px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Password Reset Request</h1>
                    </div>
                    <div class="content">
                        <h2>Password Reset Required</h2>
                        <p>We received a request to reset your password for the Hospital Management System.</p>
                        
                        <div class="instructions">
                            <strong>Instructions:</strong><br>
                            Enter this code in the password reset form to create a new password.
                        </div>
                        
                        <div class="code">${data.resetCode}</div>
                        
                        <div class="warning">
                            <strong>Important:</strong> If you didn't request this password reset, please ignore this email and ensure your account is secure.
                        </div>
                        
                        <div class="security">
                            <strong>Security Information:</strong><br>
                            Email: ${data.userEmail}<br>
                            IP Address: ${data.ipAddress || 'Not available'}<br>
                            Code expires in: ${data.expiryMinutes} minutes
                        </div>
                        
                        <p>This password reset code will expire in ${data.expiryMinutes} minutes.</p>
                    </div>
                    <div class="footer">
                        <p>&copy; ${data.currentYear} Hospital Management System. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
        `;
    }

    getDefault2FACodeTemplate(data) {
        return `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif; }
                    .header { background: #059669; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f8fafc; padding: 30px; border-radius: 0 0 10px 10px; }
                    .code { background: #1e293b; color: white; padding: 20px; font-size: 32px; font-weight: bold; text-align: center; border-radius: 8px; margin: 20px 0; letter-spacing: 8px; }
                    .footer { text-align: center; margin-top: 20px; color: #64748b; font-size: 12px; }
                    .security { background: #f1f5f9; padding: 15px; border-radius: 5px; margin: 15px 0; font-size: 14px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Two-Factor Authentication</h1>
                    </div>
                    <div class="content">
                        <h2>Your Verification Code</h2>
                        <p>Use the following code to complete your ${data.method} two-factor authentication:</p>
                        
                        <div class="code">${data.twoFACode}</div>
                        
                        <div class="security">
                            <strong>Security Information:</strong><br>
                            Email: ${data.userEmail}<br>
                            Method: ${data.method}<br>
                            IP Address: ${data.ipAddress || 'Not available'}<br>
                            Code expires in: ${data.expiryMinutes} minutes
                        </div>
                        
                        <p>This code will expire in ${data.expiryMinutes} minutes.</p>
                        <p>If you didn't request this code, please contact support immediately.</p>
                    </div>
                    <div class="footer">
                        <p>&copy; ${data.currentYear} Hospital Management System. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
        `;
    }

    getDefaultBackupCodesTemplate(data) {
        return `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif; }
                    .header { background: #7c3aed; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f8fafc; padding: 30px; border-radius: 0 0 10px 10px; }
                    .codes { background: #1e293b; color: white; padding: 20px; border-radius: 8px; margin: 20px 0; font-family: monospace; }
                    .footer { text-align: center; margin-top: 20px; color: #64748b; font-size: 12px; }
                    .warning { background: #fef3c7; border: 1px solid #f59e0b; padding: 15px; border-radius: 5px; margin: 15px 0; }
                    .security { background: #f1f5f9; padding: 15px; border-radius: 5px; margin: 15px 0; font-size: 14px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Backup Codes</h1>
                    </div>
                    <div class="content">
                        <h2>Your Two-Factor Authentication Backup Codes</h2>
                        
                        <div class="warning">
                            <strong>IMPORTANT SECURITY NOTICE:</strong><br>
                            Store these codes in a secure location. Each code can be used only once.
                        </div>
                        
                        <div class="codes">${data.backupCodes}</div>
                        
                        <div class="security">
                            <strong>Security Information:</strong><br>
                            Email: ${data.userEmail}<br>
                            IP Address: ${data.ipAddress || 'Not available'}<br>
                            Generated: ${new Date().toLocaleString()}
                        </div>
                        
                        <p><strong>Instructions:</strong></p>
                        <ul>
                            <li>Store these codes in a secure location (password manager, encrypted file)</li>
                            <li>Each code can be used only once</li>
                            <li>Generate new codes if you run out or suspect compromise</li>
                            <li>Do not share these codes with anyone</li>
                        </ul>
                    </div>
                    <div class="footer">
                        <p>&copy; ${data.currentYear} Hospital Management System. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
        `;
    }

    // =============================================
    // EXISTING TEMPLATES (Keep the ones you already have)
    // =============================================

    getDefaultWelcomeTemplate(data) {
        return `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif; }
                    .header { background: #059669; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f8fafc; padding: 30px; border-radius: 0 0 10px 10px; }
                    .footer { text-align: center; margin-top: 20px; color: #64748b; font-size: 12px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Welcome Aboard!</h1>
                    </div>
                    <div class="content">
                        <h2>Welcome to Hospital Management System</h2>
                        <p>Your email has been successfully verified and your account is now active.</p>
                        <p>You can now log in and access all the features available for your role.</p>
                        <p>If you have any questions or need assistance, please contact our support team at ${data.supportEmail}.</p>
                    </div>
                    <div class="footer">
                        <p>&copy; ${data.currentYear} Hospital Management System. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
        `;
    }

    getDefaultAccountLockedTemplate(data) {
        return `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif; }
                    .header { background: #dc2626; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
                    .content { background: #f8fafc; padding: 30px; border-radius: 0 0 10px 10px; }
                    .footer { text-align: center; margin-top: 20px; color: #64748b; font-size: 12px; }
                    .alert { background: #fef2f2; border: 1px solid #fecaca; padding: 15px; border-radius: 5px; margin: 15px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Security Alert: Account Locked</h1>
                    </div>
                    <div class="content">
                        <h2>Account Security Notice</h2>
                        <div class="alert">
                            <strong>Important Security Notice:</strong> Your account has been temporarily locked due to multiple failed login attempts.
                        </div>
                        <p><strong>Email:</strong> ${data.userEmail}</p>
                        <p><strong>Locked Until:</strong> ${data.unlockTime}</p>
                        <p><strong>IP Address:</strong> ${data.ipAddress}</p>
                        <p>If this was you, you can try again after the lock period expires.</p>
                        <p>If this wasn't you, please contact our support team immediately at ${data.supportEmail}.</p>
                    </div>
                    <div class="footer">
                        <p>&copy; ${data.currentYear} Hospital Management System. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
        `;
    }

    // ... (Keep all your existing template methods as they are)
    // getDefaultPasswordChangedTemplate, getDefaultNewDeviceLoginTemplate, 
    // getDefaultAdminAlertTemplate, getDefaultPolicyUpdateTemplate,
    // getDefaultSSOLinkedTemplate, getDefaultAccountDeactivatedTemplate,
    // getDefault2FAEnabledTemplate

    // =============================================
    // CORE EMAIL SENDING FUNCTION
    // =============================================

    async sendEmail(mailOptions, emailType, recipient) {
        try {
            // Add common headers
            mailOptions.headers = {
                'X-Email-Type': emailType,
                'X-System': 'Hospital-Management-System',
                'X-Priority': '3' // Normal priority
            };

            const result = await this.transporter.sendMail(mailOptions);
            
            console.log(`✅ ${emailType} email sent to: ${recipient}`, {
                messageId: result.messageId,
                emailType,
                recipient
            });

            return {
                success: true,
                messageId: result.messageId,
                recipient: recipient,
                type: emailType
            };
        } catch (error) {
            console.error(`❌ Failed to send ${emailType} email to ${recipient}:`, error);
            
            return {
                success: false,
                error: error.message,
                recipient: recipient,
                type: emailType
            };
        }
    }

    // =============================================
    // BULK EMAIL SENDING
    // =============================================

    async sendBulkEmails(emails, templateName, templateData) {
        const results = [];
        
        for (const email of emails) {
            try {
                const result = await this.sendEmail({
                    from: `"Hospital Management System" <${process.env.EMAIL_FROM}>`,
                    to: email.recipient,
                    subject: email.subject,
                    html: this.renderTemplate(templateName, { ...templateData, ...email.data }) || email.html,
                    text: email.text
                }, templateName, email.recipient);

                results.push(result);
                
                // Small delay to avoid overwhelming the email server
                await new Promise(resolve => setTimeout(resolve, 100));
            } catch (error) {
                results.push({
                    success: false,
                    error: error.message,
                    recipient: email.recipient
                });
            }
        }

        return results;
    }

    // =============================================
    // HEALTH CHECK
    // =============================================

    async healthCheck() {
        const connection = await this.verifyConnection();
        const templateCount = Object.keys(this.templates).length;
        
        return {
            service: 'EmailService',
            status: connection.success ? 'healthy' : 'unhealthy',
            connection: connection,
            templates: {
                loaded: templateCount,
                available: Object.keys(this.templates)
            },
            timestamp: new Date().toISOString()
        };
    }
}

module.exports = new EmailService();