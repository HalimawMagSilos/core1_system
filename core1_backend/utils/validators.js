const Joi = require('joi');

// =============================================
// AUTHENTICATION VALIDATORS
// =============================================

const registrationSchema = Joi.object({
    email: Joi.string()
        .email()
        .max(255)
        .required()
        .messages({
            'string.email': 'Please provide a valid email address',
            'string.max': 'Email cannot exceed 255 characters',
            'any.required': 'Email is required'
        }),

    password: Joi.string()
        .min(8)
        .max(255)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .required()
        .messages({
            'string.min': 'Password must be at least 8 characters long',
            'string.max': 'Password cannot exceed 255 characters',
            'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)',
            'any.required': 'Password is required'
        }),

    role_id: Joi.number()
        .integer()
        .min(2) // Start from 2 (Patient) since admin (1) cannot be registered
        .max(5)
        .optional()
        .default(5) // Default to Patient role
        .messages({
            'number.base': 'Role ID must be a number',
            'number.min': 'Invalid role ID',
            'number.max': 'Invalid role ID'
        }),

    employee_id: Joi.string()
        .max(20)
        .optional()
        .allow('', null)
        .messages({
            'string.max': 'Employee ID cannot exceed 20 characters'
        })
});

const patientRegistrationSchema = Joi.object({
    email: Joi.string()
        .email()
        .max(255)
        .required()
        .messages({
            'string.email': 'Please provide a valid email address',
            'string.max': 'Email cannot exceed 255 characters',
            'any.required': 'Email is required'
        }),

    password: Joi.string()
        .min(8)
        .max(255)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .required()
        .messages({
            'string.min': 'Password must be at least 8 characters long',
            'string.max': 'Password cannot exceed 255 characters',
            'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)',
            'any.required': 'Password is required'
        })
});

const loginSchema = Joi.object({
    email: Joi.string()
        .email()
        .max(255)
        .required()
        .messages({
            'string.email': 'Please provide a valid email address',
            'string.max': 'Email cannot exceed 255 characters',
            'any.required': 'Email is required'
        }),

    password: Joi.string()
        .required()
        .messages({
            'any.required': 'Password is required'
        })
});

const ssoLoginSchema = Joi.object({
    sso_provider: Joi.string()
        .valid('google', 'microsoft', 'apple', 'saml', 'oidc')
        .required()
        .messages({
            'any.only': 'SSO provider must be one of: google, microsoft, apple, saml, oidc',
            'any.required': 'SSO provider is required'
        }),

    provider_user_id: Joi.string()
        .max(255)
        .required()
        .messages({
            'string.max': 'Provider user ID cannot exceed 255 characters',
            'any.required': 'Provider user ID is required'
        }),

    email: Joi.string()
        .email()
        .max(255)
        .required()
        .messages({
            'string.email': 'Please provide a valid email address',
            'string.max': 'Email cannot exceed 255 characters',
            'any.required': 'Email is required'
        }),

    provider_identity_data: Joi.object()
        .optional()
});

// =============================================
// PASSWORD & TOKEN VALIDATORS
// =============================================

const emailSchema = Joi.object({
    email: Joi.string()
        .email()
        .max(255)
        .required()
        .messages({
            'string.email': 'Please provide a valid email address',
            'string.max': 'Email cannot exceed 255 characters',
            'any.required': 'Email is required'
        })
});

const passwordResetSchema = Joi.object({
    token: Joi.string()
        .length(6)
        .pattern(/^\d+$/)
        .required()
        .messages({
            'string.length': 'Reset token must be exactly 6 digits',
            'string.pattern.base': 'Reset token must contain only numbers',
            'any.required': 'Reset token is required'
        }),

    newPassword: Joi.string()
        .min(8)
        .max(255)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .required()
        .messages({
            'string.min': 'Password must be at least 8 characters long',
            'string.max': 'Password cannot exceed 255 characters',
            'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)',
            'any.required': 'New password is required'
        })
});

const emailVerificationSchema = Joi.object({
    token: Joi.string()
        .length(6)
        .pattern(/^\d+$/)
        .required()
        .messages({
            'string.length': 'Verification token must be exactly 6 digits',
            'string.pattern.base': 'Verification token must contain only numbers',
            'any.required': 'Verification token is required'
        })
});

const changePasswordSchema = Joi.object({
    currentPassword: Joi.string()
        .required()
        .messages({
            'any.required': 'Current password is required'
        }),

    newPassword: Joi.string()
        .min(8)
        .max(255)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .required()
        .messages({
            'string.min': 'Password must be at least 8 characters long',
            'string.max': 'Password cannot exceed 255 characters',
            'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)',
            'any.required': 'New password is required'
        }),

    csrf_token: Joi.string()
        .length(64)
        .pattern(/^[a-f0-9]+$/)
        .required()
        .messages({
            'string.length': 'CSRF token must be exactly 64 characters',
            'string.pattern.base': 'CSRF token must be a valid hexadecimal string',
            'any.required': 'CSRF token is required'
        })
});

const passwordValidationSchema = Joi.object({
    password: Joi.string()
        .min(8)
        .max(255)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .required()
        .messages({
            'string.min': 'Password must be at least 8 characters long',
            'string.max': 'Password cannot exceed 255 characters',
            'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)',
            'any.required': 'Password is required for validation'
        })
});

// =============================================
// PROFILE & USER MANAGEMENT VALIDATORS
// =============================================

const profileUpdateSchema = Joi.object({
    email: Joi.string()
        .email()
        .max(255)
        .optional()
        .messages({
            'string.email': 'Please provide a valid email address',
            'string.max': 'Email cannot exceed 255 characters'
        }),

    employee_id: Joi.string()
        .max(20)
        .optional()
        .allow('', null)
        .messages({
            'string.max': 'Employee ID cannot exceed 20 characters'
        }),

    csrf_token: Joi.string()
        .length(64)
        .pattern(/^[a-f0-9]+$/)
        .required()
        .messages({
            'string.length': 'CSRF token must be exactly 64 characters',
            'string.pattern.base': 'CSRF token must be a valid hexadecimal string',
            'any.required': 'CSRF token is required'
        })
}).min(1); // At least one field must be provided

const adminCreateUserSchema = Joi.object({
    email: Joi.string()
        .email()
        .max(255)
        .required()
        .messages({
            'string.email': 'Please provide a valid email address',
            'string.max': 'Email cannot exceed 255 characters',
            'any.required': 'Email is required'
        }),

    password: Joi.string()
        .min(8)
        .max(255)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
        .optional()
        .allow('', null)
        .messages({
            'string.min': 'Password must be at least 8 characters long',
            'string.max': 'Password cannot exceed 255 characters',
            'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)'
        }),

    role_id: Joi.number()
        .integer()
        .min(2) // Cannot create admin users (role_id 1)
        .max(5)
        .required()
        .messages({
            'number.base': 'Role ID must be a number',
            'number.min': 'Invalid role ID',
            'number.max': 'Invalid role ID',
            'any.required': 'Role ID is required'
        }),

    employee_id: Joi.string()
        .max(20)
        .optional()
        .allow('', null)
        .messages({
            'string.max': 'Employee ID cannot exceed 20 characters'
        }),

    is_active: Joi.boolean()
        .optional()
        .default(true),

    is_verified: Joi.boolean()
        .optional()
        .default(false),

    csrf_token: Joi.string()
        .length(64)
        .pattern(/^[a-f0-9]+$/)
        .required()
        .messages({
            'string.length': 'CSRF token must be exactly 64 characters',
            'string.pattern.base': 'CSRF token must be a valid hexadecimal string',
            'any.required': 'CSRF token is required'
        })
});

const adminUpdateUserSchema = Joi.object({
    email: Joi.string()
        .email()
        .max(255)
        .optional()
        .messages({
            'string.email': 'Please provide a valid email address',
            'string.max': 'Email cannot exceed 255 characters'
        }),

    role_id: Joi.number()
        .integer()
        .min(2) // Cannot assign admin role (role_id 1)
        .max(5)
        .optional()
        .messages({
            'number.base': 'Role ID must be a number',
            'number.min': 'Invalid role ID',
            'number.max': 'Invalid role ID'
        }),

    employee_id: Joi.string()
        .max(20)
        .optional()
        .allow('', null)
        .messages({
            'string.max': 'Employee ID cannot exceed 20 characters'
        }),

    is_active: Joi.boolean()
        .optional(),

    is_locked: Joi.boolean()
        .optional(),

    is_verified: Joi.boolean()
        .optional(),

    failed_login_attempts: Joi.number()
        .integer()
        .min(0)
        .max(100)
        .optional()
        .messages({
            'number.base': 'Failed login attempts must be a number',
            'number.min': 'Failed login attempts cannot be negative',
            'number.max': 'Failed login attempts cannot exceed 100'
        }),

    csrf_token: Joi.string()
        .length(64)
        .pattern(/^[a-f0-9]+$/)
        .required()
        .messages({
            'string.length': 'CSRF token must be exactly 64 characters',
            'string.pattern.base': 'CSRF token must be a valid hexadecimal string',
            'any.required': 'CSRF token is required'
        })
}).min(1); // At least one field must be provided

// =============================================
// 2FA & SECURITY VALIDATORS
// =============================================

const twoFASetupSchema = Joi.object({
    is_email_2fa_enabled: Joi.boolean()
        .optional()
        .default(false),

    is_totp_enabled: Joi.boolean()
        .optional()
        .default(false),

    is_sms_2fa_enabled: Joi.boolean()
        .optional()
        .default(false),

    totp_secret: Joi.string()
        .max(32)
        .optional()
        .allow('', null)
        .messages({
            'string.max': 'TOTP secret cannot exceed 32 characters'
        }),

    totp_backup_codes: Joi.array()
        .items(Joi.string().length(8).pattern(/^[A-Z0-9]+$/))
        .optional()
        .messages({
            'array.items': 'Backup codes must be 8-character alphanumeric strings'
        }),

    require_2fa_for_login: Joi.boolean()
        .optional()
        .default(false),

    csrf_token: Joi.string()
        .length(64)
        .pattern(/^[a-f0-9]+$/)
        .required()
        .messages({
            'string.length': 'CSRF token must be exactly 64 characters',
            'string.pattern.base': 'CSRF token must be a valid hexadecimal string',
            'any.required': 'CSRF token is required'
        })
});

const twoFACodeSchema = Joi.object({
    code: Joi.string()
        .length(6)
        .pattern(/^\d+$/)
        .required()
        .messages({
            'string.length': '2FA code must be exactly 6 digits',
            'string.pattern.base': '2FA code must contain only numbers',
            'any.required': '2FA code is required'
        }),

    method: Joi.string()
        .valid('email', 'totp', 'sms', 'backup_code')
        .required()
        .messages({
            'any.only': '2FA method must be one of: email, totp, sms, backup_code',
            'any.required': '2FA method is required'
        })
});

// =============================================
// DEVICE & SESSION VALIDATORS
// =============================================

const deviceAuthorizationSchema = Joi.object({
    device_fingerprint: Joi.string()
        .min(10)
        .max(64)
        .required()
        .messages({
            'string.min': 'Device fingerprint must be at least 10 characters long',
            'string.max': 'Device fingerprint cannot exceed 64 characters',
            'any.required': 'Device fingerprint is required'
        })
});

const policyAcceptanceSchema = Joi.object({
    csrf_token: Joi.string()
        .length(64)
        .pattern(/^[a-f0-9]+$/)
        .optional()
        .messages({
            'string.length': 'CSRF token must be exactly 64 characters',
            'string.pattern.base': 'CSRF token must be a valid hexadecimal string'
        })
});

// =============================================
// QUERY PARAMETER VALIDATORS
// =============================================

const paginationSchema = Joi.object({
    page: Joi.number()
        .integer()
        .min(1)
        .default(1)
        .messages({
            'number.base': 'Page must be a number',
            'number.min': 'Page must be at least 1'
        }),

    limit: Joi.number()
        .integer()
        .min(1)
        .max(1000)
        .default(50)
        .messages({
            'number.base': 'Limit must be a number',
            'number.min': 'Limit must be at least 1',
            'number.max': 'Limit cannot exceed 1000'
        }),

    sort_by: Joi.string()
        .valid('email', 'role_name', 'created_at', 'last_login_at', 'is_active', 'is_locked')
        .default('created_at')
        .messages({
            'any.only': 'Invalid sort field'
        }),

    sort_order: Joi.string()
        .valid('ASC', 'DESC')
        .default('DESC')
        .messages({
            'any.only': 'Sort order must be ASC or DESC'
        })
});

const userFilterSchema = paginationSchema.append({
    role_id: Joi.number()
        .integer()
        .min(1)
        .max(5)
        .optional()
        .messages({
            'number.base': 'Role ID must be a number',
            'number.min': 'Invalid role ID',
            'number.max': 'Invalid role ID'
        }),

    role_name: Joi.string()
        .valid('admin', 'doctor', 'nurse', 'receptionist', 'patient')
        .optional()
        .messages({
            'any.only': 'Invalid role name'
        }),

    is_active: Joi.boolean()
        .optional(),

    is_locked: Joi.boolean()
        .optional(),

    is_verified: Joi.boolean()
        .optional(),

    is_sso_user: Joi.boolean()
        .optional(),

    search: Joi.string()
        .max(100)
        .optional()
        .allow('')
        .messages({
            'string.max': 'Search term cannot exceed 100 characters'
        }),

    date_from: Joi.date()
        .iso()
        .optional()
        .messages({
            'date.base': 'Date from must be a valid date',
            'date.format': 'Date from must be in ISO format (YYYY-MM-DD)'
        }),

    date_to: Joi.date()
        .iso()
        .min(Joi.ref('date_from'))
        .optional()
        .messages({
            'date.base': 'Date to must be a valid date',
            'date.format': 'Date to must be in ISO format (YYYY-MM-DD)',
            'date.min': 'Date to cannot be before date from'
        }),

    last_login_from: Joi.date()
        .iso()
        .optional()
        .messages({
            'date.base': 'Last login from must be a valid date',
            'date.format': 'Last login from must be in ISO format (YYYY-MM-DD)'
        }),

    last_login_to: Joi.date()
        .iso()
        .min(Joi.ref('last_login_from'))
        .optional()
        .messages({
            'date.base': 'Last login to must be a valid date',
            'date.format': 'Last login to must be in ISO format (YYYY-MM-DD)',
            'date.min': 'Last login to cannot be before last login from'
        })
});

// =============================================
// VALIDATION MIDDLEWARE
// =============================================

const validate = (schema) => {
    return (req, res, next) => {
        const { error } = schema.validate(req.body, {
            abortEarly: false,
            stripUnknown: true
        });
        
        if (error) {
            const errors = error.details.map(detail => ({
                field: detail.path[0],
                message: detail.message
            }));

            return res.status(400).json({
                success: false,
                error: 'Validation failed',
                message: 'Please check your input data',
                errors: errors
            });
        }
        next();
    };
};

const validateQuery = (schema) => {
    return (req, res, next) => {
        const { error } = schema.validate(req.query, {
            abortEarly: false,
            stripUnknown: true,
            convert: true
        });
        
        if (error) {
            const errors = error.details.map(detail => ({
                field: detail.path[0],
                message: detail.message
            }));

            return res.status(400).json({
                success: false,
                error: 'Invalid query parameters',
                message: 'Please check your query parameters',
                errors: errors
            });
        }
        next();
    };
};

const validateParams = (schema) => {
    return (req, res, next) => {
        const { error } = schema.validate(req.params, {
            abortEarly: false,
            stripUnknown: true
        });
        
        if (error) {
            const errors = error.details.map(detail => ({
                field: detail.path[0],
                message: detail.message
            }));

            return res.status(400).json({
                success: false,
                error: 'Invalid parameters',
                message: 'Please check your URL parameters',
                errors: errors
            });
        }
        next();
    };
};

// =============================================
// UUID VALIDATION
// =============================================

const uuidSchema = Joi.string()
    .guid({
        version: ['uuidv4']
    })
    .required()
    .messages({
        'string.guid': 'Invalid UUID format',
        'any.required': 'UUID is required'
    });

const validateUUID = (req, res, next) => {
    const { error } = uuidSchema.validate(req.params.id || req.body.user_id || req.params.user_id);
    
    if (error) {
        return res.status(400).json({
            success: false,
            error: 'Invalid identifier',
            message: 'Please provide a valid UUID'
        });
    }
    next();
};

module.exports = {
    // Authentication
    registrationSchema,
    patientRegistrationSchema,
    loginSchema,
    ssoLoginSchema,
    
    // Password & Tokens
    emailSchema,
    passwordResetSchema,
    emailVerificationSchema,
    changePasswordSchema,
    passwordValidationSchema,
    
    // Profile & User Management
    profileUpdateSchema,
    adminCreateUserSchema,
    adminUpdateUserSchema,
    
    // 2FA & Security
    twoFASetupSchema,
    twoFACodeSchema,
    
    // Device & Session
    deviceAuthorizationSchema,
    policyAcceptanceSchema,
    
    // Query Parameters
    paginationSchema,
    userFilterSchema,
    
    // Validation Middleware
    validate,
    validateQuery,
    validateParams,
    validateUUID
};