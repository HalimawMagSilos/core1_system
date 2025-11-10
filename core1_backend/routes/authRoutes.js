const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticateToken } = require('../middlewares/auth');
const { middleware: csrfMiddleware, attachToken } = require('../config/csrf');

// Apply CSRF protection to all routes except GET
router.use(csrfMiddleware);

// Public routes (no authentication required)
router.post('/register', authController.register);
router.post('/register-patient', authController.registerPatient);
router.post('/login', authController.login);
router.post('/sso-login', authController.ssoLogin);
router.post('/verify-email', authController.verifyEmail);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);
router.post('/resend-verification', authController.resendVerification);
router.post('/check-account-status', authController.checkAccountStatus);

// Password validation (public)
router.post('/validate-password', authController.validatePassword);

// System information (public)
router.get('/roles', authController.getRoles);
router.get('/policies', authController.getActivePolicies);

// Apply authentication middleware to protected routes
router.use(authenticateToken);

// Protected routes (authentication required)
router.get('/profile', authController.getProfile);
router.put('/profile', authController.updateProfile);
router.post('/change-password', authController.changePassword);
router.post('/accept-policies', authController.acceptPolicies);
router.get('/verification-status', authController.checkVerificationStatus);
router.post('/check-device-authorization', authController.checkDeviceAuthorization);

// 2FA routes
router.get('/2fa-settings', authController.get2FASettings);
router.post('/setup-2fa', authController.setup2FA);

// Socket token
router.get('/socket-token', authController.getSocketToken);

// Token validation
router.get('/validate-token', authController.validateToken);

// Logout
router.post('/logout', authController.logout);

// Attach CSRF token to response for all GET routes
router.use((req, res, next) => {
  if (req.method === 'GET') {
    attachToken(req, res);
  }
  next();
});

module.exports = router;