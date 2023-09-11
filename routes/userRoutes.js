const express = require('express');
const {
  registerUser,
  loginUser,
  getProfile,
  updateProfile,
  forgotPassword,
  resetPassword,
  changePassword,
  createProfile,
  deleteProfile,

  verifyTwoFactor,
  setupTwoFactor,
  verifyTwoFactorLogin,
  disableTwoFactor,
  refreshToken,
  verifyEmail,
  resendVerificationEmail,
} = require('../controllers/userController');
const {
  authenticateJWT,
  authorizeRole,
} = require('../middleware/authMiddleware');

const router = express.Router();

router.post('/register', registerUser);
router.post('/login', loginUser);

router.post('/forgot-password', forgotPassword);
router.post('/reset-password/:resetToken', resetPassword);

router.post('/change-password', authenticateJWT, changePassword);

// Use middleware for the profile routes
// Enable 2FA
router.post('/setup-two-factor', authenticateJWT, setupTwoFactor);
router.post('/verify-to-enable-two-factor', authenticateJWT, verifyTwoFactor);

// Disable 2FA
router.post('/disable-two-factor', authenticateJWT, disableTwoFactor);

// Verify 2FA Token during login
router.post('/verify-two-factor-login', verifyTwoFactorLogin);
router.post('/refreshToken', refreshToken);


router.get('/profile', authenticateJWT, getProfile);
router.post('/profile', authenticateJWT, createProfile);
router.put('/profile', authenticateJWT, updateProfile);
router.delete('/profile', authenticateJWT, deleteProfile);


// Example admin-only route
router.get(
  '/admin-dashboard',
  authenticateJWT,
  authorizeRole(['admin']),
  (req, res) => {
    res.status(200).json({ message: 'Welcome to the admin dashboard' });
  }
);
router.get('/verify-email/:token', verifyEmail);


router.post('/resend-verification', resendVerificationEmail);


module.exports = router;
