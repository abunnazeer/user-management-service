const express = require('express');
const {
  registerUser,
  loginUser,
  getProfile,
  updateProfile,
  forgotPassword,
  setupTwoFactor,
  verifyTwoFactor,
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

router.post('/forgotPassword', forgotPassword);
// Use middleware for the profile routes
// router.post('/setupTwoFactor', authenticateJWT, setupTwoFactor);
// router.post('/verifyTwoFactor', authenticateJWT, verifyTwoFactor);
router.post('/refreshToken', refreshToken);
router.get(
  '/profile',
  authenticateJWT,
  authorizeRole(['patient', 'doctor', 'admin']),
  getProfile
);
router.put(
  '/profile',
  authenticateJWT,
  authorizeRole(['patient', 'doctor', 'admin']),
  updateProfile
);

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
// ... (existing routes)

router.post('/resend-verification', resendVerificationEmail);

router.get(
  '/getUserById/:id',
  authenticateJWT,
  authorizeRole(['admin']),
  async (req, res) => {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json({ user });
  }
);
module.exports = router;