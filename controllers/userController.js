const User = require('../models/userModel');
const UserActivityLog = require('../models/userActivityLogModel');
const AuditTrail = require('../models/auditTrailModel');
const bcrypt = require('bcryptjs');
const transport = require('../config/mailerConfig');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

exports.registerUser = async (req, res) => {
  const { username, password, role } = req.body;
  const user = new User({ username, password, role });
  await user.save();
  const emailVerificationToken = crypto.randomBytes(32).toString('hex');

  // Store token in user model
  user.emailVerificationToken = emailVerificationToken;
  await user.save();

  // Send verification email
  const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${emailVerificationToken}`;
  await transport.sendMail({
    from: 'noreply@yourapp.com',
    to: user.email,
    subject: 'Email Verification',
    html: `<p>Click <a href="${verificationLink}">here</a> to verify your email.</p>`,
  });

  res
    .status(200)
    .json({ message: 'Registration successful, please verify your email.' });
};
// Add a new method to handle email verification
exports.verifyEmail = async (req, res) => {
  const { token } = req.params;
  const user = await User.findOne({ emailVerificationToken: token });

  if (!user) {
    return res.status(400).json({ message: 'Invalid or expired token' });
  }

  user.emailVerified = true;
  user.emailVerificationToken = undefined;
  await user.save();

  res.status(200).json({ message: 'Email verified successfully' });
};
const logUserActivity = async (userId, activity) => {
  const log = new UserActivityLog({ userId, activity });
  await log.save();
};

exports.resendVerificationEmail = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user || user.emailVerified) {
    return res
      .status(400)
      .json({ message: 'This email is either invalid or already verified.' });
  }

  // Generate new email verification token
  const emailVerificationToken = crypto.randomBytes(32).toString('hex');

  // Store new token in user model
  user.emailVerificationToken = emailVerificationToken;
  await user.save();

  // Resend verification email
  const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${emailVerificationToken}`;
  await transport.sendMail({
    from: 'noreply@yourapp.com',
    to: user.email,
    subject: 'Email Verification',
    html: `<p>Click <a href="${verificationLink}">here</a> to verify your email.</p>`,
  });

  res
    .status(200)
    .json({ message: 'Verification email resent. Please check your inbox.' });
};


const logAuditTrail = async (userId, action, changes = {}) => {
  const auditTrail = new AuditTrail({ userId, action, changes });
  await auditTrail.save();
};


exports.loginUser = async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (user.accountLockUntil && user.accountLockUntil > Date.now()) {
    return res
      .status(401)
      .json({ message: 'Account is locked. Try again later.' });
  }
  if (!user.emailVerified) {
    return res
      .status(401)
      .json({ message: 'Please verify your email before logging in.' });
  }

  if (!user || !(await bcrypt.compare(password, user.password))) {
    user.failedLoginAttempts += 1;
    await user.save();
    // Log the user login activity
    logUserActivity(user._id, 'User logged in');
    if (user.failedLoginAttempts >= 3) {
      user.accountLockUntil = Date.now() + 15 * 60 * 1000; // Lock for 15 minutes
      await user.save();
      return res.status(401).json({
        message: 'Account locked due to too many failed login attempts',
      });
    }

    return res.status(401).json({ message: 'Invalid username or password' });
  }

  user.failedLoginAttempts = 0;
  user.accountLockUntil = undefined;
  await user.save();

  const token = jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    {
      expiresIn: '1h',
    }
  );

  const refreshToken = jwt.sign(
    { id: user._id },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: '7d',
    }
  );
  user.refreshToken = refreshToken;
  await user.save();

  // Generate access token
  const accessToken = jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    {
      expiresIn: '1h',
    }
  );

  res.status(200).json({ message: 'Logged in', accessToken, refreshToken });
};
exports.refreshToken = async (req, res) => {
  const { refreshToken } = req.body;
  const user = await User.findOne({ refreshToken });

  if (!user) {
    return res.status(401).json({ message: 'Invalid refresh token' });
  }

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    const accessToken = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      {
        expiresIn: '1h',
      }
    );

    res.status(200).json({ accessToken });
  });
};
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ 'profile.email': email });

  if (!user) {
    return res.status(404).json({ message: 'Email not found' });
  }

  const resetToken = crypto.randomBytes(32).toString('hex');
  user.passwordResetToken = resetToken;
  user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  await user.save();

  const resetURL = `http://localhost:4000/users/resetPassword/${resetToken}`;

  const message = `Forgot your password? Click the link to reset your password: ${resetURL}`;

  await transport.sendMail({
    from: 'admin@example.com',
    to: email,
    subject: 'Password Reset',
    text: message,
  });

    exports.setupTwoFactor = async (req, res) => {
      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      const secret = speakeasy.generateSecret({ length: 20 });
      QRCode.toDataURL(secret.otpauth_url, (err, dataURL) => {
        user.twoFactorSecret = secret.base32;
        user.save();
        res.json({ message: 'Two-factor auth enabled', dataURL });
      });
    };

    exports.verifyTwoFactor = async (req, res) => {
      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      const token = req.body.token;
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token,
      });

      if (verified) {
        user.isTwoFactorEnabled = true;
        await user.save();
        res
          .status(200)
          .json({ message: 'Two-factor auth verified and enabled' });
      } else {
        res.status(400).json({ message: 'Invalid token' });
      }
    };
  res.status(200).json({ message: 'Password reset link sent' });
};
exports.getProfile = async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }
  res.status(200).json({ profile: user.profile });
};

exports.updateProfile = async (req, res) => {
  const updates = req.body;
  const user = await User.findByIdAndUpdate(
    req.user.id,
    { $set: { profile: updates } },
    { new: true }
  ).select('-password');
  logUserActivity(req.user.id, 'User updated profile');
  logAuditTrail(req.user.id, 'Updated Profile', { updatedFields: req.body });
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }
  res.status(200).json({ message: 'Profile updated', profile: user.profile });
};
