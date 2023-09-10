const User = require('../models/userModel');
const UserActivityLog = require('../models/userActivityLogModel');
const AuditTrail = require('../models/auditTrailModel');
const bcrypt = require('bcryptjs');
const transport = require('../config/mailerConfig');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const emailTemplate = require('../util/emailTemplate');
const url = require('url'); // Import the url library

// --- User Registration ---
exports.registerUser = async (req, res) => {
  const { username, password, role, email } = req.body;

  // Validate that the password is alphanumeric
  const alphanumericRegex = /^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d@#$%^&+=!-]{8,}$/;

  const isPasswordValid = alphanumericRegex.test(password);
  if (!isPasswordValid) {
    return res.status(400).json({
      message:
        'Password must be at least 8 characters long and contain both letters and numbers.',
    });
  }

  // Create new user (password will be hashed in the pre-save hook)
  const user = new User({ username, password, role, email });

  const emailVerificationToken = crypto.randomBytes(32).toString('hex');

  // Dynamically construct the URL for email verification
  const verificationLink = url.format({
    protocol: req.protocol,
    host: req.get('host'),
    pathname: '/verify-email',
    query: {
      token: emailVerificationToken,
    },
  });

  try {
    const emailContent = `<p>Click <a href="${verificationLink}">here</a> to verify your email.</p>`;
    const fullEmailContent = emailTemplate(emailContent);
    await transport.sendMail({
      from: 'X-HMS Solution<xhms@xzedge.ng>',
      to: user.email,
      subject: 'Email Verification',
      html: fullEmailContent,
    });

    // If email sending is successful, save the user
    user.emailVerificationToken = emailVerificationToken;
    await user.save();

    res
      .status(200)
      .json({ message: 'Registration successful, please verify your email.' });
  } catch (error) {
    // If email sending fails, delete the user and send an error response
    await User.findByIdAndDelete(user._id);
    console.log('Error sending email:', error);
    res.status(500).json({ message: 'Registration failed, please try again.' });
  }
};

// --- Email Verification ---

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

// --- User Activity Logging (Helper Function) ---
const logUserActivity = async (userId, activity) => {
  const log = new UserActivityLog({ userId, activity });
  await log.save();
};

// --- Resend Verification Email ---
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

  // Dynamically construct the URL
  const verificationLink = url.format({
    protocol: req.protocol,
    host: req.get('host'),
    pathname: '/verify-email',
    query: {
      token: emailVerificationToken,
    },
  });

  // Create email content using the template
  const emailContent = `<p>Click <a href="${verificationLink}">here</a> to verify your email.</p>`;
  const fullEmailContent = emailTemplate(emailContent);

  try {
    // Attempt to resend verification email
    await transport.sendMail({
      from: 'noreply@yourapp.com',
      to: user.email,
      subject: 'Email Verification',
      html: fullEmailContent,
    });

    res
      .status(200)
      .json({ message: 'Verification email resent. Please check your inbox.' });
  } catch (error) {
    console.log('Error sending email:', error);
    res.status(500).json({
      message: 'Could not resend verification email. Please try again.',
    });
  }
};

// --- Audit Trail Logging (Helper Function) ---
const logAuditTrail = async (userId, action, changes = {}) => {
  const auditTrail = new AuditTrail({ userId, action, changes });
  await auditTrail.save();
};

// --- User Login ---
exports.loginUser = async (req, res) => {
  const { identifier, password } = req.body; // Changed to 'identifier'

  // Find user by either username or email
  const user = await User.findOne({
    $or: [{ username: identifier }, { email: identifier }],
  });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    if (user) {
      user.failedLoginAttempts += 1;
      await user.save();
    }

    if (user && user.failedLoginAttempts >= 50) {
      user.accountLockUntil = Date.now() + 15 * 60 * 1000; // Lock for 15 minutes
      await user.save();
      return res.status(401).json({
        message: 'Account locked due to too many failed login attempts',
      });
    }

    return res
      .status(401)
      .json({ message: 'Invalid username or email or password' });
  }

  if (user && !user.emailVerified) {
    return res
      .status(401)
      .json({ message: 'Please verify your email before logging in.' });
  }

  if (!user || !(await bcrypt.compare(password, user.password))) {
    if (user) {
      user.failedLoginAttempts += 1;
      await user.save();
    }

    if (user && user.failedLoginAttempts >= 3) {
      user.accountLockUntil = Date.now() + 15 * 60 * 1000; // Lock for 15 minutes
      await user.save();
      return res.status(401).json({
        message: 'Account locked due to too many failed login attempts',
      });
    }

    return res
      .status(401)
      .json({ message: 'Invalid username or email or password' });
  }

  // Reset the failed login attempts and lockout time
  user.failedLoginAttempts = 0;
  user.accountLockUntil = undefined;
  await user.save();

  // Create JWT token
  const token = jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    {
      expiresIn: '1h',
    }
  );

  // Create Refresh Token
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

// --- Refresh JWT Token ---
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
// --- Forgot Password ---
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  // Find user by email
  const user = await User.findOne({ email });
  if (!user) {
    return res
      .status(404)
      .json({ message: 'No user found with that email address.' });
  }

  // Generate a reset token
  const resetToken = crypto.randomBytes(32).toString('hex');

  // Save the token and its expiration time in the user's record
  user.passwordResetToken = resetToken;
  user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

  await user.save();

  // Dynamically construct the reset URL
  const resetURL = `${req.protocol}://${req.get(
    'host'
  )}/reset-password/${resetToken}`;

  // Create the email content using your existing email template
  const emailContent = `<p>You are receiving this because you (or someone else) have requested the reset of the password for your account.</p><p>Please click <a href="${resetURL}">here</a> to complete the process.</p>`;
  const fullEmailContent = emailTemplate(emailContent);

  try {
    await transport.sendMail({
      from: 'X-HMS Solution<xhms@xzedge.ng>',
      to: user.email,
      subject: 'Password Reset',
      html: fullEmailContent,
    });

    res.status(200).json({ message: 'Password reset token sent to email.' });
  } catch (error) {
    console.log('Error sending email:', error);
    res.status(500).json({ message: 'Error sending reset token email.' });
  }
};
// --- Reset Password ---
exports.resetPassword = async (req, res) => {
  const { resetToken } = req.params;
  const { newPassword } = req.body;

  // Find user by reset token and ensure it hasn't expired
  const user = await User.findOne({
    passwordResetToken: resetToken,

    passwordResetExpires: { $gt: Date.now() },
  });
  if (!user) {
    return res.status(400).json({ message: 'Invalid or expired token.' });
  }

  // Update the password
  user.password = newPassword;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

  await user.save();

  res.status(200).json({ message: 'Password reset successfully.' });
};

// --- Change User Password ---
exports.changePassword = async (req, res) => {
  try {
    const userId = req.user.id; // assuming you have middleware that sets `req.user`
    const { oldPassword, newPassword } = req.body;

    // Validate new password
    const alphanumericRegex =
      /^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d@#$%^&+=!-]{8,}$/;
    if (!alphanumericRegex.test(newPassword)) {
      return res.status(400).json({
        message:
          'New password must be at least 8 characters long and contain both letters and numbers.',
      });
    }

    // Fetch the user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // Attempt to change the password
    await user.changePassword(oldPassword, newPassword);

    // Log the event
    logUserActivity(userId, 'User changed password');
    logAuditTrail(userId, 'Changed Password');

    // Respond to the client
    res.status(200).json({ message: 'Password changed successfully.' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// --- Setup Two-Factor Authentication ---
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
// --- Verify Two-Factor Token ---
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
    res.status(200).json({ message: 'Two-factor auth verified and enabled' });
  } else {
    res.status(400).json({ message: 'Invalid token' });
  }
};

// --- Get User Profile ---
exports.getProfile = async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }
  res.status(200).json({ profile: user.profile });
};

// --- Update User Profile ---
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
