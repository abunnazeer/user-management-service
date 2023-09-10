const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    unique: true,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ['patient', 'doctor', 'admin'],
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },

  profile: {
    aboutMe: String,
    specialization: String, // For doctors
    firstName: String,
    lastName: String,
    phone: String,
    profilePicture: String,
  },
  twoFactorSecret: String,
  isTwoFactorEnabled: {
    type: Boolean,
    default: false,
  },
  failedLoginAttempts: {
    type: Number,
    default: 0,
  },
  accountLockUntil: Date,

  refreshToken: {
    type: String,
    default: null,
  },
  emailVerified: {
    type: Boolean,
    default: false,
  },
  emailVerificationToken: String,
  passwordResetToken: String,
  passwordResetExpires: Date,
});

// Method to change the user's password
userSchema.methods.changePassword = async function (oldPassword, newPassword) {
  if (!(await bcrypt.compare(oldPassword, this.password))) {
    throw new Error('Your old password is incorrect.');
  }

  this.password = newPassword;
  await this.save();
};

// Pre-save hook to hash the password if it's modified
userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

module.exports = mongoose.model('User', userSchema);