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
  profile: {
    firstName: String,
    lastName: String,
    email: String,
    phone: String,
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
});


userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  next();
});

module.exports = mongoose.model('User', userSchema);
