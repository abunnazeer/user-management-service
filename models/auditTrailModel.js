const mongoose = require('mongoose');

const auditTrailSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  action: {
    type: String,
    required: true,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
  changes: Object,
});

module.exports = mongoose.model('AuditTrail', auditTrailSchema);
