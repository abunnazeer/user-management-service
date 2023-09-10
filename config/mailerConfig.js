const nodemailer = require('nodemailer');

const transport = nodemailer.createTransport({
  host: 'mail.xzedge.ng',
  port: 465,
  secure: true,
  auth: {
    user: 'xhms@xzedge.ng',
    pass: 'ShadowBlade@1235',
  },
  tls: {
    rejectUnauthorized: false,
  },
});

module.exports = transport;

