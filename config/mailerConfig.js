const nodemailer = require('nodemailer');

// const transport = nodemailer.createTransport({
//   host: "mail.virtualshago.ng",
//   port: 587, //587, //465
//   secure: false,
//   auth: {
//     user: "hplus@virtualshago.ng",
//     pass: "ShadowBlade@1235",
//   },
//   tls: {
//     rejectUnauthorized: false,
//   },
// });

// module.exports = transport;

const transport = nodemailer.createTransport({
  host: "sandbox.smtp.mailtrap.io",
  port: 2525,
  auth: {
    user: "61423be2cba607",
    pass: "cdff17e355d834",
  },
  tls: {
    rejectUnauthorized: false,
  },
});

module.exports = transport;
