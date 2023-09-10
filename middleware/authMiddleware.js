const jwt = require('jsonwebtoken');

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization').replace('Bearer ', '');
  if (!token) return res.status(403).send('Access denied.');

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
};

// Role-Based Authorization Middleware
const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res
        .status(403)
        .json({
          message: "Access forbidden: You don't have the required role.",
        });
    }
    next();
  };
};

module.exports = {
  authenticateJWT,
  authorizeRole,
};
