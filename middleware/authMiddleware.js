const jwt = require('jsonwebtoken');


const authenticateJWT = (req, res, next) => {
  const authHeader = req.header('Authorization');

  if (!authHeader) {
    return res.status(403).send('Access denied.');
  }

  const token = authHeader.replace('Bearer ', '');

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
      return res.status(403).json({
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
