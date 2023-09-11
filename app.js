// const express = require('express');
// const dotenv = require('dotenv');
// const mongoose = require('mongoose');
// const bodyParser = require('body-parser');
// const userRoutes = require('./routes/userRoutes');

// // Load environment variables

// const app = express();

// dotenv.config({ path: './config.env' });
// const dbURI = process.env.DATABASE.replace(
//   '<PASSWORD>',
//   process.env.DATABASE_PASSWORD
// );

// mongoose
//   .connect(dbURI, {
//     useNewUrlParser: true,
//     useUnifiedTopology: true,
//   })
//   .then(() => console.log('MongoDB Connected'))
//   .catch((err) => console.log(err));

// // Middleware
// app.use(bodyParser.json());

// /// User Routes
// app.use('/api/v1/users', userRoutes);

// // Start the server
// const port = process.env.PORT || 4000;
// app.listen(port, () => {
//   console.log(`Server running on http://localhost:${port}`);
// });
const express = require('express');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const winston = require('winston');
const userRoutes = require('./routes/userRoutes');
const client = require('prom-client');

// Initialize Prometheus metrics
const collectDefaultMetrics = client.collectDefaultMetrics;
collectDefaultMetrics({ timeout: 5000 });

// Create Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

// Load environment variables
dotenv.config({ path: './config.env' });
const dbURI = process.env.DATABASE.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD
);

mongoose
  .connect(dbURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => logger.info('MongoDB Connected'))
  .catch((err) => logger.error(err));

const app = express();

// Middleware
app.use(bodyParser.json());

// Morgan for HTTP request logging
app.use(morgan('combined'));

// User Routes
app.use('/api/v1/users', userRoutes);

// Prometheus metrics endpoint
app.get('/metrics', (req, res) => {
  res.set('Content-Type', client.register.contentType);
  res.end(client.register.metrics());
});

// Start the server
const port = process.env.PORT || 4000;
app.listen(port, () => {
  logger.info(`Server running on http://localhost:${port}`);
});
