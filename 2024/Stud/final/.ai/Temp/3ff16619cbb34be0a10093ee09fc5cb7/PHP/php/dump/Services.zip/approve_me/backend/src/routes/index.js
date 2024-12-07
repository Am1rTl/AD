const express = require('express');
const router = express.Router();
const userRoutes = require('./userRoutes');
const authRoutes = require('./authRoutes');
const eventRoutes = require('./eventRoutes');

router.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK' });
});

// Auth routes
router.use('/auth', authRoutes);

// User routes
router.use('/users', userRoutes);

// Event routes
router.use('/events', eventRoutes);

module.exports = router;