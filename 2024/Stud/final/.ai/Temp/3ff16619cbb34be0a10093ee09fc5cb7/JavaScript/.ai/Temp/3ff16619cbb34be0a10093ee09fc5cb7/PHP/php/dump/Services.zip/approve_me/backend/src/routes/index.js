var express = require('express');
var router = express.Router();
var userRoutes = require('./userRoutes');
var authRoutes = require('./authRoutes');
var eventRoutes = require('./eventRoutes');
router.get('/health', function (req, res) {
    res.status(200).json({ status: 'OK' });
});
// Auth routes
router.use('/auth', authRoutes);
// User routes
router.use('/users', userRoutes);
// Event routes
router.use('/events', eventRoutes);
module.exports = router;
//# sourceMappingURL=index.js.map