var express = require('express');
var router = express.Router();
var authController = require('../controllers/authController');
var authenticate = require('../middleware/auth').authenticate;
router.post('/register', authController.register);
router.post('/login', authController.login);
router.get('/me', authenticate, authController.getMe);
module.exports = router;
//# sourceMappingURL=authRoutes.js.map