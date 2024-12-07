var express = require('express');
var router = express.Router();
var userController = require('../controllers/userController');
var _a = require('../middleware/auth'), authenticate = _a.authenticate, authorize = _a.authorize;
// Protect all routes
router.use(authenticate);
// Routes accessible by authenticated users
//router.get('/me', userController.getMe);
// Routes accessible only by admins
router.get('/', authorize('admin'), userController.getAllUsers);
router.post('/', authorize('admin'), userController.createUser);
router.get('/:id', authorize('admin'), userController.getUserById);
router.put('/:id', authorize('admin'), userController.updateUser);
router.delete('/:id', authorize('admin'), userController.deleteUser);
module.exports = router;
//# sourceMappingURL=userRoutes.js.map