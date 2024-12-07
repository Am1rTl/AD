var express = require('express');
var router = express.Router();
var eventController = require('../controllers/eventController');
var authenticate = require('../middleware/auth').authenticate;
// Create a new event
router.post('/', authenticate, eventController.createEvent);
// Get all events
router.get('/', authenticate, eventController.getEvents);
// Apply for an event
router.post('/:eventId/apply', authenticate, eventController.applyForEvent);
// Manage participation (approve/reject)
router.put('/:eventId/participations/:participationId', authenticate, eventController.manageParticipation);
// Add this new route
router.get('/:eventId/status', authenticate, eventController.getEventStatus);
// Get specific event
router.get('/:id', authenticate, eventController.getEvent);
// Get event participations
router.get('/:id/participations', authenticate, eventController.getEventParticipations);
// Export event
router.get('/:id/export', authenticate, eventController.exportEvent);
// Import event
router.post('/import', authenticate, eventController.importEvent);
module.exports = router;
//# sourceMappingURL=eventRoutes.js.map