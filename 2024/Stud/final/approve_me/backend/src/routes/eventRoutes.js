const express = require('express');
const router = express.Router();
const eventController = require('../controllers/eventController');
const { authenticate } = require('../middleware/auth');

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