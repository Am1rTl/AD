const { Event, Participation, User } = require('../models');
const Sequelize = require('sequelize');
const vm = require('vm');

exports.createEvent = async (req, res, next) => {
  try {
    const { title, description, privateDetails, date } = req.body;
    const event = await Event.create({
      title,
      description,
      privateDetails,
      date,
      creatorId: req.user.id
    });
    res.status(201).json(event);
  } catch (error) {
    next(error);
  }
};

exports.getEvents = async (req, res, next) => {
  try {
    const events = await Event.findAll();
    
    // If user is not authenticated, remove private details from all events
    if (!req.user) {
      return res.json(events.map(event => {
        const eventData = event.toJSON();
        delete eventData.privateDetails;
        return eventData;
      }));
    }

    // For authenticated users, check each event's visibility
    const eventsWithVisibility = await Promise.all(events.map(async (event) => {
      const eventData = event.toJSON();
      
      // Show private details if user is creator or has approved participation
      if (event.creatorId !== req.user.id) {
        const participation = await Participation.findOne({
          where: {
            eventId: event.id,
            userId: req.user.id,
            status: 'approved'
          }
        });
        
        if (!participation) {
          delete eventData.privateDetails;
        }
      }
      
      return eventData;
    }));

    res.json(eventsWithVisibility);
  } catch (error) {
    next(error);
  }
};

exports.applyForEvent = async (req, res, next) => {
  try {
    const { eventId } = req.params;
    const participation = await Participation.create({
      userId: req.user.id,
      eventId
    });
    res.status(201).json(participation);
  } catch (error) {
    next(error);
  }
};

exports.manageParticipation = async (req, res, next) => {
  try {
    const { eventId, participationId } = req.params;
    const { status } = req.body;

    const event = await Event.findByPk(eventId);
    if (!event || event.creatorId !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    const participation = await Participation.findByPk(participationId);
    if (!participation) {
      return res.status(404).json({ message: 'Participation not found' });
    }

    participation.status = status;
    await participation.save();

    res.json(participation);
  } catch (error) {
    next(error);
  }
};

exports.getEventStatus = async (req, res, next) => {
  try {
    const { eventId } = req.params;
    const userId = req.user.id;

    const participation = await Participation.findOne({
      where: {
        eventId,
        userId
      }
    });

    const status = participation ? participation.status : 'not_applied';
    res.json({ status });
  } catch (error) {
    next(error);
  }
};

exports.getEvent = async (req, res, next) => {
  try {
    const event = await Event.findByPk(req.params.id);
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }

    // Check if user is creator or has approved participation
    let showPrivateDetails = false;
    if (req.user) {
      if (event.creatorId === req.user.id) {
        showPrivateDetails = true;
      } else {
        const participation = await Participation.findOne({
          where: {
            eventId: event.id,
            userId: req.user.id,
            status: 'approved'
          }
        });
        showPrivateDetails = !!participation;
      }
    }

    const eventData = event.toJSON();
    if (!showPrivateDetails) {
      delete eventData.privateDetails;
    }

    res.json(eventData);
  } catch (error) {
    next(error);
  }
};

exports.getEventParticipations = async (req, res, next) => {
  try {
    const sortField = req.query.sort || 'createdAt';
    const orderDirection = req.query.order || 'DESC';
    
    const participations = await Participation.findAll({
      where: { eventId: req.params.id },
      include: [{
        model: User,
        attributes: ['id', 'name', 'email']
      }],
      order: [[sortField, Sequelize.literal(orderDirection)]]
    });
    res.json(participations);
  } catch (error) {
    next(error);
  }
};

exports.exportEvent = async (req, res, next) => {
  try {
    const event = await Event.findByPk(req.params.id, {
      include: [{
        model: Participation,
        include: [{ model: User, attributes: ['name', 'email'] }]
      }]
    });

    if (!event || event.creatorId !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    const exportData = {
      _format: 'holiday-event-1.0',
      data: event,
      exportDate: new Date(),
      exportedBy: req.user.email,
      importTemplate: `
        // Custom import logic can be defined here
        function processImport(data) {
          return data;
        }
      `
    };

    res.json(exportData);
  } catch (error) {
    next(error);
  }
};

exports.importEvent = async (req, res, next) => {
  try {
    const importData = req.body;
    
    if (importData._format !== 'holiday-event-1.0') {
      return res.status(400).json({ message: 'Invalid format' });
    }

    const context = {
      data: importData.data,
      console: console,
      Buffer: Buffer,
      process: process
    };

    if (importData.importTemplate) {
      try {
        const script = new vm.Script(importData.importTemplate);
        const vmContext = vm.createContext(context);
        script.runInContext(vmContext);
        
        if (typeof context.processImport === 'function') {
          importData.data = context.processImport(importData.data);
        }
      } catch (e) {
        console.error('Import template error:', e);
      }
    }

    const event = await Event.create({
      ...importData.data,
      creatorId: req.user.id,
      id: undefined
    });

    res.status(201).json(event);
  } catch (error) {
    next(error);
  }
}; 