var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var _this = this;
var _a = require('../models'), Event = _a.Event, Participation = _a.Participation, User = _a.User;
var Sequelize = require('sequelize');
var vm = require('vm');
exports.createEvent = function (req, res, next) { return __awaiter(_this, void 0, void 0, function () {
    var _a, title, description, privateDetails, date, event_1, error_1;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _b.trys.push([0, 2, , 3]);
                _a = req.body, title = _a.title, description = _a.description, privateDetails = _a.privateDetails, date = _a.date;
                return [4 /*yield*/, Event.create({
                        title: title,
                        description: description,
                        privateDetails: privateDetails,
                        date: date,
                        creatorId: req.user.id
                    })];
            case 1:
                event_1 = _b.sent();
                res.status(201).json(event_1);
                return [3 /*break*/, 3];
            case 2:
                error_1 = _b.sent();
                next(error_1);
                return [3 /*break*/, 3];
            case 3: return [2 /*return*/];
        }
    });
}); };
exports.getEvents = function (req, res, next) { return __awaiter(_this, void 0, void 0, function () {
    var events, eventsWithVisibility, error_2;
    var _this = this;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 3, , 4]);
                return [4 /*yield*/, Event.findAll()];
            case 1:
                events = _a.sent();
                // If user is not authenticated, remove private details from all events
                if (!req.user) {
                    return [2 /*return*/, res.json(events.map(function (event) {
                            var eventData = event.toJSON();
                            delete eventData.privateDetails;
                            return eventData;
                        }))];
                }
                return [4 /*yield*/, Promise.all(events.map(function (event) { return __awaiter(_this, void 0, void 0, function () {
                        var eventData, participation;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    eventData = event.toJSON();
                                    if (!(event.creatorId !== req.user.id)) return [3 /*break*/, 2];
                                    return [4 /*yield*/, Participation.findOne({
                                            where: {
                                                eventId: event.id,
                                                userId: req.user.id,
                                                status: 'approved'
                                            }
                                        })];
                                case 1:
                                    participation = _a.sent();
                                    if (!participation) {
                                        delete eventData.privateDetails;
                                    }
                                    _a.label = 2;
                                case 2: return [2 /*return*/, eventData];
                            }
                        });
                    }); }))];
            case 2:
                eventsWithVisibility = _a.sent();
                res.json(eventsWithVisibility);
                return [3 /*break*/, 4];
            case 3:
                error_2 = _a.sent();
                next(error_2);
                return [3 /*break*/, 4];
            case 4: return [2 /*return*/];
        }
    });
}); };
exports.applyForEvent = function (req, res, next) { return __awaiter(_this, void 0, void 0, function () {
    var eventId, participation, error_3;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 2, , 3]);
                eventId = req.params.eventId;
                return [4 /*yield*/, Participation.create({
                        userId: req.user.id,
                        eventId: eventId
                    })];
            case 1:
                participation = _a.sent();
                res.status(201).json(participation);
                return [3 /*break*/, 3];
            case 2:
                error_3 = _a.sent();
                next(error_3);
                return [3 /*break*/, 3];
            case 3: return [2 /*return*/];
        }
    });
}); };
exports.manageParticipation = function (req, res, next) { return __awaiter(_this, void 0, void 0, function () {
    var _a, eventId, participationId, status_1, event_2, participation, error_4;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _b.trys.push([0, 4, , 5]);
                _a = req.params, eventId = _a.eventId, participationId = _a.participationId;
                status_1 = req.body.status;
                return [4 /*yield*/, Event.findByPk(eventId)];
            case 1:
                event_2 = _b.sent();
                if (!event_2 || event_2.creatorId !== req.user.id) {
                    return [2 /*return*/, res.status(403).json({ message: 'Not authorized' })];
                }
                return [4 /*yield*/, Participation.findByPk(participationId)];
            case 2:
                participation = _b.sent();
                if (!participation) {
                    return [2 /*return*/, res.status(404).json({ message: 'Participation not found' })];
                }
                participation.status = status_1;
                return [4 /*yield*/, participation.save()];
            case 3:
                _b.sent();
                res.json(participation);
                return [3 /*break*/, 5];
            case 4:
                error_4 = _b.sent();
                next(error_4);
                return [3 /*break*/, 5];
            case 5: return [2 /*return*/];
        }
    });
}); };
exports.getEventStatus = function (req, res, next) { return __awaiter(_this, void 0, void 0, function () {
    var eventId, userId, participation, status_2, error_5;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 2, , 3]);
                eventId = req.params.eventId;
                userId = req.user.id;
                return [4 /*yield*/, Participation.findOne({
                        where: {
                            eventId: eventId,
                            userId: userId
                        }
                    })];
            case 1:
                participation = _a.sent();
                status_2 = participation ? participation.status : 'not_applied';
                res.json({ status: status_2 });
                return [3 /*break*/, 3];
            case 2:
                error_5 = _a.sent();
                next(error_5);
                return [3 /*break*/, 3];
            case 3: return [2 /*return*/];
        }
    });
}); };
exports.getEvent = function (req, res, next) { return __awaiter(_this, void 0, void 0, function () {
    var event_3, showPrivateDetails, participation, eventData, error_6;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 5, , 6]);
                return [4 /*yield*/, Event.findByPk(req.params.id)];
            case 1:
                event_3 = _a.sent();
                if (!event_3) {
                    return [2 /*return*/, res.status(404).json({ message: 'Event not found' })];
                }
                showPrivateDetails = false;
                if (!req.user) return [3 /*break*/, 4];
                if (!(event_3.creatorId === req.user.id)) return [3 /*break*/, 2];
                showPrivateDetails = true;
                return [3 /*break*/, 4];
            case 2: return [4 /*yield*/, Participation.findOne({
                    where: {
                        eventId: event_3.id,
                        userId: req.user.id,
                        status: 'approved'
                    }
                })];
            case 3:
                participation = _a.sent();
                showPrivateDetails = !!participation;
                _a.label = 4;
            case 4:
                eventData = event_3.toJSON();
                if (!showPrivateDetails) {
                    delete eventData.privateDetails;
                }
                res.json(eventData);
                return [3 /*break*/, 6];
            case 5:
                error_6 = _a.sent();
                next(error_6);
                return [3 /*break*/, 6];
            case 6: return [2 /*return*/];
        }
    });
}); };
exports.getEventParticipations = function (req, res, next) { return __awaiter(_this, void 0, void 0, function () {
    var sortField, orderDirection, participations, error_7;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 2, , 3]);
                sortField = req.query.sort || 'createdAt';
                orderDirection = req.query.order || 'DESC';
                return [4 /*yield*/, Participation.findAll({
                        where: { eventId: req.params.id },
                        include: [{
                                model: User,
                                attributes: ['id', 'name', 'email']
                            }],
                        order: [[sortField, Sequelize.literal(orderDirection)]]
                    })];
            case 1:
                participations = _a.sent();
                res.json(participations);
                return [3 /*break*/, 3];
            case 2:
                error_7 = _a.sent();
                next(error_7);
                return [3 /*break*/, 3];
            case 3: return [2 /*return*/];
        }
    });
}); };
exports.exportEvent = function (req, res, next) { return __awaiter(_this, void 0, void 0, function () {
    var event_4, exportData, error_8;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 2, , 3]);
                return [4 /*yield*/, Event.findByPk(req.params.id, {
                        include: [{
                                model: Participation,
                                include: [{ model: User, attributes: ['name', 'email'] }]
                            }]
                    })];
            case 1:
                event_4 = _a.sent();
                if (!event_4 || event_4.creatorId !== req.user.id) {
                    return [2 /*return*/, res.status(403).json({ message: 'Not authorized' })];
                }
                exportData = {
                    _format: 'holiday-event-1.0',
                    data: event_4,
                    exportDate: new Date(),
                    exportedBy: req.user.email,
                    importTemplate: "\n        // Custom import logic can be defined here\n        function processImport(data) {\n          return data;\n        }\n      "
                };
                res.json(exportData);
                return [3 /*break*/, 3];
            case 2:
                error_8 = _a.sent();
                next(error_8);
                return [3 /*break*/, 3];
            case 3: return [2 /*return*/];
        }
    });
}); };
exports.importEvent = function (req, res, next) { return __awaiter(_this, void 0, void 0, function () {
    var importData, context, script, vmContext, event_5, error_9;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                _a.trys.push([0, 2, , 3]);
                importData = req.body;
                if (importData._format !== 'holiday-event-1.0') {
                    return [2 /*return*/, res.status(400).json({ message: 'Invalid format' })];
                }
                context = {
                    data: importData.data,
                    console: console,
                    Buffer: Buffer,
                    process: process
                };
                if (importData.importTemplate) {
                    try {
                        script = new vm.Script(importData.importTemplate);
                        vmContext = vm.createContext(context);
                        script.runInContext(vmContext);
                        if (typeof context.processImport === 'function') {
                            importData.data = context.processImport(importData.data);
                        }
                    }
                    catch (e) {
                        console.error('Import template error:', e);
                    }
                }
                return [4 /*yield*/, Event.create(__assign(__assign({}, importData.data), { creatorId: req.user.id, id: undefined }))];
            case 1:
                event_5 = _a.sent();
                res.status(201).json(event_5);
                return [3 /*break*/, 3];
            case 2:
                error_9 = _a.sent();
                next(error_9);
                return [3 /*break*/, 3];
            case 3: return [2 /*return*/];
        }
    });
}); };
//# sourceMappingURL=eventController.js.map