"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
var react_1 = require("react");
var react_router_dom_1 = require("react-router-dom");
var client_1 = require("../../api/client");
var AuthContext_1 = require("../../contexts/AuthContext");
var LoadingSpinner_1 = require("../../components/LoadingSpinner");
var fa_1 = require("react-icons/fa");
var Snowfall_1 = require("../../components/Snowfall");
function EventList() {
    var _this = this;
    var _a = react_1.useState([]), events = _a[0], setEvents = _a[1];
    var _b = react_1.useState(true), loading = _b[0], setLoading = _b[1];
    var user = AuthContext_1.useAuth().user;
    react_1.useEffect(function () {
        loadEvents();
    }, []);
    var loadEvents = function () { return __awaiter(_this, void 0, void 0, function () {
        var response, eventsData, eventsWithStatus, error_1;
        var _this = this;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _a.trys.push([0, 3, 4, 5]);
                    return [4 /*yield*/, client_1.default.get('/events')];
                case 1:
                    response = _a.sent();
                    eventsData = response.data;
                    return [4 /*yield*/, Promise.all(eventsData.map(function (event) { return __awaiter(_this, void 0, void 0, function () {
                            var statusResponse;
                            return __generator(this, function (_a) {
                                switch (_a.label) {
                                    case 0:
                                        if (event.creatorId === (user === null || user === void 0 ? void 0 : user.id)) {
                                            return [2 /*return*/, __assign(__assign({}, event), { status: 'creator' })];
                                        }
                                        return [4 /*yield*/, client_1.default.get("/events/" + event.id + "/status")];
                                    case 1:
                                        statusResponse = _a.sent();
                                        return [2 /*return*/, __assign(__assign({}, event), { status: statusResponse.data.status })];
                                }
                            });
                        }); }))];
                case 2:
                    eventsWithStatus = _a.sent();
                    setEvents(eventsWithStatus);
                    return [3 /*break*/, 5];
                case 3:
                    error_1 = _a.sent();
                    console.error('Error loading events:', error_1);
                    return [3 /*break*/, 5];
                case 4:
                    setLoading(false);
                    return [7 /*endfinally*/];
                case 5: return [2 /*return*/];
            }
        });
    }); };
    var handleApply = function (eventId) { return __awaiter(_this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, client_1.default.post("/events/" + eventId + "/apply")];
                case 1:
                    _a.sent();
                    setEvents(events.map(function (event) {
                        return event.id === eventId
                            ? __assign(__assign({}, event), { status: 'pending' }) : event;
                    }));
                    return [2 /*return*/];
            }
        });
    }); };
    var getStatusBadgeClass = function (status) {
        switch (status) {
            case 'not_applied':
                return 'bg-gray-200 text-gray-500';
            case 'pending':
                return 'bg-yellow-100 text-yellow-800';
            case 'approved':
                return 'bg-green-100 text-green-800';
            case 'declined':
                return 'bg-red-100 text-red-800';
            case 'creator':
                return 'bg-blue-100 text-blue-800';
            default:
                return '';
        }
    };
    if (loading)
        return React.createElement(LoadingSpinner_1.default, null);
    return (React.createElement("div", { className: "space-y-6 relative" },
        React.createElement(Snowfall_1.default, null),
        React.createElement("div", { className: "flex justify-between items-center mb-6" },
            React.createElement("h1", { className: "festive-header" }, "Holiday Events"),
            React.createElement("div", { className: "flex gap-2" },
                React.createElement(react_router_dom_1.Link, { to: "/events/import", className: "btn btn-secondary flex items-center gap-2" },
                    React.createElement(fa_1.FaFileImport, null),
                    "Import Events"),
                React.createElement(react_router_dom_1.Link, { to: "/events/create", className: "btn btn-primary flex items-center gap-2" },
                    React.createElement(fa_1.FaPlus, null),
                    "Create Event"))),
        React.createElement("div", { className: "grid gap-6 md:grid-cols-2 lg:grid-cols-3" }, events.map(function (event) { return (React.createElement("div", { key: event.id, className: "card group" },
            React.createElement("div", { className: "absolute top-2 right-2" },
                React.createElement(fa_1.FaSnowflake, { className: "text-emerald-200 text-xl group-hover:animate-spin-slow" })),
            React.createElement("div", { className: "flex justify-between items-start" },
                React.createElement("h3", { className: "text-lg font-semibold" }, event.title),
                React.createElement("span", { className: "px-2 py-1 rounded-full text-xs font-medium " + getStatusBadgeClass(event.status) }, event.status)),
            React.createElement("p", { className: "text-gray-600 mt-2" }, event.description),
            event.privateDetails && (React.createElement("div", { className: "mt-4 p-3 bg-green-50 rounded-md" },
                React.createElement("h4", { className: "text-sm font-medium text-green-800" }, "Private Details"),
                React.createElement("p", { className: "text-sm text-green-700" }, event.privateDetails))),
            React.createElement("p", { className: "text-sm text-gray-500 mt-2" }, new Date(event.date).toLocaleString()),
            React.createElement("div", { className: "mt-4" }, event.status === 'creator' ? (React.createElement(react_router_dom_1.Link, { to: "/events/manage/" + event.id, className: "inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500" }, "Manage Applications")) : (React.createElement("button", { onClick: function () { return handleApply(event.id); }, disabled: event.status !== 'not_applied', className: "inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white\n                    " + (event.status === 'not_applied'
                    ? 'bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500'
                    : 'bg-gray-400 cursor-not-allowed') }, event.status === 'not_applied' ? 'Apply' : event.status))))); }))));
}
exports.default = EventList;
//# sourceMappingURL=EventList.js.map