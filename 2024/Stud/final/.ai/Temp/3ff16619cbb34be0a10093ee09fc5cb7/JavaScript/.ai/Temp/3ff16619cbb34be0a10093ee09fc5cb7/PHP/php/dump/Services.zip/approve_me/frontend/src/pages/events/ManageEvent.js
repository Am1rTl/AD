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
var LoadingSpinner_1 = require("../../components/LoadingSpinner");
var fa_1 = require("react-icons/fa");
var gi_1 = require("react-icons/gi");
var Snowfall_1 = require("../../components/Snowfall");
function ManageEvent() {
    var _this = this;
    var id = react_router_dom_1.useParams().id;
    var navigate = react_router_dom_1.useNavigate();
    var _a = react_1.useState(null), event = _a[0], setEvent = _a[1];
    var _b = react_1.useState([]), participants = _b[0], setParticipants = _b[1];
    var _c = react_1.useState(true), loading = _c[0], setLoading = _c[1];
    var _d = react_1.useState(null), importFile = _d[0], setImportFile = _d[1];
    var _e = react_1.useState(''), importError = _e[0], setImportError = _e[1];
    react_1.useEffect(function () {
        loadEventAndParticipants();
    }, [id]);
    var loadEventAndParticipants = function () { return __awaiter(_this, void 0, void 0, function () {
        var _a, eventResponse, participantsResponse, error_1;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    _b.trys.push([0, 2, 3, 4]);
                    return [4 /*yield*/, Promise.all([
                            client_1.default.get("/events/" + id),
                            client_1.default.get("/events/" + id + "/participations")
                        ])];
                case 1:
                    _a = _b.sent(), eventResponse = _a[0], participantsResponse = _a[1];
                    setEvent(eventResponse.data);
                    setParticipants(participantsResponse.data);
                    return [3 /*break*/, 4];
                case 2:
                    error_1 = _b.sent();
                    console.error('Error loading event details:', error_1);
                    navigate('/events');
                    return [3 /*break*/, 4];
                case 3:
                    setLoading(false);
                    return [7 /*endfinally*/];
                case 4: return [2 /*return*/];
            }
        });
    }); };
    var handleStatusUpdate = function (participationId, newStatus) { return __awaiter(_this, void 0, void 0, function () {
        var error_2;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _a.trys.push([0, 2, , 3]);
                    return [4 /*yield*/, client_1.default.put("/events/" + id + "/participations/" + participationId, {
                            status: newStatus
                        })];
                case 1:
                    _a.sent();
                    setParticipants(participants.map(function (participant) {
                        return participant.id === participationId
                            ? __assign(__assign({}, participant), { status: newStatus }) : participant;
                    }));
                    return [3 /*break*/, 3];
                case 2:
                    error_2 = _a.sent();
                    console.error('Error updating participation status:', error_2);
                    return [3 /*break*/, 3];
                case 3: return [2 /*return*/];
            }
        });
    }); };
    var handleExport = function () { return __awaiter(_this, void 0, void 0, function () {
        var response, blob, url, a, error_3;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    if (!event)
                        return [2 /*return*/];
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, client_1.default.get("/events/" + event.id + "/export")];
                case 2:
                    response = _a.sent();
                    blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' });
                    url = window.URL.createObjectURL(blob);
                    a = document.createElement('a');
                    a.href = url;
                    a.download = "event-" + event.id + "-export.json";
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(a);
                    return [3 /*break*/, 4];
                case 3:
                    error_3 = _a.sent();
                    console.error('Export failed:', error_3);
                    return [3 /*break*/, 4];
                case 4: return [2 /*return*/];
            }
        });
    }); };
    var handleImport = function (e) { return __awaiter(_this, void 0, void 0, function () {
        var file;
        var _a;
        return __generator(this, function (_b) {
            file = (_a = e.target.files) === null || _a === void 0 ? void 0 : _a[0];
            if (!file)
                return [2 /*return*/];
            setImportFile(file);
            return [2 /*return*/];
        });
    }); };
    var handleImportSubmit = function () { return __awaiter(_this, void 0, void 0, function () {
        var reader;
        var _this = this;
        return __generator(this, function (_a) {
            if (!importFile)
                return [2 /*return*/];
            try {
                reader = new FileReader();
                reader.onload = function (e) { return __awaiter(_this, void 0, void 0, function () {
                    var content, error_4;
                    var _a;
                    return __generator(this, function (_b) {
                        switch (_b.label) {
                            case 0:
                                _b.trys.push([0, 2, , 3]);
                                content = JSON.parse((_a = e.target) === null || _a === void 0 ? void 0 : _a.result);
                                return [4 /*yield*/, client_1.default.post('/events/import', content)];
                            case 1:
                                _b.sent();
                                navigate('/events');
                                return [3 /*break*/, 3];
                            case 2:
                                error_4 = _b.sent();
                                setImportError('Invalid import file format');
                                return [3 /*break*/, 3];
                            case 3: return [2 /*return*/];
                        }
                    });
                }); };
                reader.readAsText(importFile);
            }
            catch (error) {
                setImportError('Import failed');
            }
            return [2 /*return*/];
        });
    }); };
    if (loading)
        return React.createElement(LoadingSpinner_1.default, null);
    if (!event)
        return React.createElement(LoadingSpinner_1.default, null);
    return (React.createElement("div", { className: "space-y-6 relative" },
        React.createElement(Snowfall_1.default, null),
        React.createElement("div", { className: "card" },
            React.createElement("div", { className: "flex items-start justify-between" },
                React.createElement("div", null,
                    React.createElement("h1", { className: "festive-header flex items-center gap-2" }, event.title),
                    React.createElement("p", { className: "text-gray-600 mt-4" }, event.description)),
                React.createElement(fa_1.FaSnowflake, { className: "text-3xl text-emerald-200 animate-spin-slow" })),
            event.privateDetails && (React.createElement("div", { className: "mt-4 p-4 bg-emerald-50 rounded-md border border-emerald-200" },
                React.createElement("h4", { className: "text-sm font-medium text-emerald-800 flex items-center gap-2" },
                    React.createElement(gi_1.GiPartyPopper, { className: "text-emerald-600" }),
                    "Private Details"),
                React.createElement("p", { className: "text-sm text-emerald-700 mt-1" }, event.privateDetails))),
            React.createElement("p", { className: "text-sm text-gray-500 mt-4 flex items-center gap-2" },
                React.createElement(fa_1.FaCalendarAlt, { className: "text-emerald-500" }),
                new Date(event.date).toLocaleString()),
            React.createElement("div", { className: "flex gap-4 mt-6" },
                React.createElement("button", { onClick: handleExport, className: "btn btn-secondary flex items-center gap-2" },
                    React.createElement(fa_1.FaFileExport, null),
                    "Export Event"),
                React.createElement("div", { className: "relative" },
                    React.createElement("input", { type: "file", accept: ".json", onChange: handleImport, className: "hidden", id: "import-file" }),
                    React.createElement("label", { htmlFor: "import-file", className: "btn btn-secondary flex items-center gap-2 cursor-pointer" },
                        React.createElement(fa_1.FaFileImport, null),
                        "Import Event"))),
            importFile && (React.createElement("div", { className: "mt-4" },
                React.createElement("p", { className: "text-sm text-emerald-600" },
                    "Selected file: ",
                    importFile.name),
                React.createElement("button", { onClick: handleImportSubmit, className: "btn btn-primary mt-2" }, "Process Import"))),
            importError && (React.createElement("div", { className: "mt-4 text-red-600 text-sm" }, importError))),
        React.createElement("div", { className: "card" },
            React.createElement("div", { className: "flex items-center gap-2 mb-6" },
                React.createElement(fa_1.FaUserFriends, { className: "text-2xl text-emerald-600" }),
                React.createElement("h2", { className: "text-xl font-semibold text-emerald-800" }, "Applications")),
            participants.length === 0 ? (React.createElement("div", { className: "text-center py-8" },
                React.createElement(fa_1.FaSnowflake, { className: "text-5xl text-emerald-200 mx-auto mb-3 animate-spin-slow" }),
                React.createElement("p", { className: "text-gray-500" }, "No applications yet."))) : (React.createElement("div", { className: "overflow-x-auto" },
                React.createElement("table", { className: "min-w-full divide-y divide-emerald-200" },
                    React.createElement("thead", { className: "bg-emerald-50" },
                        React.createElement("tr", null,
                            React.createElement("th", { className: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" }, "Name"),
                            React.createElement("th", { className: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" }, "Email"),
                            React.createElement("th", { className: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" }, "Status"),
                            React.createElement("th", { className: "px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider" }, "Actions"))),
                    React.createElement("tbody", { className: "divide-y divide-emerald-100" }, participants.map(function (participant) {
                        var _a, _b;
                        return (React.createElement("tr", { key: participant.id, className: "hover:bg-emerald-50 transition-colors" },
                            React.createElement("td", { className: "px-6 py-4 whitespace-nowrap" }, ((_a = participant.User) === null || _a === void 0 ? void 0 : _a.name) || 'Unknown User'),
                            React.createElement("td", { className: "px-6 py-4 whitespace-nowrap" }, ((_b = participant.User) === null || _b === void 0 ? void 0 : _b.email) || 'No email'),
                            React.createElement("td", { className: "px-6 py-4 whitespace-nowrap" },
                                React.createElement("span", { className: "px-2 py-1 rounded-full text-xs font-medium\n                        " + (participant.status === 'approved' ? 'bg-emerald-100 text-emerald-800' :
                                        participant.status === 'rejected' ? 'bg-red-100 text-red-800' :
                                            'bg-yellow-100 text-yellow-800') }, participant.status)),
                            React.createElement("td", { className: "px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2" }, participant.status === 'pending' && (React.createElement(React.Fragment, null,
                                React.createElement("button", { onClick: function () { return handleStatusUpdate(participant.id, 'approved'); }, className: "text-emerald-600 hover:text-emerald-900 flex items-center gap-1" },
                                    React.createElement(fa_1.FaCheck, null),
                                    " Approve"),
                                React.createElement("button", { onClick: function () { return handleStatusUpdate(participant.id, 'rejected'); }, className: "text-red-600 hover:text-red-900 flex items-center gap-1" },
                                    React.createElement(fa_1.FaTimes, null),
                                    " Reject"))))));
                    }))))))));
}
exports.default = ManageEvent;
//# sourceMappingURL=ManageEvent.js.map