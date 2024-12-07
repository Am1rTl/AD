"use strict";
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
var header_1 = require("../components/header");
var api_1 = require("../api");
function MyPastePage() {
    var _this = this;
    var _a = react_1.useState([]), pastes = _a[0], setPastes = _a[1];
    var _b = react_1.useState(null), error = _b[0], setError = _b[1];
    var _c = react_1.useState(true), loading = _c[0], setLoading = _c[1];
    react_1.useEffect(function () {
        var fetchPastes = function () { return __awaiter(_this, void 0, void 0, function () {
            var response, err_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, 3, 4]);
                        return [4 /*yield*/, api_1.default.getMyNotes()];
                    case 1:
                        response = _a.sent();
                        console.log(response);
                        if (response.status === "success") {
                            setPastes(response.data);
                        }
                        else {
                            setError(response.message);
                        }
                        return [3 /*break*/, 4];
                    case 2:
                        err_1 = _a.sent();
                        console.log(err_1);
                        setError("Failed to load pastes");
                        return [3 /*break*/, 4];
                    case 3:
                        setLoading(false);
                        return [7 /*endfinally*/];
                    case 4: return [2 /*return*/];
                }
            });
        }); };
        fetchPastes();
    }, []);
    var handleDelete = function (id) { return __awaiter(_this, void 0, void 0, function () {
        var response, err_2;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _a.trys.push([0, 2, , 3]);
                    return [4 /*yield*/, api_1.default.deleteNote(id)];
                case 1:
                    response = _a.sent();
                    if (response.status === "success") {
                        setPastes(pastes.filter(function (paste) { return paste.id !== id; }));
                    }
                    else {
                        setError(response.message);
                    }
                    return [3 /*break*/, 3];
                case 2:
                    err_2 = _a.sent();
                    setError("Failed to delete paste");
                    return [3 /*break*/, 3];
                case 3: return [2 /*return*/];
            }
        });
    }); };
    if (loading) {
        return (react_1.default.createElement(react_1.default.Fragment, null,
            react_1.default.createElement(header_1.default, null),
            react_1.default.createElement("div", { style: { textAlign: 'center', padding: '2rem' } },
                react_1.default.createElement("p", null, "Loading..."))));
    }
    if (error) {
        return (react_1.default.createElement(react_1.default.Fragment, null,
            react_1.default.createElement(header_1.default, null),
            react_1.default.createElement("div", { style: { textAlign: 'center', padding: '2rem' } },
                react_1.default.createElement("p", null,
                    "Error: ",
                    error))));
    }
    return (react_1.default.createElement(react_1.default.Fragment, null,
        react_1.default.createElement(header_1.default, null),
        react_1.default.createElement("div", { style: { maxWidth: '1200px', margin: '2rem auto', padding: '0 1rem' } },
            react_1.default.createElement("h2", null, "My Pastes"),
            pastes.length === 0 ? (react_1.default.createElement("p", null,
                "You haven't created any pastes yet. ",
                react_1.default.createElement(react_router_dom_1.Link, { to: "/new" }, "Create one now!"))) : (react_1.default.createElement("div", { style: { display: 'grid', gap: '1rem' } }, pastes.map(function (paste) { return (react_1.default.createElement("div", { key: paste.id, style: {
                    border: '1px solid #ccc',
                    borderRadius: '4px',
                    padding: '1rem',
                    backgroundColor: '#f9f9f9'
                } },
                react_1.default.createElement("div", { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } },
                    react_1.default.createElement("h3", { style: { margin: 0 } },
                        react_1.default.createElement(react_router_dom_1.Link, { to: "/paste/" + paste.id, style: { textDecoration: 'none', color: '#333' } },
                            "Paste ",
                            paste.id)),
                    react_1.default.createElement("div", { style: { display: 'flex', alignItems: 'center', gap: '1rem' } },
                        react_1.default.createElement("span", null,
                            "Language: ",
                            paste.language),
                        react_1.default.createElement("button", { onClick: function () { return handleDelete(paste.id); }, style: {
                                width: '32px',
                                height: '32px',
                                padding: '4px',
                                border: '1px solid #dc3545',
                                borderRadius: '4px',
                                backgroundColor: '#dc3545',
                                color: 'white',
                                cursor: 'pointer',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center'
                            }, title: "Delete paste" },
                            react_1.default.createElement("svg", { width: "16", height: "16", viewBox: "0 0 16 16", fill: "currentColor" },
                                react_1.default.createElement("path", { d: "M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z" }),
                                react_1.default.createElement("path", { fillRule: "evenodd", d: "M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4L4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118z" }))))),
                react_1.default.createElement("div", { style: { marginTop: '0.5rem', fontSize: '0.9rem', color: '#666' } }, paste.private && react_1.default.createElement("span", null, "\uD83D\uDD12 Private")))); }))))));
}
exports.default = MyPastePage;
//# sourceMappingURL=myPastePage.js.map