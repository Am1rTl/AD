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
var api_1 = require("../api");
var header_1 = require("../components/header");
function LoginPage() {
    var _this = this;
    var _a = react_1.useState(''), username = _a[0], setUsername = _a[1];
    var _b = react_1.useState(''), password = _b[0], setPassword = _b[1];
    var _c = react_1.useState(''), error = _c[0], setError = _c[1];
    var handleSubmit = function (e) { return __awaiter(_this, void 0, void 0, function () {
        var response, err_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    e.preventDefault();
                    setError('');
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, api_1.default.login(username, password)];
                case 2:
                    response = _a.sent();
                    if (response.status === 'error') {
                        setError(response.message);
                    }
                    else {
                        // Successful login - could add redirect logic here
                        console.log('Login successful');
                        window.location.href = '/';
                    }
                    return [3 /*break*/, 4];
                case 3:
                    err_1 = _a.sent();
                    setError('Failed to login. Please try again.');
                    return [3 /*break*/, 4];
                case 4: return [2 /*return*/];
            }
        });
    }); };
    return (react_1.default.createElement(react_1.default.Fragment, null,
        react_1.default.createElement(header_1.default, null),
        react_1.default.createElement("div", { className: "login-container" },
            react_1.default.createElement("form", { onSubmit: handleSubmit, className: "login-form" },
                react_1.default.createElement("h2", null, "Login"),
                error && react_1.default.createElement("div", { className: "error-message" }, error),
                react_1.default.createElement("div", { className: "form-group" },
                    react_1.default.createElement("label", { htmlFor: "username" }, "Username:"),
                    react_1.default.createElement("input", { type: "text", id: "username", value: username, onChange: function (e) { return setUsername(e.target.value); }, required: true })),
                react_1.default.createElement("div", { className: "form-group" },
                    react_1.default.createElement("label", { htmlFor: "password" }, "Password:"),
                    react_1.default.createElement("input", { type: "password", id: "password", value: password, onChange: function (e) { return setPassword(e.target.value); }, required: true })),
                react_1.default.createElement("button", { type: "submit" }, "Login"),
                react_1.default.createElement("p", { style: { marginTop: '1rem', textAlign: 'center' } },
                    "Don't have an account? ",
                    react_1.default.createElement(react_router_dom_1.Link, { to: "/register" }, "Register here"))))));
}
exports.default = LoginPage;
//# sourceMappingURL=loginPage.js.map