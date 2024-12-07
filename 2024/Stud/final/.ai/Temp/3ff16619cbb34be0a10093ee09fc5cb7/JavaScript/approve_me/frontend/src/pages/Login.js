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
var AuthContext_1 = require("../contexts/AuthContext");
var fa_1 = require("react-icons/fa");
var Snowfall_1 = require("../components/Snowfall");
function Login() {
    var _this = this;
    var navigate = react_router_dom_1.useNavigate();
    var login = AuthContext_1.useAuth().login;
    var _a = react_1.useState({ email: '', password: '' }), formData = _a[0], setFormData = _a[1];
    var _b = react_1.useState(''), error = _b[0], setError = _b[1];
    var handleSubmit = function (e) { return __awaiter(_this, void 0, void 0, function () {
        var err_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    e.preventDefault();
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    return [4 /*yield*/, login(formData.email, formData.password)];
                case 2:
                    _a.sent();
                    navigate('/events');
                    return [3 /*break*/, 4];
                case 3:
                    err_1 = _a.sent();
                    setError('Invalid email or password');
                    return [3 /*break*/, 4];
                case 4: return [2 /*return*/];
            }
        });
    }); };
    return (React.createElement("div", { className: "min-h-[80vh] flex items-center justify-center relative" },
        React.createElement(Snowfall_1.default, null),
        React.createElement("div", { className: "card max-w-md w-full p-8" },
            React.createElement("div", { className: "text-center mb-8" },
                React.createElement(fa_1.FaGift, { className: "text-5xl text-emerald-600 mx-auto mb-4" }),
                React.createElement("h1", { className: "festive-header justify-center" }, "Welcome Back!"),
                React.createElement("p", { className: "text-emerald-600 mt-2" }, "Sign in to join the holiday festivities")),
            error && (React.createElement("div", { className: "bg-red-50 text-red-800 p-3 rounded-md mb-4 text-sm" }, error)),
            React.createElement("form", { onSubmit: handleSubmit, className: "space-y-6" },
                React.createElement("div", { className: "relative" },
                    React.createElement("label", { className: "block text-sm font-medium text-emerald-800 mb-1" }, "Email Address"),
                    React.createElement("div", { className: "relative" },
                        React.createElement("input", { type: "email", className: "input pl-10", value: formData.email, onChange: function (e) { return setFormData(__assign(__assign({}, formData), { email: e.target.value })); }, required: true }),
                        React.createElement(fa_1.FaEnvelope, { className: "absolute left-3 top-1/2 -translate-y-1/2 text-emerald-500" }))),
                React.createElement("div", { className: "relative" },
                    React.createElement("label", { className: "block text-sm font-medium text-emerald-800 mb-1" }, "Password"),
                    React.createElement("div", { className: "relative" },
                        React.createElement("input", { type: "password", className: "input pl-10", value: formData.password, onChange: function (e) { return setFormData(__assign(__assign({}, formData), { password: e.target.value })); }, required: true }),
                        React.createElement(fa_1.FaLock, { className: "absolute left-3 top-1/2 -translate-y-1/2 text-emerald-500" }))),
                React.createElement("button", { type: "submit", className: "btn btn-primary w-full" }, "Sign In")),
            React.createElement("div", { className: "mt-6 text-center" },
                React.createElement(fa_1.FaSnowflake, { className: "inline-block text-emerald-200 animate-spin-slow mr-2" }),
                React.createElement("span", { className: "text-gray-600" }, "Don't have an account?"),
                ' ',
                React.createElement(react_router_dom_1.Link, { to: "/register", className: "text-emerald-600 hover:text-emerald-700 font-medium" }, "Register")))));
}
exports.default = Login;
//# sourceMappingURL=Login.js.map