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
var react_router_dom_1 = require("react-router-dom");
var AuthContext_1 = require("../contexts/AuthContext");
var fa_1 = require("react-icons/fa");
function Navbar() {
    var _this = this;
    var _a = AuthContext_1.useAuth(), user = _a.user, logout = _a.logout;
    var navigate = react_router_dom_1.useNavigate();
    var handleLogout = function () { return __awaiter(_this, void 0, void 0, function () {
        var error_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    _a.trys.push([0, 2, , 3]);
                    return [4 /*yield*/, logout()];
                case 1:
                    _a.sent();
                    navigate('/login');
                    return [3 /*break*/, 3];
                case 2:
                    error_1 = _a.sent();
                    console.error('Logout failed:', error_1);
                    return [3 /*break*/, 3];
                case 3: return [2 /*return*/];
            }
        });
    }); };
    return (React.createElement("nav", { className: "bg-gradient-to-r from-emerald-600 to-emerald-800 shadow-lg relative" },
        React.createElement("div", { className: "absolute inset-0 overflow-hidden pointer-events-none z-0" },
            React.createElement("div", { className: "absolute top-1 left-4 text-emerald-300/30 text-xl" },
                React.createElement(fa_1.FaSnowflake, { className: "animate-spin-slow" })),
            React.createElement("div", { className: "absolute top-2 right-8 text-emerald-300/30 text-sm" },
                React.createElement(fa_1.FaSnowflake, { className: "animate-spin-slow", style: { animationDuration: '4s' } })),
            React.createElement("div", { className: "absolute bottom-1 left-1/4 text-emerald-300/30 text-lg" },
                React.createElement(fa_1.FaSnowflake, { className: "animate-spin-slow", style: { animationDuration: '6s' } }))),
        React.createElement("div", { className: "max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10" },
            React.createElement("div", { className: "flex items-center justify-between h-16" },
                React.createElement("div", { className: "flex items-center" },
                    React.createElement(react_router_dom_1.Link, { to: "/", className: "flex items-center gap-2 text-white font-bold text-xl hover:text-emerald-100 transition-colors" },
                        React.createElement(fa_1.FaGift, { className: "text-2xl" }),
                        React.createElement("span", null, "Holiday Events"))),
                React.createElement("div", { className: "flex items-center gap-6" }, user ? (React.createElement(React.Fragment, null,
                    React.createElement("div", { className: "flex items-center gap-2 text-emerald-100" },
                        React.createElement(fa_1.FaUser, { className: "text-emerald-200" }),
                        React.createElement("span", null, user.name)),
                    React.createElement("button", { onClick: handleLogout, className: "flex items-center gap-2 px-4 py-2 rounded-md bg-emerald-700 text-white hover:bg-emerald-600 transition-colors duration-200" },
                        React.createElement(fa_1.FaSignOutAlt, null),
                        React.createElement("span", null, "Sign Out")))) : (React.createElement("div", { className: "space-x-4" },
                    React.createElement(react_router_dom_1.Link, { to: "/login", className: "text-emerald-100 hover:text-white transition-colors duration-200" }, "Sign In"),
                    React.createElement(react_router_dom_1.Link, { to: "/register", className: "px-4 py-2 rounded-md bg-emerald-700 text-white hover:bg-emerald-600 transition-colors duration-200" }, "Register")))))),
        React.createElement("div", { className: "h-1 bg-gradient-to-r from-emerald-200/20 via-emerald-100/40 to-emerald-200/20" })));
}
exports.default = Navbar;
//# sourceMappingURL=Navbar.js.map