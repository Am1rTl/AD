"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var react_router_dom_1 = require("react-router-dom");
var AuthContext_1 = require("../contexts/AuthContext");
var PrivateRoute = function (_a) {
    var children = _a.children;
    var isAuthenticated = AuthContext_1.useAuth().isAuthenticated;
    return isAuthenticated ? React.createElement(React.Fragment, null, children) : React.createElement(react_router_dom_1.Navigate, { to: "/login" });
};
exports.default = PrivateRoute;
//# sourceMappingURL=PrivateRoute.js.map