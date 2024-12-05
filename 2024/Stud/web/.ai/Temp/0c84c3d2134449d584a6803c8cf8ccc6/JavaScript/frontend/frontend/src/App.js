"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var react_router_dom_1 = require("react-router-dom");
var loginPage_1 = require("./views/loginPage");
var pastePage_1 = require("./views/pastePage");
var registerPage_1 = require("./views/registerPage");
var createPastePage_1 = require("./views/createPastePage");
var helpers_1 = require("./helpers");
var myPastePage_1 = require("./views/myPastePage");
var userPastePage_1 = require("./views/userPastePage");
function App() {
    var isAuthenticated = helpers_1.checkAuth();
    return (React.createElement(react_router_dom_1.BrowserRouter, null,
        React.createElement(react_router_dom_1.Routes, null,
            React.createElement(react_router_dom_1.Route, { path: "/paste/:pasteId", element: isAuthenticated ? React.createElement(pastePage_1.default, null) : React.createElement(react_router_dom_1.Navigate, { to: "/login" }) }),
            React.createElement(react_router_dom_1.Route, { path: "/new", element: isAuthenticated ? React.createElement(createPastePage_1.default, null) : React.createElement(react_router_dom_1.Navigate, { to: "/login" }) }),
            React.createElement(react_router_dom_1.Route, { path: "/login", element: !isAuthenticated ? React.createElement(loginPage_1.default, null) : React.createElement(react_router_dom_1.Navigate, { to: "/" }) }),
            React.createElement(react_router_dom_1.Route, { path: "/register", element: !isAuthenticated ? React.createElement(registerPage_1.default, null) : React.createElement(react_router_dom_1.Navigate, { to: "/" }) }),
            React.createElement(react_router_dom_1.Route, { path: "/", element: isAuthenticated ? React.createElement(myPastePage_1.default, null) : React.createElement(react_router_dom_1.Navigate, { to: "/login" }) }),
            React.createElement(react_router_dom_1.Route, { path: "/user/:username", element: isAuthenticated ? React.createElement(userPastePage_1.default, null) : React.createElement(react_router_dom_1.Navigate, { to: "/login" }) }))));
}
exports.default = App;
//# sourceMappingURL=App.js.map