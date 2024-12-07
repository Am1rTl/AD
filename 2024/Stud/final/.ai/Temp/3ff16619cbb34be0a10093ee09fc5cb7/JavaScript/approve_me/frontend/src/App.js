"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var react_router_dom_1 = require("react-router-dom");
var AuthContext_1 = require("./contexts/AuthContext");
var Layout_1 = require("./components/Layout");
var Login_1 = require("./pages/Login");
var Register_1 = require("./pages/Register");
var EventList_1 = require("./pages/events/EventList");
var CreateEvent_1 = require("./pages/events/CreateEvent");
var ManageEvent_1 = require("./pages/events/ManageEvent");
var PrivateRoute_1 = require("./components/PrivateRoute");
var BulkImport_1 = require("./pages/events/BulkImport");
function App() {
    return (React.createElement(AuthContext_1.AuthProvider, null,
        React.createElement(react_router_dom_1.BrowserRouter, null,
            React.createElement(react_router_dom_1.Routes, null,
                React.createElement(react_router_dom_1.Route, { element: React.createElement(Layout_1.default, null) },
                    React.createElement(react_router_dom_1.Route, { index: true, element: React.createElement(react_router_dom_1.Navigate, { to: "/events", replace: true }) }),
                    React.createElement(react_router_dom_1.Route, { path: "login", element: React.createElement(Login_1.default, null) }),
                    React.createElement(react_router_dom_1.Route, { path: "register", element: React.createElement(Register_1.default, null) }),
                    React.createElement(react_router_dom_1.Route, { path: "events", element: React.createElement(PrivateRoute_1.default, null,
                            React.createElement(EventList_1.default, null)) }),
                    React.createElement(react_router_dom_1.Route, { path: "events/create", element: React.createElement(PrivateRoute_1.default, null,
                            React.createElement(CreateEvent_1.default, null)) }),
                    React.createElement(react_router_dom_1.Route, { path: "events/manage/:id", element: React.createElement(PrivateRoute_1.default, null,
                            React.createElement(ManageEvent_1.default, null)) }),
                    React.createElement(react_router_dom_1.Route, { path: "events/import", element: React.createElement(PrivateRoute_1.default, null,
                            React.createElement(BulkImport_1.default, null)) }))))));
}
exports.default = App;
//# sourceMappingURL=App.js.map