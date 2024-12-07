"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var react_router_dom_1 = require("react-router-dom");
var Navbar_tsx_1 = require("./Navbar.tsx");
function Layout() {
    return (React.createElement("div", { className: "min-h-screen bg-gray-50" },
        React.createElement(Navbar_tsx_1.default, null),
        React.createElement("main", { className: "container mx-auto px-4 py-8" },
            React.createElement(react_router_dom_1.Outlet, null))));
}
exports.default = Layout;
//# sourceMappingURL=Layout.js.map