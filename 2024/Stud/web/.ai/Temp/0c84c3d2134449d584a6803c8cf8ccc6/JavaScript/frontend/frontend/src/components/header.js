"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var react_1 = require("react");
var react_router_dom_1 = require("react-router-dom");
var helpers_1 = require("../helpers");
function Header() {
    var isAuthenticated = helpers_1.checkAuth();
    var _a = react_1.useState(''), username = _a[0], setUsername = _a[1];
    var navigate = react_router_dom_1.useNavigate();
    var handleSearch = function (e) {
        e.preventDefault();
        if (username.trim()) {
            navigate("/user/" + username);
            setUsername('');
        }
    };
    var handleLogout = function () {
        helpers_1.logout();
        window.location.href = '/login';
        setIsAuthenticated(false);
    };
    return (react_1.default.createElement("header", { style: {
            backgroundColor: '#333',
            padding: '1rem',
            color: 'white',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
        } },
        react_1.default.createElement("div", { className: "logo" },
            react_1.default.createElement(react_router_dom_1.Link, { to: "/", style: { textDecoration: 'none', color: 'white' } },
                react_1.default.createElement("h1", { style: {
                        margin: 0,
                        fontSize: '1.5rem'
                    } }, "CodePaste"))),
        react_1.default.createElement("nav", { style: { display: 'flex', alignItems: 'center', gap: '1.5rem' } },
            isAuthenticated && (react_1.default.createElement("form", { onSubmit: handleSearch, style: { display: 'flex', gap: '0.5rem' } },
                react_1.default.createElement("input", { type: "text", placeholder: "Search by username", value: username, onChange: function (e) { return setUsername(e.target.value); }, style: {
                        padding: '0.25rem 0.5rem',
                        borderRadius: '2px',
                        border: 'none'
                    } }),
                react_1.default.createElement("button", { type: "submit", style: {
                        padding: '0.25rem 0.75rem',
                        borderRadius: '2px',
                        border: 'none`',
                        backgroundColor: '#007bff',
                        color: 'white',
                        cursor: 'pointer',
                        width: 'auto'
                    } }, "Search"))),
            react_1.default.createElement("ul", { style: {
                    listStyle: 'none',
                    margin: 0,
                    padding: 0,
                    display: 'flex',
                    gap: '1.5rem'
                } },
                react_1.default.createElement("li", null,
                    react_1.default.createElement(react_router_dom_1.Link, { to: "/", style: { color: 'white', textDecoration: 'none' } }, "Home")),
                isAuthenticated ? (react_1.default.createElement(react_1.default.Fragment, null,
                    react_1.default.createElement("li", null,
                        react_1.default.createElement(react_router_dom_1.Link, { to: "/new", style: {
                                color: 'white',
                                textDecoration: 'none',
                                backgroundColor: '#007bff',
                                padding: '0.5rem 1rem',
                                borderRadius: '4px'
                            } }, "New Paste")),
                    react_1.default.createElement("li", null,
                        react_1.default.createElement("button", { onClick: handleLogout, style: {
                                color: 'white',
                                textDecoration: 'none',
                                backgroundColor: 'transparent',
                                border: 'none',
                                cursor: 'pointer',
                                padding: 0,
                                fontSize: '1rem'
                            } }, "Logout")))) : (react_1.default.createElement(react_1.default.Fragment, null,
                    react_1.default.createElement("li", null,
                        react_1.default.createElement(react_router_dom_1.Link, { to: "/login", style: { color: 'white', textDecoration: 'none' } }, "Login")),
                    react_1.default.createElement("li", null,
                        react_1.default.createElement(react_router_dom_1.Link, { to: "/register", style: { color: 'white', textDecoration: 'none' } }, "Register"))))))));
}
exports.default = Header;
//# sourceMappingURL=header.js.map