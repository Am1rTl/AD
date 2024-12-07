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
var __spreadArray = (this && this.__spreadArray) || function (to, from) {
    for (var i = 0, il = from.length, j = to.length; i < il; i++, j++)
        to[j] = from[i];
    return to;
};
Object.defineProperty(exports, "__esModule", { value: true });
var js_1 = require("@eslint/js");
var globals_1 = require("globals");
var eslint_plugin_react_hooks_1 = require("eslint-plugin-react-hooks");
var eslint_plugin_react_refresh_1 = require("eslint-plugin-react-refresh");
var typescript_eslint_1 = require("typescript-eslint");
exports.default = typescript_eslint_1.default.config({ ignores: ['dist'] }, {
    extends: __spreadArray([js_1.default.configs.recommended], typescript_eslint_1.default.configs.recommended),
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
        ecmaVersion: 2020,
        globals: globals_1.default.browser,
    },
    plugins: {
        'react-hooks': eslint_plugin_react_hooks_1.default,
        'react-refresh': eslint_plugin_react_refresh_1.default,
    },
    rules: __assign(__assign({}, eslint_plugin_react_hooks_1.default.configs.recommended.rules), { 'react-refresh/only-export-components': [
            'warn',
            { allowConstantExport: true },
        ] }),
});
//# sourceMappingURL=eslint.config.js.map