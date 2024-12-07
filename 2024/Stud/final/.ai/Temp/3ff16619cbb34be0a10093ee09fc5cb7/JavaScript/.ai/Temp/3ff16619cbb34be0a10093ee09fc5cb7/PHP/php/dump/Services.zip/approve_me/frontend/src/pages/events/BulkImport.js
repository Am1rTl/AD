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
var fa_1 = require("react-icons/fa");
var client_1 = require("../../api/client");
function BulkImport() {
    var _this = this;
    var navigate = react_router_dom_1.useNavigate();
    var _a = react_1.useState(null), files = _a[0], setFiles = _a[1];
    var _b = react_1.useState(''), template = _b[0], setTemplate = _b[1];
    var _c = react_1.useState(''), error = _c[0], setError = _c[1];
    var handleImport = function () { return __awaiter(_this, void 0, void 0, function () {
        var _loop_1, i, error_1;
        var _this = this;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    if (!files)
                        return [2 /*return*/];
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 6, , 7]);
                    _loop_1 = function (i) {
                        var file, reader;
                        return __generator(this, function (_b) {
                            switch (_b.label) {
                                case 0:
                                    file = files[i];
                                    reader = new FileReader();
                                    return [4 /*yield*/, new Promise(function (resolve, reject) {
                                            reader.onload = function (e) { return __awaiter(_this, void 0, void 0, function () {
                                                var content, error_2;
                                                var _a;
                                                return __generator(this, function (_b) {
                                                    switch (_b.label) {
                                                        case 0:
                                                            _b.trys.push([0, 2, , 3]);
                                                            content = JSON.parse((_a = e.target) === null || _a === void 0 ? void 0 : _a.result);
                                                            // Add custom import template if provided
                                                            if (template) {
                                                                content.importTemplate = template;
                                                            }
                                                            return [4 /*yield*/, client_1.default.post('/events/import', content)];
                                                        case 1:
                                                            _b.sent();
                                                            resolve(null);
                                                            return [3 /*break*/, 3];
                                                        case 2:
                                                            error_2 = _b.sent();
                                                            reject(error_2);
                                                            return [3 /*break*/, 3];
                                                        case 3: return [2 /*return*/];
                                                    }
                                                });
                                            }); };
                                            reader.onerror = reject;
                                            reader.readAsText(file);
                                        })];
                                case 1:
                                    _b.sent();
                                    return [2 /*return*/];
                            }
                        });
                    };
                    i = 0;
                    _a.label = 2;
                case 2:
                    if (!(i < files.length)) return [3 /*break*/, 5];
                    return [5 /*yield**/, _loop_1(i)];
                case 3:
                    _a.sent();
                    _a.label = 4;
                case 4:
                    i++;
                    return [3 /*break*/, 2];
                case 5:
                    navigate('/events');
                    return [3 /*break*/, 7];
                case 6:
                    error_1 = _a.sent();
                    setError('Import failed. Please check your files and template.');
                    return [3 /*break*/, 7];
                case 7: return [2 /*return*/];
            }
        });
    }); };
    return (React.createElement("div", { className: "card max-w-2xl mx-auto" },
        React.createElement("h1", { className: "festive-header flex items-center gap-2" },
            React.createElement(fa_1.FaFileImport, { className: "text-emerald-600" }),
            "Bulk Import Events"),
        React.createElement("div", { className: "mt-6 space-y-6" },
            React.createElement("div", null,
                React.createElement("label", { className: "block text-sm font-medium text-emerald-800 mb-2" }, "Select Event Files"),
                React.createElement("input", { type: "file", accept: ".json", multiple: true, onChange: function (e) { return setFiles(e.target.files); }, className: "block w-full text-sm text-gray-500\n              file:mr-4 file:py-2 file:px-4\n              file:rounded-full file:border-0\n              file:text-sm file:font-semibold\n              file:bg-emerald-50 file:text-emerald-700\n              hover:file:bg-emerald-100" })),
            React.createElement("div", null,
                React.createElement("label", { className: "block text-sm font-medium text-emerald-800 mb-2 flex items-center gap-2" },
                    React.createElement(fa_1.FaCode, null),
                    "Custom Import Template (Optional)"),
                React.createElement("textarea", { value: template, onChange: function (e) { return setTemplate(e.target.value); }, placeholder: "function processImport(data) { return data; }", className: "input min-h-[200px] font-mono text-sm" }),
                React.createElement("p", { className: "mt-1 text-xs text-gray-500" }, "Add custom JavaScript to process your imports. The template must define a processImport function.")),
            error && (React.createElement("div", { className: "text-red-600 text-sm" }, error)),
            React.createElement("button", { onClick: handleImport, disabled: !files, className: "btn btn-primary w-full" }, "Import Events"))));
}
exports.default = BulkImport;
//# sourceMappingURL=BulkImport.js.map