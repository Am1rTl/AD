"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var react_1 = require("react");
var react_syntax_highlighter_1 = require("react-syntax-highlighter");
var prism_1 = require("react-syntax-highlighter/dist/esm/styles/prism");
function PasteComponent(_a) {
    var code = _a.code, language = _a.language, title = _a.title, author = _a.author;
    return (react_1.default.createElement("div", { style: {
            border: '1px solid #ccc',
            borderRadius: '4px',
            backgroundColor: '#f9f9f9',
            maxWidth: '800px',
            width: '100%'
        } },
        react_1.default.createElement("div", { style: {
                padding: '1rem 1rem .5rem 1rem',
                borderBottom: '1px solid #ccc'
            } },
            react_1.default.createElement("div", { style: {
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                } },
                title && react_1.default.createElement("h3", { style: { margin: 0 } }, title),
                react_1.default.createElement("span", null, language)),
            react_1.default.createElement("div", { style: {
                    marginTop: '0.5rem',
                    fontSize: '0.9rem',
                    color: '#666'
                } }, author && (react_1.default.createElement("span", null,
                "Posted by ",
                react_1.default.createElement("strong", null, author))))),
        react_1.default.createElement("div", null,
            react_1.default.createElement(react_syntax_highlighter_1.Prism, { language: language, style: prism_1.vscDarkPlus, showLineNumbers: true, wrapLines: true, customStyle: {
                    margin: 0,
                    borderRadius: '0 0 4px 4px',
                } }, code))));
}
// Add prop types validation
PasteComponent.defaultProps = {
    title: '',
    code: '',
    language: 'javascript',
    author: ''
};
exports.default = PasteComponent;
//# sourceMappingURL=paste.js.map