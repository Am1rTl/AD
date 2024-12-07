"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var react_1 = require("react");
var prismjs_1 = require("prismjs");
require("prismjs/themes/prism.css");
require("prismjs/components/prism-javascript");
require("prismjs/components/prism-jsx");
require("prismjs/components/prism-python");
require("prismjs/components/prism-java");
require("prismjs/components/prism-c");
require("prismjs/components/prism-cpp");
function CodeEditor(_a) {
    var _b = _a.initialValue, initialValue = _b === void 0 ? '' : _b, _c = _a.language, language = _c === void 0 ? 'javascript' : _c, onCodeChange = _a.onCodeChange;
    var _d = react_1.useState(initialValue), code = _d[0], setCode = _d[1];
    var preRef = react_1.useRef(null);
    var textareaRef = react_1.useRef(null);
    react_1.useEffect(function () {
        prismjs_1.default.highlightAll();
    }, [code]);
    react_1.useEffect(function () {
        if (preRef.current && textareaRef.current) {
            textareaRef.current.style.width = preRef.current.offsetWidth + "px";
            textareaRef.current.style.height = preRef.current.offsetHeight + "px";
        }
    }, [code]);
    var handleChange = function (e) {
        var newCode = e.target.value;
        setCode(newCode);
        if (onCodeChange) {
            onCodeChange(newCode);
        }
    };
    return (react_1.default.createElement("div", { className: "code-editor" },
        react_1.default.createElement("div", { className: "editor-container", style: { position: 'relative' } },
            react_1.default.createElement("textarea", { ref: textareaRef, value: code, onChange: handleChange, className: "code-input", spellCheck: "false", placeholder: "Enter your code here...", style: {
                    minHeight: '300px',
                    padding: '1rem',
                    fontFamily: 'monospace',
                    fontSize: '14px',
                    lineHeight: '1.5',
                    border: '1px solid #ccc',
                    borderRadius: '4px',
                    backgroundColor: 'transparent',
                    resize: 'vertical',
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    zIndex: 1,
                    color: 'transparent',
                    caretColor: 'black',
                    boxSizing: 'border-box',
                } }),
            react_1.default.createElement("pre", { ref: preRef, style: {
                    minHeight: '300px',
                    padding: '1rem',
                    fontFamily: 'monospace',
                    fontSize: '14px',
                    lineHeight: '1.5',
                    border: '1px solid #ccc',
                    borderRadius: '4px',
                    backgroundColor: '#f8f8f8',
                    margin: 0,
                    pointerEvents: 'none',
                } },
                react_1.default.createElement("code", { className: "language-" + language }, code || ' ')))));
}
exports.default = CodeEditor;
//# sourceMappingURL=codeEditor.js.map