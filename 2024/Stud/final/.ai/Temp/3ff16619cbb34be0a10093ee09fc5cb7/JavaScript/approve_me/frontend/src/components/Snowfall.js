"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var react_1 = require("react");
var fa_1 = require("react-icons/fa");
function Snowfall() {
    var _a = react_1.useState([]), snowflakes = _a[0], setSnowflakes = _a[1];
    react_1.useEffect(function () {
        var flakes = Array.from({ length: 30 }, function (_, i) { return ({
            id: i,
            left: Math.random() * 100,
            size: Math.random() * 1 + 1,
            delay: Math.random() * 10,
            duration: Math.random() * 5 + 10,
            opacity: Math.random() * 0.3 + 0.6, // 0.6 to 0.9 (increased opacity)
        }); });
        setSnowflakes(flakes);
    }, []);
    return (React.createElement("div", { className: "fixed inset-0 pointer-events-none z-0 overflow-hidden" }, snowflakes.map(function (flake) { return (React.createElement("div", { key: flake.id, className: "absolute animate-fall", style: {
            left: flake.left + "%",
            fontSize: flake.size + "rem",
            opacity: flake.opacity,
            animationDelay: flake.delay + "s",
            animationDuration: flake.duration + "s",
            transform: "translateY(-20px) rotate(0deg)",
        } },
        React.createElement(fa_1.FaSnowflake, { className: "text-emerald-200" }))); })));
}
exports.default = Snowfall;
//# sourceMappingURL=Snowfall.js.map