'use strict';
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var Model = require('sequelize').Model;
module.exports = function (sequelize, DataTypes) {
    var Participation = /** @class */ (function (_super) {
        __extends(Participation, _super);
        function Participation() {
            return _super !== null && _super.apply(this, arguments) || this;
        }
        Participation.associate = function (models) {
            Participation.belongsTo(models.User, { foreignKey: 'userId' });
            Participation.belongsTo(models.Event, { foreignKey: 'eventId' });
        };
        return Participation;
    }(Model));
    Participation.init({
        status: {
            type: DataTypes.ENUM('pending', 'approved', 'rejected'),
            defaultValue: 'pending'
        },
        userId: {
            type: DataTypes.INTEGER,
            allowNull: false
        },
        eventId: {
            type: DataTypes.INTEGER,
            allowNull: false
        }
    }, {
        sequelize: sequelize,
        modelName: 'Participation',
    });
    return Participation;
};
//# sourceMappingURL=participation.js.map