'use strict';
const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class Participation extends Model {
    static associate(models) {
      Participation.belongsTo(models.User, { foreignKey: 'userId' });
      Participation.belongsTo(models.Event, { foreignKey: 'eventId' });
    }
  }

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
    sequelize,
    modelName: 'Participation',
  });

  return Participation;
}; 