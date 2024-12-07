var express = require('express');
var cors = require('cors');
var helmet = require('helmet');
require('dotenv').config();
var routes = require('./routes');
var db = require('./models');
var app = express();
// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Routes
app.use('/api', routes);
// Error handling middleware
app.use(function (err, req, res, next) {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});
var PORT = process.env.PORT || 3000;
// Sync database and start server
db.sequelize.drop({}).then(function () {
    db.sequelize.sync({ force: true }).then(function () {
        app.listen(PORT, function () {
            console.log("Server is running on port " + PORT);
        });
    });
});
//# sourceMappingURL=app.js.map