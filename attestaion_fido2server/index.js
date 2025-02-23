// index.js
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv')
const bodyParser = require('body-parser');
const authController = require('./server/auth');

// Load environment variables
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Auth routes
app.post('/api/register/init', authController.registerInit);
app.post('/api/register/complete', authController.registerComplete);
app.post('/api/login/challenge', authController.loginChallenge);
app.post('/api/login/complete', authController.loginComplete);

app.listen(port, () => {
    console.log(`Server running on http://${process.env.HOST || 'localhost'}:${port}`);
});