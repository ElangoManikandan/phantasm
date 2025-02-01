const express = require("express");
const bodyParser = require("body-parser");
const adminRoutes = require("./admin");
const authRoutes = require("./auth");
const eventsRoutes = require("./events");
const profileRoutes = require("./profile");
const db = require("../utils/db");

const app = express();
app.use(bodyParser.json());

app.use("/admin", adminRoutes);    // Admin-related routes
app.use("/auth", authRoutes);      // Authentication routes
app.use("/events", eventsRoutes);  // Event-related routes
app.use("/profile", profileRoutes); // Profile-related routes

// Import necessary modules
const express = require('express');
const mysql = require('mysql');
const app = express();
const port = process.env.PORT || 3000;

// Middleware to parse JSON
app.use(express.json());

// Test database connection route
app.get('/test-db', (req, res) => {
    db.query('SELECT 1', (err, results) => {
        if (err) {
            console.error('Database connection failed:', err);
            return res.status(500).json({ error: 'Database connection failed!' });
        }
        console.log('Database connected successfully');
        res.status(200).json({ message: 'Database connected successfully!', results });
    });
});

// Example route
app.get('/', (req, res) => {
    res.send('Hello, world!');
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

// Main route (root endpoint, can be adjusted)
app.get("/", (req, res) => {
    res.send("Welcome to the Symposium API");
});

module.exports = app;
