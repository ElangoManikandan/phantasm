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

// Main route (root endpoint, can be adjusted)
app.get("/", (req, res) => {
    res.send("Welcome to the Symposium API");
});

module.exports = app;
