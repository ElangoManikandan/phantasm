// Import required modules
import express from "express";
import bodyParser from "body-parser";
import adminRoutes from "./admin.js"; // Correctly import with .js extension
import authRoutes from "./auth.js";
import eventsRoutes from "./events.js";
import profileRoutes from "./profile.js";
import db from "../utils/db.js";  // Ensure correct path with .js extension

const app = express();
const port = process.env.PORT || 3000;

// Middleware to parse JSON
app.use(bodyParser.json());
app.use(express.json());

// Define routes
app.use("/admin", adminRoutes);    // Admin-related routes
app.use("/auth", authRoutes);      // Authentication routes
app.use("/events", eventsRoutes);  // Event-related routes
app.use("/profile", profileRoutes); // Profile-related route

// Test database connection route
app.get("/test-db", (req, res) => {
  db.query("SELECT 1", (err, results) => {
    if (err) {
      console.error("Database connection failed:", err);
      return res.status(500).json({ error: "Database connection failed!" });
    }
    console.log("Database connected successfully");
    res.status(200).json({ message: "Database connected successfully!", results });
  });
});

// Example route
app.get("/", (req, res) => {
  res.send("Welcome to the Symposium API");
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

export default app;  // Export the app for further use
