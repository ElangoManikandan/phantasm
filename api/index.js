import express from "express";
import cors from "cors";
import path from "path";
import bodyParser from "body-parser";
import adminRoutes from "./admin.js";
import authRoutes from "./auth.js";
import eventsRoutes from "./events.js";
import profileRoutes from "./profile.js";
import loginRoutes from "./login.js";  
import db from "../utils/db.js";  
import userRouter from './user.js'; 
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import { requireAuth, requireAdmin } from "../middleware.js";

const app = express();
const port = process.env.PORT || 3000;
app.use(cookieParser()); // ✅ Parse cookies before handling requests

// Enable CORS globally (Adjust origin if needed)
app.use(cors({
    origin: 'https://phantasm.onrender.com',  // Replace with your frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials:true
}));

// ✅ Use express.json() to parse JSON request bodies
app.use(express.json()); 

// ✅ Optional: Use bodyParser.urlencoded() for form data
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static frontend files
const __dirname = path.resolve();
app.use(express.static(path.join(__dirname, "public")));

// Define routes
// Example usage for admin routes
app.use("/api/admin", requireAuth, requireAdmin, adminRoutes);
// Example usage for other routes that require authentication
app.use("/api/profile", requireAuth, profileRoutes);
app.use('/api/auth', authRoutes);
app.use("/api/events", requireAuth, requireAdmin, eventsRoutes);
app.use("/api/login", loginRoutes);  
app.use("/api/user", requireAuth, userRouter);// Use user routes for '/api/user'

app.get("/test-db", (req, res) => {
    const userId = 1; // Replace with the userId you want to test with

    const start = Date.now();  // Start time tracking for the query

    console.log("🚀 Starting Database Query for userId:", userId);

    // Log database connection state (check if it's connected)
    console.log("Database Client State:", db.state);

    db.query(
        "SELECT id, name, college, year, accommodation, role FROM users WHERE id = ?",
        [userId], 
        (err, results) => {
            const end = Date.now();  // End time tracking for the query
            console.log("Query Execution Time:", end - start, "ms"); // Log the query execution time

            if (err) {
                console.error("❌ Database query error:", err);
                return res.status(500).json({ error: "Database error!" });
            }

            // Log the raw query results to check if anything unexpected is returned
            console.log("🔍 Full Query Results:", results);
            if (results && results.length > 0) {
                console.log("🔍 Column Names:", Object.keys(results[0])); // Check the column names
            }

            // Check if results are empty or not
            if (!results || results.length === 0) {
                console.error("❌ No user found for ID:", userId);
                return res.status(404).json({ error: "User not found!" });
            }

            // Log the response before sending it back
            console.log("✅ User Found:", results[0]);

            res.json(results[0]);
        }
    );
});



// Serve index.html for root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

export default app;
