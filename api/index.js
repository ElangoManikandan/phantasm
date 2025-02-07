import express from "express";
import cors from "cors";
import path from "path";
import bodyParser from "body-parser";
import adminRoutes from "./admin.js";
import authRoutes from "./auth.js";
import eventsRoutes from "./events.js";
import loginRoutes from "./login.js";  
import db from "../utils/db.js";  
import userRouter from './user.js'; 
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import { requireAuth } from "../middleware.js";

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
app.use("/api/admin", requireAuth, adminRoutes);
app.use('/api/auth', authRoutes);
app.use("/api/events", requireAuth, eventsRoutes);
app.use("/api/login", loginRoutes);  
app.use("/api/user", requireAuth, userRouter);// Use user routes for '/api/user'
// Test database route
app.get("/test-db", async (req, res) => {
    const userId = 1;

    try {
        console.log("🚀 Starting Database Query for userId:", userId);

        // Ensure db is available and connected
        const connection = await db.getConnection();
        console.log("✅ Connection acquired from pool");

        // Running the query
        const [results] = await connection.execute(
            "SELECT id, name, college, year, accommodation, role FROM users WHERE id = ?",
            [userId]
        );

        console.log("🔍 Query Results:", results);

        if (!results || results.length === 0) {
            console.error("❌ No user found for ID:", userId);
            return res.status(404).json({ error: "User not found!" });
        }

        res.json(results[0]);
        connection.release();  // Don't forget to release the connection back to the pool

    } catch (err) {
        console.error("❌ Database query error:", err);
        res.status(500).json({ error: "Database error!" });
    }
});

console.log("🔍 Checking Database Connection State:", db);


// Serve index.html for root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

export default app;
