// Import required modules
import express from "express";
import bodyParser from "body-parser";
import path from "path";
import adminRoutes from "./admin.js";
import authRoutes from "./auth.js";
import eventsRoutes from "./events.js";
import profileRoutes from "./profile.js";
import db from "../utils/db.js";  // Ensure correct path
import cors from 'cors';  

const app = express();
const port = process.env.PORT || 3000;

// Enable CORS globally
app.use(cors({
    origin: 'https://phantasm.onrender.com',  // Specify your frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware to parse JSON
app.use(bodyParser.json());
app.use(express.json());

// Serve static frontend files from the `public` folder
const __dirname = path.resolve();
app.use(express.static(path.join(__dirname, "public")));

// Define routes
app.use("/admin", adminRoutes);
app.use('/api/auth', authRoutes);
app.use("/events", eventsRoutes);
app.use("/profile", profileRoutes);

// Test database connection route
app.get("/test-db", async (req, res) => {
  try {
    // Use db.query directly
    const [results] = await db.query("SELECT 1");  // No .promise() needed
    console.log("Database connected successfully");
    res.status(200).json({ message: "Database connected successfully!", results });
  } catch (err) {
    console.error("Database connection failed:", err);
    res.status(500).json({ error: "Database connection failed!" });
  }
});




// Serve `index.html` when visiting the root URL
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

export default app;
