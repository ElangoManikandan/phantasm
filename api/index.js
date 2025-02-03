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

const app = express();
const port = process.env.PORT || 3000;

// Enable CORS globally (Adjust origin if needed)
app.use(cors({
    origin: 'https://phantasm.onrender.com',  // Replace with your frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// ✅ Use express.json() to parse JSON request bodies
app.use(express.json()); 

// ✅ Optional: Use bodyParser.urlencoded() for form data
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static frontend files
const __dirname = path.resolve();
app.use(express.static(path.join(__dirname, "public")));

// Define routes
app.use("/admin", adminRoutes);
app.use('/api/auth', authRoutes);
app.use("/events", eventsRoutes);
app.use("/api/login", loginRoutes);  
app.use("/api/profile", profileRoutes);

// Test database connection
app.get("/test-db", async (req, res) => {
  try {
    const [results] = await db.query("SELECT 1");
    res.status(200).json({ message: "Database connected successfully!", results });
  } catch (err) {
    res.status(500).json({ error: "Database connection failed!" });
  }
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
