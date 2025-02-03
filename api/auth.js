import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import auth from "../utils/auth.js";
import db from "../utils/db.js";

const router = express.Router();
const { requireAuth, requireAdmin } = auth;

// Enable CORS for all routes
router.use(
    cors({
        origin: process.env.CLIENT_URL,
        methods: ["GET", "POST", "PUT", "DELETE"],
        allowedHeaders: ["Content-Type", "Authorization"],
    })
);

// Helper function for async DB queries
const queryDatabase = async (query, values) => {
    try {
        const [results] = await db.query(query, values);
        return results;
    } catch (error) {
        throw error;
    }
};

// **User Registration**
router.post("/register", async (req, res) => {
    try {
        const { name, college, year, email, password, accommodation, role, admin_key } = req.body;

        if (!name || !college || !year || !email || !password || !accommodation || !role) {
            return res.status(400).json({ error: "All fields are required!" });
        }

        if (role === "admin" && admin_key !== process.env.ADMIN_KEY) {
            return res.status(400).json({ error: "Invalid admin key!" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await queryDatabase(
            `INSERT INTO users (name, college, year, email, password, accommodation, role) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [name, college, year, email, hashedPassword, accommodation, role]
        );

        const token = jwt.sign({ email, role }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.status(201).json({
            message: `${role === "user" ? "User" : "Admin"} registered successfully!`,
            token,
        });
    } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({ error: "Server error!" });
    }
});

// **User Login**
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required!" });
        }

        const results = await queryDatabase("SELECT * FROM users WHERE email = ?", [email]);
        if (results.length === 0) {
            return res.status(404).json({ error: "User not found!" });
        }

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid credentials!" });
        }

        const token = jwt.sign(
            { id: user.id, name: user.name, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.cookie("token", token, { httpOnly: true, secure: true, sameSite: "Strict", maxAge: 3600000 });
        res.json({ message: "Login successful!", role: user.role });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ error: "Server error!" });
    }
});

export default router;
