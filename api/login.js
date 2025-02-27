import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import db from "../utils/db.js";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";

dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    throw new Error("Missing JWT_SECRET in environment variables");
}

const router = express.Router();
router.use(cookieParser()); // Enable cookie parsing

// Login route
router.post("/", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
    }

    try {
        // Query to find user by email
        const [rows] = await db.execute('SELECT id, email, password, role FROM users WHERE email = ?', [email]);

        if (!rows || rows.length === 0) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const user = rows[0]; // Extract user object

        if (!user.password) {
            console.error('Database issue: Password column is missing or null.');
            return res.status(500).json({ error: "Internal error: Password missing" });
        }

        // Compare password with stored hash
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        // ✅ FIX: Generate JWT token WITH `role`
        const token = jwt.sign(
            { userId: user.id, role: user.role }, // 👀 Include `role`
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Set the token in a cookie
        res.cookie("authToken", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production", // Ensure it’s secure in production
            sameSite: "Strict", // For security against CSRF
            maxAge: 60 * 60 * 1000, // Token expiration time (1 hour in ms)
        });

        return res.json({ message: "Logged in successfully", role: user.role }); // 👀 Return role for debugging

    } catch (err) {
        console.error('Error in login:', err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

export default router;
