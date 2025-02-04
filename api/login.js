import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import db from "../utils/db.js";
import dotenv from "dotenv";

dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET;

const router = express.Router();

router.post('/', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);  
        const user = users[0];  // Extract user from array

        if (!user) {
            return res.status(401).json({ error: "User not found" });
        }

        // Compare hashed password
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        // Generate JWT
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

        // Set token in HTTP-Only Cookie
        res.cookie("authToken", token, {
            httpOnly: true,  // Prevents access from JavaScript
            secure: process.env.NODE_ENV === "production", // Secure in production
            sameSite: "Strict",
            maxAge: 3600000 // 1 hour
        });

        console.log("Generated Token:", token);  // 🔍 Debugging

        res.json({ message: "Login successful", role: user.role });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal server error" });
    }
});

export default router;

