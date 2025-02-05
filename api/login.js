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

router.post('/', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
    }

    try {
        // Ensure DB query returns a valid result
        const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

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

        // Generate JWT token
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

        // Send token as an HTTP-only cookie
        res.cookie('authToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 3600000, // 1 hour
            sameSite: 'Strict',
        });

        return res.json({ message: "Logged in successfully" });

    } catch (err) {
        console.error('Error in login:', err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

export default router;
