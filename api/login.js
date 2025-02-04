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

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
    }

    try {
        // Check if user exists
        const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        const user = rows[0]; // Extract the first row

        if (!user) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        console.log('User object from DB:', user); // Debugging

        if (!user.password) {
            return res.status(500).json({ error: "Password not found in database" });
        }

        // Compare the hashed password
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

        return res.json({ message: 'Logged in successfully' });

    } catch (err) {
        console.error('Error in login:', err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

export default router;
