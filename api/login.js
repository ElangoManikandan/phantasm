import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import db from "../utils/db.js";
import dotenv from "dotenv";

dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET;

router.post('/', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [user] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

        if (!user || user.password !== password) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
        
        // Send token as an HTTP-only cookie
        res.cookie('authToken', token, {
            httpOnly: true, // Makes the cookie inaccessible to JavaScript (for security)
            secure: process.env.NODE_ENV === 'production', // Ensures cookies are sent over HTTPS
            maxAge: 3600000, // Cookie expiration time (1 hour)
            sameSite: 'Strict' // To prevent cross-site request forgery
        });

        return res.json({ message: 'Logged in successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal server error" });
    }
});

export default router;

export default router;

