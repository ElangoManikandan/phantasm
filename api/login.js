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
        const [user] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

        if (!user) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        // Log the entire user object to check the structure
        console.log('User object from DB:', user);

        // Check if password exists in the user object
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
            httpOnly: true, // Makes the cookie inaccessible to JavaScript (for security)
            secure: process.env.NODE_ENV === 'production', // Ensures cookies are sent over HTTPS
            maxAge: 3600000, // Cookie expiration time (1 hour)
            sameSite: 'Strict', // To prevent cross-site request forgery
        });

        // Return a success message
        return res.json({ message: 'Logged in successfully' });

    } catch (err) {
        console.error('Error in login:', err);
        return res.status(500).json({ error: "Internal server error" });
    }
});
export default router;
