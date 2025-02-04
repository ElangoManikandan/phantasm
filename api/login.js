import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import db from "../utils/db.js";

const router = express.Router();

import dotenv from 'dotenv';

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

        console.log("Generated Token:", token); // 🔍 Debugging
        res.json({ token }); // ✅ Ensure token is sent in response
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal server error" });
    }
});

export default router;
