import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import db from "../utils/db.js";

const router = express.Router();

router.post("/", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required!" });
    }

    try {
        // Use async/await instead of callback
        const [users] = await db.query("SELECT * FROM users WHERE email = ?", [email]);

        if (users.length === 0) {
            return res.status(404).json({ error: "User not found!" });
        }

        const user = users[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid credentials!" });
        }

        // Generate JWT Token
        const token = jwt.sign(
            { id: user.id, name: user.name, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        // Set cookie (adjust secure settings for dev/prod)
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production", // Secure in production only
            sameSite: "Strict",
            maxAge: 3600000,
        });

        return res.json({
            message: "Login successful!",
            role: user.role,
            redirectUrl: user.role === "admin" ? "/adminprofile.html" : "/profile.html",
        });

    } catch (error) {
        console.error("Server error:", error);
        res.status(500).json({ error: "Server error!" });
    }
});

export default router;
