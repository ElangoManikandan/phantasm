import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import db from "../utils/db.js";

const router = express.Router();

router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required!" });
    }

    try {
        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ error: "Database error!" });
            }

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

            return res.json({
                message: "Login successful!",
                role: user.role,
                redirectUrl: user.role === "admin" ? "/adminprofile.html" : "/profile.html",
            });
        });
    } catch (error) {
        console.error("Server error:", error);
        res.status(500).json({ error: "Server error!" });
    }
});

export default router;
