import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import  db  from "../utils/db.js"; // Assuming this is your database connection

const router = express.Router();

router.post("/", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required" });
        }

        // ✅ Check if user exists in the database
        const [user] = await db.query("SELECT * FROM users WHERE email = ?", [email]);

        if (!user) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        // ✅ Compare password with hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        // ✅ Generate JWT token
        const token = jwt.sign(
            { userId: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "2h" }
        );

        console.log("✅ Login successful. Token generated.");

        // ✅ Send response with token and role
        res.json({ token, role: user.role });

    } catch (error) {
        console.error("❌ Login error:", error);
        res.status(500).json({ error: "Server error. Please try again." });
    }
});

export default router;
