import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import path from "path";
import fs from "fs";
import QRCode from "qrcode";
import auth from "../utils/auth.js";
import db from "../utils/db.js";
import cors from "cors";

const router = express.Router();
const { requireAuth, requireAdmin } = auth;

// Enable CORS for all routes
router.use(
    cors({
        origin: "https://phantasm.onrender.com",
        methods: ["GET", "POST", "PUT", "DELETE"],
        allowedHeaders: ["Content-Type", "Authorization"],
    })
);

// Helper function for async DB queries
const queryDatabase = (query, values) => {
    return new Promise((resolve, reject) => {
        db.query(query, values, (err, results) => {
            if (err) reject(err);
            else resolve(results);
        });
    });
};

// **User Registration**
router.post("/register", async (req, res) => {
    const { name, college, year, email, password, accommodation, role, admin_key } = req.body;

    if (!name || !college || !year || !email || !password || !accommodation || !role) {
        return res.status(400).json({ error: "All fields are required!" });
    }

    if (role !== "user" && role !== "admin") {
        return res.status(400).json({ error: "Invalid role! Choose either 'user' or 'admin'." });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        if (role === "admin" && admin_key !== process.env.ADMIN_KEY) {
            return res.status(400).json({ error: "Invalid admin key!" });
        }

        const insertQuery = `INSERT INTO users (name, college, year, email, password, accommodation, role) VALUES (?, ?, ?, ?, ?, ?, ?)`;
        const result = await queryDatabase(insertQuery, [name, college, year, email, hashedPassword, accommodation, role]);

        const userId = result.insertId;
        const qr_code_id = `PSM_${userId}`;

        await queryDatabase(`UPDATE users SET qr_code_id = ? WHERE id = ?`, [qr_code_id, userId]);

        const qrData = qr_code_id;
        const qrCodePath = path.join(process.cwd(), "public", "qrcodes", `user_${userId}.png`);

        if (!fs.existsSync(path.dirname(qrCodePath))) {
            fs.mkdirSync(path.dirname(qrCodePath), { recursive: true });
        }

        await QRCode.toFile(qrCodePath, qrData);

        const token = jwt.sign({ id: userId, role, email }, process.env.JWT_SECRET, { expiresIn: "1h" });

        res.status(201).json({
            message: `${role === "user" ? "User" : "Admin"} registered successfully!`,
            redirectUrl: role === "user" ? "/profile.html" : "/adminprofile.html",
            qrCodeUrl: `/qrcodes/user_${userId}.png`,
            token,
        });

    } catch (error) {
        console.error("Server error:", error);
        res.status(500).json({ error: "Server error!" });
    }
});

// **User Login**
router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required!" });
    }

    try {
        const results = await queryDatabase("SELECT * FROM users WHERE email = ?", [email]);

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

    } catch (error) {
        console.error("Server error:", error);
        res.status(500).json({ error: "Server error!" });
    }
});

// **Check Authentication**
router.get("/check-authentication", (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({ error: "Not authenticated" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        res.json({ message: "Authenticated", user: decoded });
    } catch (err) {
        res.status(403).json({ error: "Invalid token" });
    }
});

// **Forgot Password**
router.post("/forgot-password", async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: "Email is required." });
    }

    try {
        const results = await queryDatabase("SELECT * FROM users WHERE email = ?", [email]);

        if (results.length > 0) {
            return res.status(200).json({ success: true, message: "A password reset link has been sent." });
        } else {
            return res.status(404).json({ success: false, message: "Email not found." });
        }

    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ success: false, message: "Database error" });
    }
});

// **Reset Password**
router.post("/reset-password", async (req, res) => {
    const { email, newPassword } = req.body;

    if (newPassword.length < 6) {
        return res.status(400).json({ success: false, message: "Password must be at least 6 characters long." });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const result = await queryDatabase("UPDATE users SET password = ? WHERE email = ?", [hashedPassword, email]);

        if (result.affectedRows > 0) {
            return res.status(200).json({ success: true, message: "Password successfully reset" });
        } else {
            return res.status(404).json({ success: false, message: "User not found or reset failed" });
        }

    } catch (error) {
        console.error("Database query error:", error);
        res.status(500).json({ success: false, message: "Database error" });
    }
});

export default router;
