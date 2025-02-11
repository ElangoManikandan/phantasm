import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import {requireAuth} from "../middleware.js";
import db from "../utils/db.js";
import crypto from "crypto";
import nodemailer from "nodemailer"; // For sending emails

const router = express.Router();

// Temporary store for reset tokens (use a database in production)
const resetTokens = {};

/**
 * 📌 Forgot Password Route - Sends a reset link to the user
 */
router.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;

        // Check if email exists
        const [user] = await db.execute("SELECT id FROM users WHERE email = ?", [email]);

        if (user.length === 0) {
            return res.status(404).json({ success: false, message: "Email not found!" });
        }

        // Generate a reset token (valid for 15 minutes)
        const resetToken = crypto.randomBytes(32).toString("hex");
        resetTokens[email] = resetToken;

        // (Mock) Send email (Replace with real email service)
        console.log(`📧 Reset Token for ${email}: ${resetToken}`);

        return res.json({ success: true, message: "Reset link sent! Check console for token." });

    } catch (error) {
        console.error("Error in forgot password:", error);
        return res.status(500).json({ success: false, message: "Server error. Try again later." });
    }
});

/**
 * 📌 Reset Password Route - Updates user's password
 */
router.post("/reset-password", async (req, res) => {
    try {
        const { email, newPassword, resetToken } = req.body;

        // Validate reset token
        if (!resetTokens[email] || resetTokens[email] !== resetToken) {
            return res.status(400).json({ success: false, message: "Invalid or expired token." });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update password in the database
        await db.execute("UPDATE users SET password = ? WHERE email = ?", [hashedPassword, email]);

        // Delete token after use
        delete resetTokens[email];

        return res.json({ success: true, message: "Password reset successfully!" });

    } catch (error) {
        console.error("Error resetting password:", error);
        return res.status(500).json({ success: false, message: "Server error. Try again later." });
    }
});

const router = express.Router();
const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== "admin") {
        return res.status(403).json({ error: "Forbidden: Admins only" });
    }
    next();
};

// Helper function for async DB queries
const queryDatabase = async (query, values) => {
    try {
        const [results] = await db.query(query, values);
        return results;
    } catch (error) {
        throw error;
    }
};

// **User Registration**
router.post("/register", async (req, res) => {
    try {
        const { name, college, year, phone, email, password, accommodation, role, admin_key } = req.body;

        // Validate required fields
        if (!name || !college || !year || !phone || !email || !password || !accommodation || !role) {
            return res.status(400).json({ error: "All fields are required!" });
        }

        // Validate phone number format (10 digits)
        const phoneRegex = /^\d{10}$/;
        if (!phoneRegex.test(phone)) {
            return res.status(400).json({ error: "Invalid phone number! Must be 10 digits." });
        }

        // Validate admin key if role is "admin"
        if (role === "admin" && admin_key !== process.env.ADMIN_KEY) {
            return res.status(400).json({ error: "Invalid admin key!" });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user data into the database (excluding qr_code_id initially)
        const result = await queryDatabase(
            `INSERT INTO users (name, college, year, phone, email, password, accommodation, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [name, college, year, phone, email, hashedPassword, accommodation, role]
        );

        // Get the newly inserted user's ID
        const userId = result.insertId;

        // Generate QR Code ID (format: PSM_<id>)
        const qrCodeId = `PSM_${userId}`;

        // Update the user's record with the generated qr_code_id
        await queryDatabase(
            `UPDATE users SET qr_code_id = ? WHERE id = ?`,
            [qrCodeId, userId]
        );

        // Generate JWT Token
        const token = jwt.sign({ email, role }, process.env.JWT_SECRET, { expiresIn: "1h" });

        res.status(201).json({
            message: `${role === "user" ? "User" : "Admin"} registered successfully!`,
            token,
            qr_code_id: qrCodeId
        });
    } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({ error: "Server error!" });
    }
});

export default router;
