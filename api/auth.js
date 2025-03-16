// Import required modules
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import { requireAuth } from "../middleware.js";
import db from "../utils/db.js";
import crypto from "crypto";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import path from "path";
import fs from "fs";

dotenv.config();

const router = express.Router();

// Configure Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});


dotenv.config();

// Define file path for the poster
const posterPath = path.resolve("public", "poster.pdf");

// Forgot Password Route
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const [user] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (user.length === 0) return res.json({ success: false, message: 'Email not found' });

        // Generate Token
        const resetToken = crypto.randomBytes(20).toString('hex');
        const expires = Date.now() + 3600000; // 1 hour expiry

        // Store the token in the database
        await db.query('UPDATE users SET reset_token = ?, reset_expires = ? WHERE email = ?', [resetToken, expires, email]);

        // Send Email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset Request',
            text: `Use the following token to reset your password: ${resetToken}\n\nThis token is valid for 1 hour.`
        };

        await transporter.sendMail(mailOptions);

        res.json({ success: true, message: 'Reset token sent to your email.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Server error, please try again later.' });
    }
});
router.post('/reset-password', async (req, res) => {
    const { email, resetToken, newPassword } = req.body;

    try {
        // Verify user & token
        const [user] = await db.query('SELECT * FROM users WHERE email = ? AND reset_token = ?', [email, resetToken]);

        if (user.length === 0) {
            return res.json({ success: false, message: 'Invalid token or email.' });
        }

        // Check if token is expired
        if (Date.now() > user[0].reset_expires) {
            return res.json({ success: false, message: 'Token expired, request a new one.' });
        }

        // Hash new password and update DB
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.query('UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE email = ?', [hashedPassword, email]);

        res.json({ success: true, message: 'Password successfully reset. You can now log in.' });

    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Server error, please try again later.' });
    }
});
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
// User Registration Route with Poster Attachment
router.post("/register", async (req, res) => {
    try {
        const { name, college, department, reg_no, year, phone, email, password, accommodation, role, admin_key } = req.body;

        if (!name || !college || !department || !reg_no || !year || !phone || !email || !password || !accommodation || !role) {
            return res.status(400).json({ error: "All fields are required!" });
        }

        const phoneRegex = /^\d{10}$/;
        if (!phoneRegex.test(phone)) {
            return res.status(400).json({ error: "Invalid phone number! Must be 10 digits." });
        }

        if (role === "admin" && admin_key !== process.env.ADMIN_KEY) {
            return res.status(400).json({ error: "Invalid admin key!" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await db.query(
            `INSERT INTO users (name, college, department, reg_no, year, phone, email, password, accommodation, role) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [name, college, department, reg_no, year, phone, email, hashedPassword, accommodation, role]
        );

        const userId = result.insertId;
        const qrCodeId = `PSM_${userId}`;

        await db.query(`UPDATE users SET qr_code_id = ? WHERE id = ?`, [qrCodeId, userId]);

        const token = jwt.sign({ email, role }, process.env.JWT_SECRET, { expiresIn: "1h" });

        // Check if poster file exists before sending
        if (!fs.existsSync(posterPath)) {
            console.error("Poster file not found:", posterPath);
        }

        // Send Welcome Email with Poster Attachment
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Welcome to Phantasm'25! 🎉",
            html: `
                <h2>Hello ${name},</h2>
                <p>Welcome to our symposium! 🚀</p>
                <p>Your ID: <strong>${qrCodeId}</strong></p>
                <p>We’ve attached the symposium poster with all the details—make sure to check it out!</p>
                <p>Instructions to register for an event:</p>
                <ul>
                    <li>Visit our event page: <a href="https://phantasm.onrender.com/events.html">Register Here</a></li>
                    <li>Select an event and confirm your participation.</li>
                </ul>
                <p>See you at the event! 🏆</p>
                <p>Best Regards,<br/>Phantasm Team</p>
            `,
            attachments: [
                {
                    filename: "Phantasm25_Poster.pdf",
                    path: posterPath, // Attach the PDF poster
                },
            ],
        };

        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                console.error("Email Sending Error:", err);
            } else {
                console.log("Email Sent:", info.response);
            }
        });

        res.status(201).json({
            message: `${role === "user" ? "User" : "Admin"} registered successfully!`,
            token,
            qr_code_id: qrCodeId,
        });

    } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({ error: "Server error!" });
    }
});

export default router;
