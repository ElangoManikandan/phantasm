import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import {requireAuth} from "../middleware.js";
import db from "../utils/db.js";
import crypto from "crypto";
import nodemailer from "nodemailer";
import dotenv from 'dotenv';


dotenv.config();

const { body, validationResult } = require("express-validator");


const router = express.Router();

// Configure Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

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
// **User Registration**

// **User Registration**
router.post(
    "/register",
    [
        // Validate required fields
        body("name").notEmpty().withMessage("Name is required"),
        body("college").notEmpty().withMessage("College is required"),
        body("department").notEmpty().withMessage("Department is required"),
        body("reg_no").notEmpty().withMessage("Registration number is required"),
        body("year").notEmpty().withMessage("Year is required"),
        body("phone")
            .matches(/^\d{10}$/)
            .withMessage("Invalid phone number! Must be 10 digits."),
        body("email")
            .isEmail()
            .withMessage("Invalid email format")
            .normalizeEmail(), // ✅ Normalizes email
        body("password")
            .isLength({ min: 6 })
            .withMessage("Password must be at least 6 characters"),
        body("accommodation").notEmpty().withMessage("Accommodation field is required"),
        body("role").notEmpty().withMessage("Role is required"),
        body("admin_key").optional(), // Admin key is only required if role is "admin"
    ],
    async (req, res) => {
        try {
            // Check for validation errors
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { name, college, department, reg_no, year, phone, email, password, accommodation, role, admin_key } =
                req.body;

            // Validate admin key if role is "admin"
            if (role === "admin" && admin_key !== process.env.ADMIN_KEY) {
                return res.status(400).json({ error: "Invalid admin key!" });
            }

            // Check if email already exists
            const [existingUser] = await queryDatabase(`SELECT * FROM users WHERE email = ?`, [email]);
            if (existingUser.length > 0) {
                return res.status(400).json({ error: "Email already exists!" });
            }

            // Hash the password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert user data into the database
            const result = await queryDatabase(
                `INSERT INTO users (name, college, department, reg_no, year, phone, email, password, accommodation, role) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [name, college, department, reg_no, year, phone, email, hashedPassword, accommodation, role]
            );

            // Get the newly inserted user's ID
            const userId = result.insertId;

            // Generate QR Code ID (format: PSM_<id>)
            const qrCodeId = `PSM_${userId}`;

            // Update the user's record with the generated qr_code_id
            await queryDatabase(`UPDATE users SET qr_code_id = ? WHERE id = ?`, [qrCodeId, userId]);

            // Generate JWT Token
            const token = jwt.sign({ email, role }, process.env.JWT_SECRET, { expiresIn: "1h" });

            res.status(201).json({
                message: `${role === "user" ? "User" : "Admin"} registered successfully!`,
                token,
                qr_code_id: qrCodeId,
            });
        } catch (error) {
            console.error("Registration Error:", error);
            res.status(500).json({ error: "Server error!" });
        }
    }
);

export default router;
