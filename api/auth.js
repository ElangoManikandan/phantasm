import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import {createSession,verifySession,requireAuth} from "../utils/auth.js";
import db from "../utils/db.js";

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
        const { name, college, year, email, password, accommodation, role, admin_key } = req.body;

        if (!name || !college || !year || !email || !password || !accommodation || !role) {
            return res.status(400).json({ error: "All fields are required!" });
        }

        if (role === "admin" && admin_key !== process.env.ADMIN_KEY) {
            return res.status(400).json({ error: "Invalid admin key!" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user data into the database (excluding qr_code_id initially)
        const result = await queryDatabase(
            `INSERT INTO users (name, college, year, email, password, accommodation, role) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [name, college, year, email, hashedPassword, accommodation, role]
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
