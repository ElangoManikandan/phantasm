import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import db from "../utils/db.js"; // Ensure correct path with .js extension
import {requireAuth,requireAdmin} from "../utils/auth.js";
const router = express.Router();

// Login route for admin
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Fetch the admin from the database
        const [admin] = await db.promise().query(
            "SELECT * FROM users WHERE email = ? AND role = 'admin'",
            [email]
        );

        if (admin.length === 0 || !bcrypt.compareSync(password, admin[0].password)) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        // Create a JWT token with the admin's ID and role
        const token = jwt.sign(
            { id: admin[0].id, role: admin[0].role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" } // Token expires in 1 hour
        );

        // Send the token in the response
        res.status(200).json({
            success: true,
            message: "Admin logged in successfully.",
            token: token, // The token will be sent to the client
        });
    } catch (err) {
        console.error("Error during login:", err);
        res.status(500).json({ success: false, message: "Server error during login" });
    }
});

// Admin Attendance Route
router.post('/admin/mark-attendance', requireAdmin, async (req, res) => {
    const { qr_code_id, event_id } = req.body;
    const adminId = req.user.id; // Get admin's ID from the decoded JWT

    if (!qr_code_id || !event_id) {
        return res.status(400).json({ success: false, message: "QR Code ID and Event ID are required." });
    }

    try {
        // Check if the user exists
        const [userResults] = await db.promise().query(
            `SELECT id FROM users WHERE qr_code_id = ?`,
            [qr_code_id]
        );

        if (userResults.length === 0) {
            return res.status(404).json({ success: false, message: "QR Code ID not found!" });
        }

        const userId = userResults[0].id;

        // Check if the event exists
        const [eventResults] = await db.promise().query(
            `SELECT id FROM events WHERE id = ?`,
            [event_id]
        );

        if (eventResults.length === 0) {
            return res.status(404).json({ success: false, message: "Event ID not found!" });
        }

        // Check if the user is registered for the event
        const [registrationResults] = await db.promise().query(
            `SELECT id FROM registrations WHERE user_id = ? AND event_id = ?`,
            [userId, event_id]
        );

        if (registrationResults.length === 0) {
            // Register the user for the event
            await db.promise().query(
                `INSERT INTO registrations (user_id, event_id) VALUES (?, ?)`,
                [userId, event_id]
            );
        }

        // Check if attendance is already marked
        const [attendanceResults] = await db.promise().query(
            `SELECT id FROM attendance WHERE event_id = ? AND user_id = ?`,
            [event_id, userId]
        );

        if (attendanceResults.length > 0) {
            return res.status(400).json({ success: false, message: "Attendance already marked!" });
        }

        // Mark attendance
        await db.promise().query(
            `INSERT INTO attendance (event_id, user_id, admin_id, attendance_status) 
             VALUES (?, ?, ?, 'present')`,
            [event_id, userId, adminId]
        );

        res.json({ success: true, message: "User registered and attendance marked successfully!" });
    } catch (err) {
        console.error("Database error:", err);
        res.status(500).json({ success: false, message: "Database error!" });
    }
});

// Admin Profile Route
router.get('/get-admin-profile', requireAdmin, (req, res) => {
    const adminId = req.user.id; // Get admin's ID from the decoded JWT

    db.query(
        "SELECT name, email, college FROM users WHERE id = ? AND role = 'admin'",
        [adminId],
        (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ error: "Database error!" });
            }
            if (results.length === 0) {
                return res.status(404).json({ error: "Admin not found!" });
            }
            res.json(results[0]); // Return the admin profile data
        }
    );
});

// Admin Attendance Details Route
router.get('/attendance', requireAdmin, (req, res) => {
    const adminId = req.user.id; // Get admin's ID from the decoded JWT

    db.query(
        `SELECT events.name AS event_name, users.name AS participant_name, 
        attendance.attendance_status, attendance.marked_at
        FROM attendance
        JOIN events ON attendance.event_id = events.id
        JOIN users ON attendance.user_id = users.id
        WHERE attendance.admin_id = ?`,
        [adminId],
        (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ error: "Database error!" });
            }
            res.json(results); // Return the attendance details
        }
    );
});

export default router;  // Use export default for ES module
