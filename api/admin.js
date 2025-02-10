import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import db from "../utils/db.js";
import { requireAuth, requireAdmin } from "../middleware.js";

const router = express.Router();
// ✅ Mark Attendance Route (Admin Only)
router.post("/mark-attendance", requireAuth, requireAdmin, async (req, res) => {
    const { qr_code_id, event_id } = req.body;
    const adminId = req.user.id;

    if (!qr_code_id || !event_id) {
        return res.status(400).json({ success: false, message: "QR Code ID and Event ID are required." });
    }

    try {
        const [[user]] = await db.promise().query("SELECT id FROM users WHERE qr_code_id = ?", [qr_code_id]);
        if (!user) return res.status(404).json({ success: false, message: "QR Code ID not found!" });

        const [[event]] = await db.promise().query("SELECT id FROM events WHERE id = ?", [event_id]);
        if (!event) return res.status(404).json({ success: false, message: "Event ID not found!" });

        const [[registration]] = await db.promise().query("SELECT id FROM registrations WHERE user_id = ? AND event_id = ?", [user.id, event_id]);
        if (!registration) {
            await db.promise().query("INSERT INTO registrations (user_id, event_id) VALUES (?, ?)", [user.id, event_id]);
        }

        const [[attendance]] = await db.promise().query("SELECT id FROM attendance WHERE event_id = ? AND user_id = ?", [event_id, user.id]);
        if (attendance) return res.status(400).json({ success: false, message: "Attendance already marked!" });

        await db.promise().query("INSERT INTO attendance (event_id, user_id, admin_id, attendance_status) VALUES (?, ?, ?, 'present')", [event_id, user.id, adminId]);

        res.json({ success: true, message: "User registered and attendance marked successfully!" });
    } catch (err) {
        console.error("Database error:", err);
        res.status(500).json({ success: false, message: "Database error!" });
    }
});

// ✅ Get Admin Profile Route
router.get("/get-admin-profile", requireAuth, requireAdmin, async (req, res) => {
    try {
        const adminId = req.user.id;
        const [[admin]] = await db.promise().query("SELECT name, email, college FROM users WHERE id = ? AND role = 'admin'", [adminId]);

        if (!admin) return res.status(404).json({ error: "Admin not found!" });

        res.json(admin);
    } catch (error) {
        console.error("Error fetching admin profile:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// ✅ Get Admin's Attendance Records
router.get("/attendance", requireAuth, requireAdmin, async (req, res) => {
    try {
        const adminId = req.user.id;
        const [attendanceRecords] = await db.promise().query(
            `SELECT events.name AS event_name, users.name AS participant_name, 
            attendance.attendance_status, attendance.marked_at
            FROM attendance
            JOIN events ON attendance.event_id = events.id
            JOIN users ON attendance.user_id = users.id
            WHERE attendance.admin_id = ?`,
            [adminId]
        );

        res.json(attendanceRecords);
    } catch (err) {
        console.error("Database error:", err);
        res.status(500).json({ error: "Database error!" });
    }
});

export default router;
