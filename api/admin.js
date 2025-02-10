import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import db from "../utils/db.js";
import { requireAuth, requireAdmin } from "../middleware.js";

const router = express.Router();
// ✅ Mark Attendance Route (Admin Only)
router.post("/mark-attendance", requireAuth, requireAdmin, async (req, res) => {
    const { qr_code_id, event_id } = req.body;
    const adminId = req.user?.id;  // Ensure adminId is extracted properly

    if (!qr_code_id || !event_id) {
        return res.status(400).json({ success: false, message: "QR Code ID and Event ID are required." });
    }

    try {
        // ✅ Fetch user by QR Code
        const [user] = await db.query("SELECT id FROM users WHERE qr_code_id = ?", [qr_code_id]);
        if (user.length === 0) return res.status(404).json({ success: false, message: "QR Code ID not found!" });

        // ✅ Fetch event
        const [event] = await db.query("SELECT id FROM events WHERE id = ?", [event_id]);
        if (event.length === 0) return res.status(404).json({ success: false, message: "Event ID not found!" });

        const userId = user[0].id;

        // ✅ Insert registration if not exists
        await db.query(`
            INSERT INTO registrations (user_id, event_id) 
            SELECT ?, ? FROM DUAL 
            WHERE NOT EXISTS (
                SELECT 1 FROM registrations WHERE user_id = ? AND event_id = ?
            )`, [userId, event_id, userId, event_id]);

        // ✅ Check if attendance is already marked
        const [attendance] = await db.query("SELECT id FROM attendance WHERE event_id = ? AND user_id = ?", [event_id, userId]);
        if (attendance.length > 0) return res.status(400).json({ success: false, message: "Attendance already marked!" });

        // ✅ Mark attendance
        await db.query("INSERT INTO attendance (event_id, user_id, admin_id, attendance_status) VALUES (?, ?, ?, 'present')", 
            [event_id, userId, adminId]);

        res.json({ success: true, message: "User registered and attendance marked successfully!" });

    } catch (err) {
        console.error("❌ Database error:", err);
        res.status(500).json({ success: false, message: "Database error!" });
    }
});


// ✅ Get Admin Profile Route
router.get("/get-admin-profile", requireAuth, requireAdmin, async (req, res) => {
    try {
        const adminId = req.user.id;
        const [[admin]] = await db.query("SELECT name, email, college FROM users WHERE id = ? AND role = 'admin'", [adminId]);

        if (!admin) return res.status(404).json({ error: "Admin not found!" });

        res.json(admin);
    } catch (error) {
        console.error("Error fetching admin profile:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// ✅ Get Admin's Attendance Records
router.get('/attendance', requireAuth, requireAdmin, async (req, res) => {
    const adminId = req.user.id; 
    console.log(`🔍 Fetching attendance for Admin ID: ${adminId}`);

    if (!adminId) {
        return res.status(400).json({ error: "Invalid admin ID in token!" });
    }

    const query = `
        SELECT events.name AS event_name, users.name AS participant_name, 
               attendance.attendance_status, attendance.marked_at
        FROM attendance
        JOIN events ON attendance.event_id = events.id
        JOIN users ON attendance.user_id = users.id
        WHERE attendance.admin_id = ?`;

    try {
        const [results] = await db.query(query, [adminId]);

        console.log("✅ Attendance Data Fetched:", results);

        if (results.length === 0) {
            return res.status(404).json({ message: "No attendance records found for this admin." });
        }

        res.json(results);
    } catch (err) {
        console.error("❌ Database Query Error:", err);
        res.status(500).json({ error: "Database error!", details: err.message });
    }
});


export default router;
