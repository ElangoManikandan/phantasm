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
// **GET Overall Attendance**
router.get("/overall-attendance", async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT 
                attendance.id, 
                users.name AS user_name, 
                users.college, 
                events.name AS event_name, 
                attendance.attendance_status, 
                attendance.marked_at 
            FROM attendance
            JOIN users ON attendance.user_id = users.id
            JOIN events ON attendance.event_id = events.id
            ORDER BY attendance.marked_at DESC;
        `);
        res.json(rows);
    } catch (error) {
        console.error("Error fetching attendance:", error);
        res.status(500).json({ error: "Server error" });
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

// ✅ Get Admin's Attendance Records with Enhanced Debugging
router.get('/attendance', requireAuth, requireAdmin, async (req, res) => {
    const startTime = Date.now(); // Start time for performance tracking
    console.log("🚀 [Request] GET /api/admin/attendance");
    
    const adminId = req.user?.id; 
    console.log(`🔍 [Middleware] Extracted Admin ID: ${adminId}`);

    // Validate adminId before proceeding
    if (!adminId) {
        console.warn("⚠️ [Error] Missing or Invalid admin ID in Token!");
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
        console.log("⏳ [DB] Executing Query...");
        console.log("🔹 [DB Query] ", query);
        console.log("🔸 [DB Params] ", [adminId]);

        const [results] = await db.query(query, [adminId]);
        
        const queryTime = Date.now() - startTime; // Calculate execution time
        console.log(`✅ [DB] Attendance Data Fetched in ${queryTime}ms`);
        console.table(results); // Logs the results in a readable table format

        if (results.length === 0) {
            console.warn("⚠️ [Warning] No attendance records found for this admin.");
            return res.status(404).json({ message: "No attendance records found for this admin." });
        }

        res.json({ success: true, data: results });

    } catch (err) {
        console.error("❌ [DB Error] Database Query Failed!");
        console.error("🔴 [Error Details]", err.message);
        console.error("🔴 [Stack Trace]", err.stack);

        res.status(500).json({ error: "Database error!", details: err.message });
    }
});

router.get("/logout", async (req, res) => {
    console.log("Logout request received!"); // Debugging log
    try {
        res.clearCookie("authToken", { path: "/" });
        return res.status(200).json({ message: "Successfully logged out" });
    } catch (error) {
        console.error("Logout error:", error);
        return res.status(500).json({ error: "Error logging out" });
    }
});


export default router;
