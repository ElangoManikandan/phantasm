import db from "../config/db"; // Import database connection
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

export default async function handler(req, res) {
    const { method, url } = req;

    // 🔹 Admin Login
    if (method === "POST" && url.endsWith("/admin/login")) {
        const { email, password } = req.body;

        try {
            const [admin] = await db.promise().query(
                "SELECT * FROM users WHERE email = ? AND role = 'admin'",
                [email]
            );

            if (admin.length === 0 || !bcrypt.compareSync(password, admin[0].password)) {
                return res.status(401).json({ success: false, message: "Invalid credentials" });
            }

            const token = jwt.sign(
                { id: admin[0].id, role: "admin" },
                process.env.JWT_SECRET,
                { expiresIn: "2h" }
            );

            return res.status(200).json({ success: true, message: "Admin logged in successfully.", token });
        } catch (error) {
            console.error("Login Error:", error);
            return res.status(500).json({ success: false, message: "Internal server error" });
        }
    }

    // Extract JWT token from Authorization header for protected routes
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, message: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    try {
        // Verify JWT
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Ensure admin access
        if (decoded.role !== "admin") {
            return res.status(403).json({ success: false, message: "Forbidden: Admin access required" });
        }

        // 🔹 Get Admin Profile
        if (method === "GET" && url.endsWith("/admin/profile")) {
            const [admin] = await db.promise().query(
                "SELECT name, email, college FROM users WHERE id = ? AND role = 'admin'",
                [decoded.id]
            );

            if (admin.length === 0) {
                return res.status(404).json({ success: false, message: "Admin not found!" });
            }

            return res.status(200).json({ success: true, admin: admin[0] });
        }

        // 🔹 Fetch Attendance Records
        if (method === "GET" && url.endsWith("/admin/attendance")) {
            const [attendance] = await db.promise().query(
                `SELECT events.name AS event_name, users.name AS participant_name, 
                        attendance.attendance_status, attendance.marked_at
                 FROM attendance
                 JOIN events ON attendance.event_id = events.id
                 JOIN users ON attendance.user_id = users.id
                 WHERE attendance.admin_id = ?`,
                [decoded.id]
            );

            return res.status(200).json({ success: true, attendance });
        }

        // 🔹 Admin Authentication Check
        if (method === "GET" && url.endsWith("/admin/check-auth")) {
            return res.status(200).json({ success: true, message: "Authenticated", user: decoded });
        }
    } catch (error) {
        console.error("Authentication/Error:", error);
        return res.status(401).json({ success: false, message: "Invalid or expired token!" });
    }

    return res.status(405).json({ success: false, message: "Method not allowed" });
}
