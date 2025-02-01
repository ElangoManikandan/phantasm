import db from "../../config/db"; // Import your database connection
import jwt from "jsonwebtoken";

export default async function handler(req, res) {
    if (req.method !== "GET") {
        return res.status(405).json({ success: false, message: "Method not allowed" });
    }

    // Extract JWT token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, message: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    try {
        // Verify the JWT token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Ensure the user is an admin
        if (decoded.role !== "admin") {
            return res.status(403).json({ success: false, message: "Forbidden: Admin access required" });
        }

        // Fetch attendance details from the database
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
    } catch (error) {
        console.error("Authentication/Error:", error);
        return res.status(401).json({ success: false, message: "Invalid or expired token!" });
    }
}
