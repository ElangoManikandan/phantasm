import db from "../../utils/db"; // Import your database connection
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

        // Fetch the admin profile from the database
        const [admin] = await db.promise().query(
            "SELECT name, email, college FROM users WHERE id = ? AND role = 'admin'",
            [decoded.id]
        );

        if (admin.length === 0) {
            return res.status(404).json({ success: false, message: "Admin not found!" });
        }

        return res.status(200).json({ success: true, admin: admin[0] });
    } catch (error) {
        console.error("Authentication Error:", error);
        return res.status(401).json({ success: false, message: "Invalid or expired token!" });
    }
}
