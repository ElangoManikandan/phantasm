import db from "../../config/db"; // Import your database connection
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export default async function handler(req, res) {
    if (req.method === "POST") {
        const { email, password } = req.body;

        try {
            // Fetch admin details
            const [admin] = await db.promise().query(
                "SELECT * FROM users WHERE email = ? AND role = 'admin'",
                [email]
            );

            if (admin.length === 0 || !bcrypt.compareSync(password, admin[0].password)) {
                return res.status(401).json({ success: false, message: "Invalid credentials" });
            }

            // Generate JWT token
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

    if (req.method === "GET") {
        // Authentication check logic
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ success: false, message: "No token provided" });
        }

        const token = authHeader.split(" ")[1];
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            return res.status(200).json({ success: true, message: "Authenticated", user: decoded });
        } catch (error) {
            return res.status(401).json({ success: false, message: "Invalid token" });
        }
    }

    return res.status(405).json({ success: false, message: "Method not allowed" });
}
