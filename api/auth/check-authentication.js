import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";  // Make sure to set a secret in your environment variables

export default function handler(req, res) {
    if (req.method === 'GET') {
        const token = req.headers['authorization']?.split(' ')[1]; // Expecting token in the Authorization header as "Bearer <token>"

        if (!token) {
            return res.status(401).json({ error: "Not authenticated" });
        }

        try {
            // Verify the JWT token
            const decoded = jwt.verify(token, JWT_SECRET);
            res.status(200).json({ message: "Authenticated", user: decoded }); // Send decoded user info if authentication is successful
        } catch (error) {
            return res.status(401).json({ error: "Invalid or expired token" });
        }
    } else {
        res.status(405).json({ error: "Method Not Allowed" });
    }
}
