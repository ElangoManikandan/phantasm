import { pool } from '../../utils/db';  // Assuming you are using MySQL with a connection pool
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";  // JWT secret from environment

export default async function handler(req, res) {
    if (req.method === 'GET') {
        // Get the JWT token from the Authorization header
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Authentication token is required!' });
        }

        try {
            // Verify the JWT token and extract user data
            const decoded = jwt.verify(token, JWT_SECRET);
            const userId = decoded.id;  // Extract the user ID from the token

            // Query to fetch events registered by the user
            const query = `
                SELECT e.name AS eventName
                FROM events e
                INNER JOIN registrations r ON e.id = r.event_id
                WHERE r.user_id = ?
            `;

            pool.query(query, [userId], (err, results) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ error: 'Database error!', details: err });
                }

                res.status(200).json(results);  // Send the event names to the frontend
            });
        } catch (error) {
            console.error('JWT Verification error:', error);
            res.status(401).json({ error: 'Invalid or expired token' });
        }
    } else {
        res.status(405).json({ error: 'Method Not Allowed' });  // Only allow GET requests
    }
}
