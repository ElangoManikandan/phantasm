import { pool } from '../../utils/db';  // Assuming you are using MySQL with a connection pool
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";  // Make sure the JWT secret is set in your environment

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

            // Query to fetch the user's profile data
            const query = `
                SELECT id, name, college, year, accommodation, role
                FROM users WHERE id = ?
            `;

            pool.query(query, [userId], (err, results) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ error: 'Database error!', details: err });
                }

                if (results.length === 0) {
                    return res.status(404).json({ error: 'User not found!' });
                }

                const user = results[0];
                user.qr_code_id = `user_${user.id}.png`; // Dynamically add qr_code_id based on user id

                res.status(200).json(user);  // Send the profile data to the frontend
            });
        } catch (error) {
            console.error('JWT Verification error:', error);
            res.status(401).json({ error: 'Invalid or expired token' });
        }
    } else {
        res.status(405).json({ error: 'Method Not Allowed' });  // Only allow GET requests
    }
}
