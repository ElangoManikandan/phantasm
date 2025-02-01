import { pool } from '../../utils/db';  // Assuming you're using MySQL with a connection pool
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";  // Ensure you have the JWT secret set in your environment

export default async function handler(req, res) {
    if (req.method === 'POST') {
        // Get the JWT token from the Authorization header
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Authentication token is required!' });
        }

        try {
            // Verify the JWT token and extract user data
            const decoded = jwt.verify(token, JWT_SECRET);
            const userId = decoded.id;  // Extract the user ID from the token

            // Extract updated user information from the request body
            const { name, college, year, accommodation } = req.body;

            // Validate that all fields are provided
            if (!name || !college || !year || !accommodation) {
                return res.status(400).json({ error: 'All fields are required!' });
            }

            // Query to update the user's profile
            const query = `
                UPDATE users SET name = ?, college = ?, year = ?, accommodation = ?
                WHERE id = ?
            `;

            pool.query(query, [name, college, year, accommodation, userId], (err, result) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ error: 'Database error!', details: err });
                }

                if (result.affectedRows === 0) {
                    return res.status(404).json({ error: 'User not found!' });
                }

                // Send success response
                res.status(200).json({ message: 'Profile updated successfully!' });
            });
        } catch (error) {
            console.error('JWT Verification error:', error);
            res.status(401).json({ error: 'Invalid or expired token' });
        }
    } else {
        res.status(405).json({ error: 'Method Not Allowed' });  // Only allow POST requests
    }
}
