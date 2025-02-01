import db from '../../utils/db'; // MySQL connection pool
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret"; // JWT Secret

export default async function handler(req, res) {
    if (req.method === 'GET') {
        return getUserProfile(req, res);
    } else if (req.method === 'POST') {
        return updateUserProfile(req, res);
    } else {
        res.status(405).json({ error: 'Method Not Allowed' });
    }
}

// Fetch user profile
function getUserProfile(req, res) {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authentication token is required!' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.id;

        const query = `
            SELECT id, name, college, year, accommodation, role
            FROM users WHERE id = ?
        `;

        db.query(query, [userId], (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Database error!', details: err });
            }

            if (results.length === 0) {
                return res.status(404).json({ error: 'User not found!' });
            }

            const user = results[0];
            user.qr_code_id = `user_${user.id}.png`; // Dynamically add qr_code_id

            res.status(200).json(user);
        });
    } catch (error) {
        console.error('JWT Verification error:', error);
        res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// Update user profile
function updateUserProfile(req, res) {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authentication token is required!' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.id;

        const { name, college, year, accommodation } = req.body;

        if (!name || !college || !year || !accommodation) {
            return res.status(400).json({ error: 'All fields are required!' });
        }

        const query = `
            UPDATE users SET name = ?, college = ?, year = ?, accommodation = ?
            WHERE id = ?
        `;

        db.query(query, [name, college, year, accommodation, userId], (err, result) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Database error!', details: err });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'User not found!' });
            }

            res.status(200).json({ message: 'Profile updated successfully!' });
        });
    } catch (error) {
        console.error('JWT Verification error:', error);
        res.status(401).json({ error: 'Invalid or expired token' });
    }
}
