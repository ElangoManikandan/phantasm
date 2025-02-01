import jwt from 'jsonwebtoken';
import { pool } from '../../utils/db';  // Assuming you're using MySQL with a connection pool

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";  // Ensure the same secret as in login.js

export default async function handler(req, res) {
    if (req.method === 'POST') {
        // Extract the token from the Authorization header
        const token = req.headers.authorization?.split(' ')[1]; // Format: "Bearer <token>"

        if (!token) {
            return res.status(401).json({ error: "Unauthorized. No token provided." });
        }

        try {
            // Verify the JWT token
            const decoded = jwt.verify(token, JWT_SECRET);

            // Now the user ID is available from the decoded token
            const userId = decoded.id;
            const { eventId } = req.body;

            if (!eventId) {
                return res.status(400).json({ error: "Event ID is required!" });
            }

            // Check if the event exists
            const checkEventQuery = 'SELECT id FROM events WHERE id = ?';
            pool.query(checkEventQuery, [eventId], (err, results) => {
                if (err) {
                    return res.status(500).json({ error: "Database error when checking event!" });
                }

                if (results.length === 0) {
                    return res.status(404).json({ error: "Event not found!" });
                }

                // Insert the registration into the registrations table
                const query = 'INSERT INTO registrations (user_id, event_id) VALUES (?, ?)';
                pool.query(query, [userId, eventId], (err, result) => {
                    if (err) {
                        if (err.code === 'ER_DUP_ENTRY') {
                            return res.status(400).json({ error: "User already registered for this event!" });
                        }
                        return res.status(500).json({ error: "Database error!", details: err });
                    }

                    // Send success response
                    res.status(201).json({ message: "Event registration successful!" });
                });
            });
        } catch (err) {
            return res.status(401).json({ error: "Invalid or expired token." });
        }
    } else {
        res.status(405).json({ error: "Method Not Allowed" });
    }
}

