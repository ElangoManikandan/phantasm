import { pool } from '../../utils/db'; // MySQL connection pool
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret"; // Ensure JWT secret is set

export default async function handler(req, res) {
    if (req.method === 'GET') {
        if (req.query.user === "true") {
            return getUserRegisteredEvents(req, res);
        } else {
            return getAllEvents(req, res);
        }
    } else if (req.method === 'POST') {
        return registerForEvent(req, res);
    } else {
        res.status(405).json({ error: 'Method Not Allowed' });
    }
}

// Fetch all events
function getAllEvents(req, res) {
    const query = "SELECT id, name, DATE_FORMAT(date, '%d-%m-%Y') AS date, TIME_FORMAT(time, '%H:%i:%s') AS time FROM events";
    
    pool.query(query, (err, results) => {
        if (err) {
            console.error("Error fetching events:", err);
            return res.status(500).json({ error: "Failed to fetch events." });
        }
        res.status(200).json(results);
    });
}

// Register a user for an event
function registerForEvent(req, res) {
    const token = req.headers.authorization?.split(' ')[1]; // Expecting "Bearer <token>"

    if (!token) {
        return res.status(401).json({ error: "Unauthorized. No token provided." });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.id;
        const { eventId } = req.body;

        if (!eventId) {
            return res.status(400).json({ error: "Event ID is required!" });
        }

        // Check if the event exists
        pool.query('SELECT id FROM events WHERE id = ?', [eventId], (err, results) => {
            if (err) {
                return res.status(500).json({ error: "Database error when checking event!" });
            }

            if (results.length === 0) {
                return res.status(404).json({ error: "Event not found!" });
            }

            // Insert the registration into the registrations table
            pool.query('INSERT INTO registrations (user_id, event_id) VALUES (?, ?)', [userId, eventId], (err) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        return res.status(400).json({ error: "User already registered for this event!" });
                    }
                    return res.status(500).json({ error: "Database error!", details: err });
                }

                res.status(201).json({ message: "Event registration successful!" });
            });
        });
    } catch (err) {
        return res.status(401).json({ error: "Invalid or expired token." });
    }
}

// Fetch user-registered events
function getUserRegisteredEvents(req, res) {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authentication token is required!' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.id;

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

            res.status(200).json(results);
        });
    } catch (error) {
        console.error('JWT Verification error:', error);
        res.status(401).json({ error: 'Invalid or expired token' });
    }
}
