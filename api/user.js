import express from 'express';
import db from "../utils/db.js"; // Assuming db.query is your SQL query function
import jwt from 'jsonwebtoken';
import { requireAuth } from "./middleware.js"; 

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET; // Use your secret for JWT

// Middleware to authenticate user by verifying JWT
const authenticateJWT = (req, res, next) => {
    const authToken = req.headers['authorization'];
    if (!authToken) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authToken.split(' ')[1]; // Extract token from "Bearer token"

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }
        req.user = user; // Attach user info to the request object
        next();
    });
};

// Route to get user profile information
router.get('/profile', authenticateJWT, async (req, res) => {
    try {
        const userId = req.user.userId; // Retrieved from the JWT
        const query = 'SELECT * FROM users WHERE id = ?'; // Query to fetch user data by ID
        const [user] = await db.query(query, [userId]);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Send user details as a response, excluding sensitive information
        res.json({
            name: user.name,
            college: user.college,
            year: user.year,
            accommodation: user.accommodation,
            qr_code_id: user.qr_code_id, // If relevant to your profile
        });
    } catch (err) {
        console.error('Error fetching profile:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Route to update user profile information
router.post('/update-profile', authenticateJWT, async (req, res) => {
    try {
        const userId = req.user.userId; // Retrieved from the JWT
        const { name, college, year, accommodation } = req.body;

        // Validate inputs
        if (!name || !college || !year || !accommodation) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const query = `
            UPDATE users 
            SET name = ?, college = ?, year = ?, accommodation = ?
            WHERE id = ?;
        `;
        const result = await db.query(query, [name, college, year, accommodation, userId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'Profile updated successfully' });
    } catch (err) {
        console.error('Error updating profile:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

router.get("/events", requireAuth, (req, res) => {
    const userId = req.user.id;

    const query = `
        SELECT e.name AS eventName
        FROM events e
        INNER JOIN registrations r ON e.id = r.event_id
        WHERE r.user_id = ?
    `;

    db.query(query, [userId], (err, results) => {
        if (err) return res.status(500).json({ error: "Database error!", details: err });
        res.status(200).json(results);  // Send the event names to the frontend
    });
});

export default router;
