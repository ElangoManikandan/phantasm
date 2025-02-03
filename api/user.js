// api/user.js (Create this file to handle user profile data)
import express from 'express';
import db from "../utils/db.js";
import middleware from "../middleware.js";
const { requireAuth } = middleware;
const router = express.Router();
import jwt from 'jsonwebtoken';

const JWT_SECRET = 'your_jwt_secret'; // Use your secret for JWT

// Middleware to authenticate user by verifying JWT
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1]; // Extract token from "Bearer token"

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
        const user = await User.findById(userId).select('-password'); // Exclude password

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Send user details as a response
        res.json({
            name: user.name,
            college: user.college,
            year: user.year,
            accommodation: user.accommodation,
            qr_code_id: user.qr_code_id, // If relevant to your profile
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

export default router; // Exporting the router for use in other parts of the app
