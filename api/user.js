import express from 'express';
import db from "../utils/db.js"; // Assuming db.query is your SQL query function
import jwt from 'jsonwebtoken';
import { requireAuth } from "./middleware.js"; 

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET; // Use your secret for JWT
// Get User Profile Route
router.get("/get-profile", requireAuth, (req, res) => {
    console.log("req.user in /get-profile:", req.user); // 🔍 Debugging
    
    if (!req.user || !req.user.userId) {
        console.error("❌ No userId in req.user");
        return res.status(401).json({ error: "Unauthorized: No user ID found in token" });
    }

    const userId = req.user.userId;
    console.log("Fetching profile for userId:", userId); // 🔍 Debugging

    // Query to fetch the user details
db.query(
    "SELECT id, name, college, year, accommodation, role FROM users WHERE id = ?",
    [userId], 
    (err, results) => {
        if (err) {
            console.error("❌ Database error:", err);
            return res.status(500).json({ error: "Database error!" });
        }

        console.log("🛠 SQL Query Executed for userId:", userId);
        console.log("🔍 Query Results:", results); // Debugging

        if (!results || results.length === 0) {
            console.error("❌ No user found in database for ID:", userId);
            return res.status(404).json({ error: "User not found!" });
        }

        console.log("✅ User Found:", results[0]); // Log user data

        const user = results[0];

        res.json(user); // Send user data
    }
);


});



// Update User Profile Route
router.post("/update-profile", requireAuth, (req, res) => {
    const userId = req.user.id; // Access user id from JWT payload
    const { name, college, year, accommodation, role } = req.body; // Get updated values from the request body

    // Validate the fields
    if (!name || !college || !year || !accommodation || !role) {
        return res.status(400).json({ error: "All fields are required!" });
    }

    // Query to update the user details
    db.query(
        "UPDATE users SET name = ?, college = ?, year = ?, accommodation = ?, role = ? WHERE id = ?",
        [name, college, year, accommodation, role, userId],
        (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ error: "Database error!" });
            }
            if (results.affectedRows === 0) {
                return res.status(404).json({ error: "User not found!" });
            }

            res.status(200).json({ message: "Profile updated successfully!" });
        }
    );
});

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
router.get('/profile', requireAuth, async (req, res) => {
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
router.get("/get-events",requireAuth, async (req, res) => {
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
