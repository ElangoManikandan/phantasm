import express from 'express';
import db from "../utils/db.js"; // Assuming db.query is your SQL query function
import jwt from 'jsonwebtoken';
import { requireAuth } from "./middleware.js"; 

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET; // Use your secret for JWT

// Get User Profile Route
router.get("/get-profile", async (req, res, next) => {
    console.log("🚀 Route /get-profile has been called");

    // Proceed to next middleware (requireAuth) for token validation
    next();
}, requireAuth, async (req, res) => {
    try {
        console.log("✅ Passed authentication, now fetching user...");
        console.log("req.user in /get-profile:", req.user); // Debugging

        // Ensure req.user and req.user.userId exist
        if (!req.user || !req.user.userId) {
            console.error("❌ No userId in req.user");
            return res.status(401).json({ error: "Unauthorized: No user ID found in token" });
        }

        const userId = parseInt(req.user.userId, 10); // Ensure we are using a number for the query
        console.log("Fetching profile for userId:", userId);

        // Prepare the SQL query
        const sqlQuery = "SELECT id, name, college, year, accommodation, role FROM users WHERE id = ?";
        console.log(`🛠 Running SQL Query: ${sqlQuery} with userId = ${userId}`);

        // Check the state of the database connection
        console.log("🔍 Checking Database Connection State:", db.state);

        // Use async/await for the query
        const [results] = await db.query(sqlQuery, [userId]);

        if (!results || results.length === 0) {
            console.error("❌ No user found in database for ID:", userId);
            return res.status(404).json({ error: "User not found!" });
        }

        console.log("✅ User Found:", results[0]); // Log user data

        const user = results[0];
        user.qr_code_id = `user_${user.id}.png`; // Dynamically add qr_code_id

        // Send user data as JSON response
        res.json(user);
    } catch (err) {
        console.error("❌ Error in /get-profile:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});



// Update User Profile Route
router.post("/update-profile", requireAuth, async (req, res) => {
    try {
        const userId = req.user.id; // Access user id from JWT payload
        const { name, college, year, accommodation, role } = req.body; // Get updated values from the request body

        // Validate the fields
        if (!name || !college || !year || !accommodation || !role) {
            return res.status(400).json({ error: "All fields are required!" });
        }

        // Query to update the user details
        const sqlQuery = "UPDATE users SET name = ?, college = ?, year = ?, accommodation = ?, role = ? WHERE id = ?";
        console.log(`🛠 Running SQL Query: ${sqlQuery} with userId = ${userId}`);

        // Use async/await for the query
        const [results] = await db.query(sqlQuery, [name, college, year, accommodation, role, userId]);

        if (results.affectedRows === 0) {
            console.error("❌ User not found for ID:", userId);
            return res.status(404).json({ error: "User not found!" });
        }

        console.log("✅ Profile updated successfully for userId:", userId);
        res.status(200).json({ message: "Profile updated successfully!" });

    } catch (err) {
        console.error("❌ Error in /update-profile:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});
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
