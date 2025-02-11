import express from 'express';
import db from "../utils/db.js"; // Assuming db.query is your SQL query function
import jwt from 'jsonwebtoken';
import { requireAuth } from "./middleware.js"; 

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET; // Use your secret for JWT

// Modify the existing update-profile route to handle POST requests
router.post("/update-profile", async (req, res, next) => {
    try {
        const { name, college, year, accommodation, phone } = req.body;
        const userId = req.user.userId;

        if (!name || !college || !year || !accommodation || !phone) {
            return res.status(400).json({ error: "All fields are required!" });
        }

        // Log the query for debugging
        const sqlQuery = `UPDATE users SET name = ?, college = ?, year = ?, accommodation = ?, phone = ? WHERE id = ?`;
        console.log(`🛠 Running SQL Query: ${sqlQuery} with userId = ${userId}`);
        
        // Database query to update profile
        const results = await db.query(sqlQuery, [name, college, year, accommodation, phone, userId]);

        if (results.affectedRows === 0) {
            return res.status(400).json({ error: "Failed to update profile. Please try again." });
        }

        res.json({ message: "Profile updated successfully" });
    } catch (err) {
        console.error("Error updating profile:", err);
        res.status(500).json({ error: "An error occurred while updating the profile." });
    }
});


// Get User Profile Route
// Get User Profile Route
router.get("/get-profile", async (req, res, next) => {
    console.log("🚀 Route /get-profile has been called");

    // Proceed to next middleware (requireAuth) for token validation
    next();
}, requireAuth, async (req, res) => {
    try {
        console.log("✅ Passed authentication, now fetching user...");

        // Ensure req.user and req.user.userId exist
        if (!req.user || !req.user.userId) {
            console.error("❌ Unauthorized: No user ID found in token");
            return res.status(401).json({ error: "Unauthorized: No user ID found in token" });
        }

        const userId = parseInt(req.user.userId, 10);
        console.log("🔍 Fetching profile for userId:", userId);

        // SQL query to fetch user data including qr_code_id and phone
        const sqlQuery = "SELECT id, name, college, year, accommodation, role, phone, qr_code_id FROM users WHERE id = ?";
        console.log(`🛠 Running SQL Query: ${sqlQuery} with userId = ${userId}`);

        // Execute query
        const [results] = await db.query(sqlQuery, [userId]);

        if (!results || results.length === 0) {
            console.error("❌ No user found in database for ID:", userId);
            return res.status(404).json({ error: "User not found!" });
        }

        let user = results[0];

        // Generate qr_code_id dynamically if it doesn't exist in the database
        if (!user.qr_code_id) {
            user.qr_code_id = `PSM_${user.id}`;

            // Update the database with the generated qr_code_id
            await db.query("UPDATE users SET qr_code_id = ? WHERE id = ?", [user.qr_code_id, user.id]);

            console.log(`🔄 Assigned new QR Code ID: ${user.qr_code_id}`);
        }

        console.log("✅ User Found:", user);

        // Send user data as JSON response
        res.json(user);
    } catch (err) {
        console.error("❌ Error in /get-profile:", err);
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
router.get("/get-events", async (req, res, next) => {
    console.log("🚀 Route /get-events has been called");

    // Proceed to next middleware (requireAuth) for token validation
    next();
}, requireAuth, async (req, res) => {
  try {
const userId = req.user.userId;  // Make sure this is set properly in your JWT validation middleware
    
    if (!userId) {
      return res.status(400).json({ error: "Invalid or missing userId" });
    }

    // Query to fetch events based on userId
    const [results] = await db.execute(`
      SELECT e.name AS eventName
      FROM events e
      INNER JOIN registrations r ON e.id = r.event_id
      WHERE r.user_id = ?`, [userId]);

    // If no events are found, send an appropriate message
    if (results.length === 0) {
      return res.status(200).json({ message: "No events registered yet." });
    }

    // Return events to the frontend
    res.status(200).json(results);
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: "Database error", details: error.message });
  }
});

router.get("/logout", async (req, res) => {
    try {
        // Clear the JWT token or session (depends on how you're managing sessions)
        res.clearCookie('authToken', { path: '/' }); // If using cookies
        res.status(200).json({ message: "Successfully logged out" });
    } catch (error) {
        console.error("Logout error:", error);
        res.status(500).json({ error: "Error logging out" });
    }
});



export default router;
