import express from 'express';
import db from "../utils/db.js"; // Assuming db.query is your SQL query function
import jwt from 'jsonwebtoken';
import { requireAuth } from "./middleware.js"; 

const router = express.Router();
// Update User Profile Route
router.get("/update-profile", async (req, res, next) => {
    console.log("🚀 Route /update-profile has been called");

    // Proceed to next middleware (requireAuth) for token validation
    next();
}, requireAuth, async (req, res) => {
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
export default router;
    } catch (err) {
        console.error("❌ Error in /update-profile:", err.message);
        res.status(500).json({ error: "Internal server error" });
    }
});
