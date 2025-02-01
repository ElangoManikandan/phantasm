import express from "express";
import db from "../utils/db";
import { requireAuth } from "../api/middleware";

const router = express.Router();

// Get User Profile Route
// Get Profile Route using JWT Authentication
router.get("/get-profile", requireAuth, (req, res) => {
    const userId = req.user.id; // Access user id from the JWT payload

    // Query to fetch the user details
    db.query(
        "SELECT id, name, college, year, accommodation, role FROM users WHERE id = ?",
        [userId],
        (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ error: "Database error!" });
            }
            if (results.length === 0) {
                return res.status(404).json({ error: "User not found!" });
            }

            const user = results[0];
            user.qr_code_id = `user_${user.id}.png`; // Dynamically add qr_code_id based on user id

            res.json(user); // Send the updated user data
        }
    );
});

// Update User Profile Route
// POST method for updating profile
router.post("/update-profile", requireAuth, (req, res) => {
    const userId = req.user.id; // Access user id from the JWT payload
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

            // Send success response
            res.status(200).json({ message: "Profile updated successfully!" });
        }
    );
});

export default router;
