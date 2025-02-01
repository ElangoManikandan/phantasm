const express = require("express");
const db = require("../utils/db");
const { requireAuth } = require("../api/middleware");
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


module.exports = router;
