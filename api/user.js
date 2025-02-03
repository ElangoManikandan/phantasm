// api/user.js (Create this file to handle user profile data)
import express from 'express';
import db from "../utils/db.js";
import middleware from "../middleware.js";
const { requireAuth } = middleware;

const router = express.Router();

// 🟢 Fetch User Profile
router.get('/profile', requireAuth, async (req, res) => {
    const userId = req.user.id;

    try {
        const [user] = await db.query("SELECT name, college, year, accommodation FROM users WHERE id = ?", [userId]);

        if (user.length === 0) {
            return res.status(404).json({ error: "User not found!" });
        }

        res.status(200).json(user[0]); // Send user profile data
    } catch (error) {
        console.error("Error fetching profile:", error);
        res.status(500).json({ error: "Database error!", details: error });
    }
});

export default router;
