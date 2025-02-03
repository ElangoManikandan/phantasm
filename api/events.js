import express from "express";
import db from "../utils/db.js";
import middleware from "../middleware.js";
const { requireAuth } = middleware;

const router = express.Router();

// 🟢 Register for Event Route with Duplicate Check
router.post("/event/register", requireAuth, async (req, res) => {
    const { eventId } = req.body;
    const userId = req.user.id;

    if (!eventId) {
        return res.status(400).json({ error: "Event ID is required!" });
    }

    try {
        // Check if the event exists
        const [eventExists] = await db.query("SELECT id FROM events WHERE id = ?", [eventId]);
        if (eventExists.length === 0) {
            return res.status(404).json({ error: "Event not found!" });
        }

        // Check if user already registered
        const [alreadyRegistered] = await db.query(
            "SELECT id FROM registrations WHERE user_id = ? AND event_id = ?",
            [userId, eventId]
        );

        if (alreadyRegistered.length > 0) {
            return res.status(400).json({ error: "User already registered for this event!" });
        }

        // Register user for the event
        await db.query("INSERT INTO registrations (user_id, event_id) VALUES (?, ?)", [userId, eventId]);

        return res.status(201).json({ message: "Event registration successful!" });

    } catch (error) {
        console.error("Database error:", error);
        return res.status(500).json({ error: "Database error!", details: error });
    }
});
// 🟢 Get All Events (Public Route)
router.get("/get-events", async (req, res) => {
    try {
        const [events] = await db.query(
            `SELECT id, name, DATE_FORMAT(date, '%d-%m-%Y') AS date, 
            TIME_FORMAT(time, '%H:%i:%s') AS time FROM events`
        );

        res.json(events);
    } catch (error) {
        console.error("Error fetching events:", error);
        res.status(500).json({ error: "Failed to fetch events." });
    }
});

export default router;
