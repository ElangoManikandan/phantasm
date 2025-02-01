import express from "express";
import db from "../utils/db.js";
import { requireAuth } from "./middleware.js";

const router = express.Router();

// Register for Event Route
// Event Registration Route using JWT Authentication
router.post("/event/register", requireAuth, (req, res) => {
    const { eventId } = req.body;
    const userId = req.user.id; // Access user id from the JWT payload

    if (!eventId) {
        return res.status(400).json({ error: "Event ID is required!" });
    }

    // Check if the event exists in the events table
    const checkEventQuery = "SELECT id FROM events WHERE id = ?";
    db.query(checkEventQuery, [eventId], (err, results) => {
        if (err) {
            return res.status(500).json({ error: "Database error when checking event!" });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: "Event not found!" });
        }

        // Insert the registration into the registrations table
        const query = "INSERT INTO registrations (user_id, event_id) VALUES (?, ?)";
        db.query(query, [userId, eventId], (err, result) => {
            if (err) {
                if (err.code === "ER_DUP_ENTRY") {
                    return res.status(400).json({ error: "User already registered for this event!" });
                }
                return res.status(500).json({ error: "Database error!", details: err });
            }

            // Send success response
            res.status(201).json({ message: "Event registration successful!" });
        });
    });
});

// Fetch Registered Events Route
// Fetch Registered Events for a User using JWT Authentication
router.get("/user/events", requireAuth, (req, res) => {
    const userId = req.user.id; // Access user id from the JWT payload

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

// Get All Events Route
router.get("/get-events", requireAuth, (req, res) => {
    const query = "SELECT id, name, DATE_FORMAT(date, '%d-%m-%Y') AS date, TIME_FORMAT(time, '%H:%i:%s') AS time FROM events";

    db.query(query, (err, results) => {
        if (err) {
            console.error("Error fetching events:", err);
            return res.status(500).json({ error: "Failed to fetch events." });
        }

        res.json(results); // Send the event details as JSON
    });
});

export default router;
