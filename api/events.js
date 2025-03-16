import express from "express";
import db from "../utils/db.js";
import { requireAuth } from "./middleware.js"; // Correct import of requireAuth
const router = express.Router();
import nodemailer from "nodemailer";
router.post("/register", requireAuth, async (req, res) => {
    console.log("User data in request:", req.user); // Debugging user session
    const { eventId } = req.body;
    const userId = req.user?.userId;

    if (!userId) {      
        return res.status(401).json({ error: "Unauthorized" });
    }

    if (!eventId) {
        return res.status(400).json({ error: "Event ID is required!" });
    }
    
    try {
        // Check if the event exists
        const [eventExists] = await db.query("SELECT id, name, date, venue FROM events WHERE id = ?", [eventId]);
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

        // Fetch user details
        const [user] = await db.query("SELECT name, email, qr_code_id FROM users WHERE id = ?", [userId]);

        // ✅ Handle case where no user is found
        if (user.length === 0) {
            console.error("Error: User not found in database.");
            return res.status(404).json({ error: "User not found!" });
        }

        // Send confirmation email (Pass qr_code_id instead of userId)
        await sendRegistrationEmail(user[0].name, user[0].email, user[0].qr_code_id, eventExists[0]);

        return res.status(201).json({ message: "Event registration successful!" });

    } catch (error) {
        console.error("Database error:", error);
        return res.status(500).json({ error: "Database error!", details: error });
    }
});

async function sendRegistrationEmail(name, email, qrCodeId, event) {
    const transporter = nodemailer.createTransport({
        service: "Gmail",
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });
const formattedDate = new Date(event.date).toLocaleDateString("en-IN", {
    year: "numeric",
    month: "long",
    day: "numeric",
});

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: `You're Officially Registered! 🎉 – ${event.name}`,
        html: `
            <p>Dear ${name},</p>
            <p>We’re excited to welcome you to <strong>${event.name}</strong> on <strong>${formattedDate}</strong> at <strong>${event.venue}</strong>! Your registration has been confirmed, and we can’t wait to see you there.</p>
            <h3>✅ Your Registration Details:</h3>
            <p><strong>Name:</strong> ${name}</p>
            <p><strong>Event Registered:</strong> ${event.name}</p>
            <p><strong>user ID:</strong> ${qrCodeId}</p>
            <p>Got questions? Feel free to reach out at phantasm25cse@gmail.com. Stay updated by visiting https://phantasm.onrender.com</p>
            <p>See you soon!</p>
            <p><strong>Best Regards,</strong></p>
            <p>Phantasm'25 Team</p>
        `,
    };

    await transporter.sendMail(mailOptions);
}

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
