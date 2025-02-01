import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import path from "path";
import fs from "fs";
import QRCode from "qrcode";
import { generateToken } from "../utils/auth";
import db from "../utils/db";

const router = express.Router();

router.post("/register", async (req, res) => {
    const { name, college, year, email, password, accommodation, role, admin_key } = req.body;

    // Ensure all required fields are provided
    if (!name || !college || !year || !email || !password || !accommodation || !role) {
        return res.status(400).json({ error: "All fields are required!" });
    }

    // Check if the role is either 'user' or 'admin'
    if (role !== "user" && role !== "admin") {
        return res.status(400).json({ error: "Invalid role! Choose either 'user' or 'admin'." });
    }

    try {
        // Hash the password before saving it
        const hashedPassword = await bcrypt.hash(password, 10);

        // If the role is 'admin', validate the admin key
        if (role === "admin" && admin_key !== process.env.ADMIN_KEY) {
            return res.status(400).json({ error: "Invalid admin key!" });
        }

        // Insert the new user into the database
        const query = `INSERT INTO users (name, college, year, email, password, accommodation, role) VALUES (?, ?, ?, ?, ?, ?, ?)`;
        db.query(query, [name, college, year, email, hashedPassword, accommodation, role], async (err, result) => {
            if (err) {
                console.error("Database error:", err);
                if (err.code === "ER_DUP_ENTRY") {
                    return res.status(400).json({ error: "Email already exists!" });
                }
                return res.status(500).json({ error: "Database error!", details: err });
            }

            const userId = result.insertId; // Get the inserted user's ID

            // Generate QR code ID based on the userId
            const qr_code_id = `PSM_${userId}`;

            // Update the user record with the generated QR code ID
            const updateQuery = `UPDATE users SET qr_code_id = ? WHERE id = ?`;
            db.query(updateQuery, [qr_code_id, userId], async (updateErr) => {
                if (updateErr) {
                    return res.status(500).json({ error: "Error updating QR code ID" });
                }

                // Generate the QR code containing only qr_code_id
                const qrData = qr_code_id;  // QR code data now only contains qr_code_id
                const qrCodePath = path.join(__dirname, "public", "qrcodes", `user_${userId}.png`);

                // Ensure the QR code directory exists
                const qrCodeDirectory = path.dirname(qrCodePath);
                if (!fs.existsSync(qrCodeDirectory)) {
                    fs.mkdirSync(qrCodeDirectory, { recursive: true });
                }

                try {
                    await QRCode.toFile(qrCodePath, qrData); // Save the QR code as a file

                    // Generate a JWT for the user
                    const token = jwt.sign(
                        { id: userId, role: role, email: email },  // Payload containing user data
                        process.env.JWT_SECRET,                     // Secret for signing the JWT
                        { expiresIn: "1h" }                         // Token expiry (1 hour)
                    );

                    // Send appropriate response for user or admin with JWT token
                    if (role === "user") {
                        return res.status(201).json({
                            message: "User registered successfully!",
                            redirectUrl: "/profile.html", // Redirect URL for users
                            qrCodeUrl: `/qrcodes/user_${userId}.png`, // QR code URL
                            token: token  // Send JWT token for the user
                        });
                    } else if (role === "admin") {
                        return res.status(201).json({
                            message: "Admin registered successfully!",
                            redirectUrl: "/adminprofile.html", // Redirect URL for admins
                            qrCodeUrl: `/qrcodes/user_${userId}.png`, // QR code URL
                            token: token  // Send JWT token for the admin
                        });
                    }
                } catch (qrError) {
                    console.error("QR Code generation error:", qrError);
                    return res.status(500).json({ error: "QR Code generation failed!" });
                }
            });
        });
    } catch (error) {
        res.status(500).json({ error: "Server error!" });
    }
});


// User Login Route

router.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required!" });
    }

    try {
        const query = `SELECT * FROM users WHERE email = ?`;
        db.query(query, [email], async (err, results) => {
            if (err) return res.status(500).json({ error: "Database error!" });
            if (results.length === 0) return res.status(404).json({ error: "User not found!" });

            const user = results[0];
            const isPasswordValid = await bcrypt.compare(password, user.password);

            if (!isPasswordValid) return res.status(401).json({ error: "Invalid credentials!" });

            // Generate a JWT token for the user
            const token = jwt.sign(
                { id: user.id, role: user.role, email: user.email },  // Payload containing user info
                process.env.JWT_SECRET,                              // Secret for signing the JWT
                { expiresIn: "1h" }                                  // Token expiry time (1 hour)
            );

            // Send the token and user details in the response
            return res.status(200).json({
                message: "Login successful",
                token: token,  // Send JWT token
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    role: user.role,
                }
            });
        });
    } catch (error) {
        res.status(500).json({ error: "Server error!" });
    }
});


// Check Authentication Status Route

router.get("/check-authentication", (req, res) => {
    // Get the JWT token from the authorization header
    const token = req.headers.authorization?.split(" ")[1]; // Bearer <token>

    if (!token) {
        return res.status(401).json({ error: "Not authenticated" });
    }

    // Verify the JWT token
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify and decode the token
        res.json({ message: "Authenticated", user: decoded }); // Send back the user details
    } catch (err) {
        res.status(403).json({ error: "Invalid token" });
    }
});

// Forgot Password Route
router.post('/forgot-password', (req, res) => {
    const { email } = req.body;

    // Ensure the email is provided
    if (!email) {
        return res.status(400).json({ success: false, message: "Email is required." });
    }

    // Query to check if the email exists in the database
    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (results.length > 0) {
            // Email found, return success
            return res.status(200).json({ success: true, message: 'Email found. A password reset link has been sent.' });
        } else {
            // Email not found
            return res.status(404).json({ success: false, message: 'Email not found.' });
        }
    });
});


// Route to handle resetting the password
router.post('/reset-password', (req, res) => {
    const { email, newPassword } = req.body;

    // Validate the new password (e.g., check length, special characters)
    if (newPassword.length < 6) {
        return res.status(400).json({ success: false, message: 'Password must be at least 6 characters long' });
    }

    // Hash the new password before saving it
    bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({ success: false, message: 'Error hashing password' });
        }

        // Update the password in the database
        const query = 'UPDATE users SET password = ? WHERE email = ?';
        db.query(query, [hashedPassword, email], (err, results) => {
            if (err) {
                console.error('Database query error:', err);
                return res.status(500).json({ success: false, message: 'Database error' });
            }

            if (results.affectedRows > 0) {
                // Password updated successfully
                return res.status(200).json({ success: true, message: 'Password successfully reset' });
            } else {
                // User not found or update failed
                return res.status(404).json({ success: false, message: 'User not found or failed to reset password' });
            }
        });
    });
});

export default router;
