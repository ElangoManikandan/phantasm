// Import required modules
const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const path = require("path");
const session = require("express-session");
const QRCode = require('qrcode');
const fs = require("fs");
const { Html5Qrcode } = require("html5-qrcode");



// Load environment variables
dotenv.config();

// Database connection setup
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
});

// Connect to the database
db.connect((err) => {
    if (err) {
        console.error("Error connecting to the database:", err);
    } else {
        console.log("Connected to the MySQL database!");
    }
});

// Initialize the Express app
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public"))); // Serve static files

// Add session middleware
app.use(
    session({
        secret: process.env.SESSION_SECRET || "secure_session_key",
        resave: false,
        saveUninitialized: true,
        cookie: {
            secure: false, // Set to false in development (for HTTP)
            httpOnly: true, // Ensures the cookie is not accessible from JavaScript
            sameSite: 'lax', // Allows the cookie to be sent with cross-origin requests
            maxAge: 1000 * 60 * 60 * 24, // Cookie expiration (24 hours)
        },
    })
);

// Middleware for authentication checks
const requireAuth = (req, res, next) => {
    if (!req.session.user) {
        return res.status(401).json({ error: "Not authenticated" });
    }
    next();
};

// Middleware for admin checks
const requireAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.role === 'admin') {
        return next();
    }
    return res.status(403).json({ error: "Access denied. Admins only!" });
};

// User Registration Route
// Registration route
app.post("/register", async (req, res) => {
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

                    // Send appropriate response for user or admin
                    if (role === "user") {
                        return res.status(201).json({
                            message: "User registered successfully!",
                            redirectUrl: "/profile.html", // Redirect URL for users
                            qrCodeUrl: `/qrcodes/user_${userId}.png` // QR code URL
                        });
                    } else if (role === "admin") {
                        return res.status(201).json({
                            message: "Admin registered successfully!",
                            redirectUrl: "/adminprofile.html", // Redirect URL for admins
                            qrCodeUrl: `/qrcodes/user_${userId}.png` // QR code URL
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

// Endpoint to check authentication status
app.get("/check-authentication", (req, res) => {
    if (!req.session.user) {
        return res.json({ error: "Not authenticated" });
    }
    res.json({ message: "Authenticated" });
});

// User Login Route
app.post("/login", async (req, res) => {
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

            // Save user information in session
            req.session.user = {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role, // Role to differentiate admin and user
            };

            // Redirect based on user role
            if (user.role === "admin") {
                return res.redirect("/adminprofile.html"); // Redirect to admin profile
            } else {
                return res.redirect("/profile.html"); // Redirect to user profile
            }
        });
    } catch (error) {
        res.status(500).json({ error: "Server error!" });
    }
});

// Serve Profile Page
app.get("/profile", requireAuth, (req, res) => {
    // Check if user is authenticated via the session
    if (!req.session.user) {
        return res.redirect("/login.html"); // Redirect to login if not authenticated
    }
    res.sendFile(path.join(__dirname, "public", "profile.html"));
});

// Get Profile Route
app.get("/get-profile", requireAuth, (req, res) => {
    const userId = req.session.user.id;

    db.query(
        "SELECT id, name, college, year, accommodation, role FROM users WHERE id = ?",
        [userId],
        (err, results) => {
            if (err) return res.status(500).json({ error: "Database error!" });
            if (results.length === 0) return res.status(404).json({ error: "User not found!" });

            const user = results[0];
            user.qr_code_id = `user_${user.id}.png`; // Dynamically add qr_code_id based on user id

            res.json(user); // Send the updated user data
        }
    );
});

// Route to handle forgot password (email validation)
app.post('/forgot-password', (req, res) => {
    const { email } = req.body;

    // Query to check if the email exists in the database
    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ success: false, message: 'Database error' });
        }

        if (results.length > 0) {
            // Email found, return success
            return res.status(200).json({ success: true });
        } else {
            // Email not found
            return res.status(404).json({ success: false, message: 'Email not found' });
        }
    });
});

app.post('/admin/login', async (req, res) => {
    const { email, password } = req.body;

    // Authenticate admin (replace this with your actual authentication logic)
    const [admin] = await db.promise().query(
        "SELECT * FROM users WHERE email = ? AND role = 'admin'",
        [email]
    );

    if (admin.length === 0 || !bcrypt.compareSync(password, admin[0].password)) {
        return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    // Set the session with admin's ID
    req.session.userId = admin[0].id;

    res.status(200).json({ success: true, message: "Admin logged in successfully." });
});

// Route to handle resetting the password
app.post('/reset-password', (req, res) => {
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
                return res.status(404).json({ success: false, message: 'Failed to reset password' });
            }
        });
    });
});
app.get('/get-admin-profile', requireAdmin, (req, res) => {
    const userId = req.session.user.id;

    db.query(
        "SELECT name, email, college FROM users WHERE id = ? AND role = 'admin'",
        [userId],
        (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ error: "Database error!" });
            }
            if (results.length === 0) {
                return res.status(404).json({ error: "Admin not found!" });
            }
            res.json(results[0]);
        }
    );
});

// 3. Fetch Attendance Details
app.get('/admin/attendance', requireAdmin, (req, res) => {
    const adminId = req.session.user.id;

    db.query(
        `SELECT events.name AS event_name, users.name AS participant_name, 
       attendance.attendance_status, attendance.marked_at
FROM attendance
JOIN events ON attendance.event_id = events.id
JOIN users ON attendance.user_id = users.id
WHERE attendance.admin_id = ?`,
        [adminId],
        (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ error: "Database error!" });
            }
            res.json(results);
        }
    );
});
app.post("/event/register", requireAuth, (req, res) => {
    const { eventId } = req.body;
    const userId = req.session.user.id;

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


// Update User Profile Route
app.post("/update-profile", requireAuth, (req, res) => {
    const { name, college, year, accommodation } = req.body;
    const userId = req.session.user.id;

    if (!name || !college || !year || !accommodation) {
        return res.status(400).json({ error: "All fields are required!" });
    }

    const query = `UPDATE users SET name = ?, college = ?, year = ?, accommodation = ? WHERE id = ?`;
    db.query(query, [name, college, year, accommodation, userId], (err, result) => {
        if (err) return res.status(500).json({ error: "Database error!" });
        if (result.affectedRows === 0) return res.status(404).json({ error: "User not found!" });

        req.session.user.name = name;
        res.status(200).json({ message: "Profile updated successfully!" });
    });
});

// Fetch Registered Events for a User
app.get("/user/events", requireAuth, (req, res) => {
    const userId = req.session.user.id;

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

// 2. Mark Attendance
app.post('/admin/mark-attendance', requireAdmin, async (req, res) => {
    const { qr_code_id, event_id } = req.body;
    const adminId = req.session.user.id;

    if (!qr_code_id || !event_id) {
        return res.status(400).json({ success: false, message: "QR Code ID and Event ID are required." });
    }

    try {
        // Check if the user exists
        const [userResults] = await db.promise().query(
            `SELECT id FROM users WHERE qr_code_id = ?`,
            [qr_code_id]
        );

        if (userResults.length === 0) {
            return res.status(404).json({ success: false, message: "QR Code ID not found!" });
        }

        const userId = userResults[0].id;

        // Check if the event exists
        const [eventResults] = await db.promise().query(
            `SELECT id FROM events WHERE id = ?`,
            [event_id]
        );

        if (eventResults.length === 0) {
            return res.status(404).json({ success: false, message: "Event ID not found!" });
        }

        // Check if the user is registered for the event
        const [registrationResults] = await db.promise().query(
            `SELECT id FROM registrations WHERE user_id = ? AND event_id = ?`,
            [userId, event_id]
        );

        if (registrationResults.length === 0) {
            // Register the user for the event
            await db.promise().query(
                `INSERT INTO registrations (user_id, event_id) VALUES (?, ?)`,
                [userId, event_id]
            );
        }

        // Check if attendance is already marked
        const [attendanceResults] = await db.promise().query(
            `SELECT id FROM attendance WHERE event_id = ? AND user_id = ?`,
            [event_id, userId]
        );

        if (attendanceResults.length > 0) {
            return res.status(400).json({ success: false, message: "Attendance already marked!" });
        }

        // Mark attendance
        await db.promise().query(
            `INSERT INTO attendance (event_id, user_id, admin_id, attendance_status) 
             VALUES (?, ?, ?, 'present')`,
            [event_id, userId, adminId]
        );

        res.json({ success: true, message: "User registered and attendance marked successfully!" });
    } catch (err) {
        console.error("Database error:", err);
        res.status(500).json({ success: false, message: "Database error!" });
    }
});

// Define the GET /get-events endpoint
app.get("/get-events", (req, res) => {
    const query = "SELECT id, name, DATE_FORMAT(date, '%d-%m-%Y') AS date, TIME_FORMAT(time, '%H:%i:%s') AS time FROM events";

    db.query(query, (err, results) => {
        if (err) {
            console.error("Error fetching events:", err);
            return res.status(500).json({ error: "Failed to fetch events." });
        }

        res.json(results); // Send the event details as JSON
    });
});


// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ success: false, message: 'Could not log out' });
        }

        // Clear the session cookie by setting it with an expired date
        res.clearCookie('connect.sid'); // The default session cookie name is 'connect.sid'

        // Redirect to the homepage or login page
        res.redirect('/');
    });
});

// Root Route
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
