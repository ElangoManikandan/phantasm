import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import db from "../utils/db.js";

export default async function handler(req, res) {
    if (req.method === 'POST') {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required!" });
        }

        try {
            // Query to find user based on email
            const [results] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

            if (results.length === 0) {
                return res.status(404).json({ error: "User not found!" });
            }

            const user = results[0];

            // Compare provided password with the stored hashed password
            const isPasswordValid = await bcrypt.compare(password, user.password);

            if (!isPasswordValid) {
                return res.status(401).json({ error: "Invalid credentials!" });
            }

            // Generate JWT token with user details
            const token = jwt.sign(
                { id: user.id, name: user.name, email: user.email, role: user.role },
                process.env.JWT_SECRET, // Use environment variable for the secret
                { expiresIn: '1h' } // Token expiration time (e.g., 1 hour)
            );

            // Set the JWT token as an HTTP-only cookie
            res.setHeader('Set-Cookie', `token=${token}; HttpOnly; Secure; Path=/; Max-Age=3600; SameSite=Strict`);

            // Respond with the user details, token, and role for the frontend to handle
            return res.status(200).json({
                message: "Login successful!",
                role: user.role,  // Send the role back to the frontend
                token: token  // Send JWT token back
            });

        } catch (error) {
            return res.status(500).json({ error: "Server error!" });
        }
    } else {
        // Handle any other HTTP methods (if necessary)
        res.status(405).json({ error: "Method Not Allowed" });
    }
}
export default login;
