import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from '../../utils/db';  // Assuming you're using MySQL with a connection pool

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";  // Make sure to set a secret in your environment variables

export default async function handler(req, res) {
    if (req.method === 'POST') {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required!" });
        }

        try {
            const query = `SELECT * FROM users WHERE email = ?`;
            pool.query(query, [email], async (err, results) => {
                if (err) {
                    return res.status(500).json({ error: "Database error!" });
                }

                if (results.length === 0) {
                    return res.status(404).json({ error: "User not found!" });
                }

                const user = results[0];
                const isPasswordValid = await bcrypt.compare(password, user.password);

                if (!isPasswordValid) {
                    return res.status(401).json({ error: "Invalid credentials!" });
                }

                // Create a JWT token containing user details
                const token = jwt.sign(
                    { id: user.id, name: user.name, email: user.email, role: user.role },
                    JWT_SECRET,
                    { expiresIn: '1h' } // Token expires in 1 hour
                );

                // Send the token in the response (you can also set it as an HttpOnly cookie if you prefer)
                res.status(200).json({
                    message: "Login successful!",
                    token,
                    redirectUrl: user.role === 'admin' ? '/adminprofile.html' : '/profile.html',
                });
            });
        } catch (error) {
            res.status(500).json({ error: "Server error!" });
        }
    } else {
        res.status(405).json({ error: "Method not allowed!" });
    }
}
