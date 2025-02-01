import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import mysql from 'mysql2/promise';

// Create a connection to the MySQL database
const db = mysql.createPool({
  host:'gateway01.ap-southeast-1.prod.aws.tidbcloud.com',
  user: '43yxnpPZ3zo884a.root',   // Replace with your database user
  password: 'oPWexZ8hDt6o97QT', // Replace with your database password
  database: 'symposium_db'  // Replace with your database name
});

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
                'your-jwt-secret', // Secret key for signing JWT
                { expiresIn: '1h' } // Token expiration time (e.g., 1 hour)
            );

            // Set the JWT token as an HTTP-only cookie
            res.setHeader('Set-Cookie', `token=${token}; HttpOnly; Secure; Path=/; Max-Age=3600; SameSite=Strict`);

            // Redirect based on the user's role
            if (user.role === "admin") {
                return res.redirect("/adminprofile.html"); // Redirect to admin profile
            } else {
                return res.redirect("/profile.html"); // Redirect to user profile
            }
        } catch (error) {
            return res.status(500).json({ error: "Server error!" });
        }
    } else {
        // Handle any other HTTP methods (if necessary)
        res.status(405).json({ error: "Method Not Allowed" });
    }
}
