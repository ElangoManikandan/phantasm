export default function handler(req, res) {
    if (req.method === 'POST') {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ success: false, message: "Email is required" });
        }

        // Query to check if the email exists in the database
        const query = 'SELECT * FROM users WHERE email = ?';
        
        // Assuming you have a MySQL connection pool (db is your database client)
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
    } else {
        res.status(405).json({ success: false, message: "Method Not Allowed" });
    }
}
