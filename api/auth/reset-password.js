import bcrypt from 'bcryptjs';

export default function handler(req, res) {
    if (req.method === 'POST') {
        const { email, newPassword } = req.body;

        if (!email || !newPassword) {
            return res.status(400).json({ success: false, message: 'Email and new password are required' });
        }

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
    } else {
        res.status(405).json({ success: false, message: 'Method Not Allowed' });
    }
}
