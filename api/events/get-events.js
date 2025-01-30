import { pool } from '../../utils/db';  // Assuming you are using MySQL with a connection pool

export default async function handler(req, res) {
    if (req.method === 'GET') {
        const query = "SELECT id, name, DATE_FORMAT(date, '%d-%m-%Y') AS date, TIME_FORMAT(time, '%H:%i:%s') AS time FROM events";

        try {
            pool.query(query, (err, results) => {
                if (err) {
                    console.error("Error fetching events:", err);
                    return res.status(500).json({ error: "Failed to fetch events." });
                }

                res.status(200).json(results); // Send event details as JSON
            });
        } catch (error) {
            console.error('Server error:', error);
            res.status(500).json({ error: 'Failed to fetch events due to server error.' });
        }
    } else {
        res.status(405).json({ error: 'Method Not Allowed' }); // Only allow GET requests
    }
}
