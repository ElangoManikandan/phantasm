export default function handler(req, res) {
    if (req.method === 'GET') {
        // Simply return a success message on the server-side
        // Client will handle token removal on the frontend
        res.status(200).json({
            message: "Logout successful!",
        });
    } else {
        res.status(405).json({ error: "Method Not Allowed" });
    }
}
