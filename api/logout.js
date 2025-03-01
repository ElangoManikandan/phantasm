export default function handler(req, res) {
    if (req.method === 'POST') { // Use POST for logout actions
        res.setHeader('Set-Cookie', 'authToken=; Path=/; HttpOnly; Max-Age=0'); // Clear token if stored in cookies
        return res.status(200).json({ message: "Logout successful!" });
    } 
    return res.status(405).json({ error: "Method Not Allowed" });
}
