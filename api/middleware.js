const jwt = require("jsonwebtoken");

const requireAuth = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1]; // Extract token from the Authorization header

    if (!token) return res.status(401).json({ error: "Unauthorized" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify the token with the secret
        req.user = decoded; // Attach decoded user data to request
        next(); // Proceed to the next middleware/route handler
    } catch (err) {
        return res.status(403).json({ error: "Invalid token" }); // Invalid token error
    }
};
const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== "admin") {
        return res.status(403).json({ error: "Forbidden: Admins only" });
    }
    next();
};

module.exports = { requireAuth, requireAdmin };
