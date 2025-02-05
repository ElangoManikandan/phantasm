import jwt from "jsonwebtoken";

// Middleware to check authentication
const requireAuth = (req, res, next) => {
    let token;

    // 1️⃣ Check if token is in Authorization header (Bearer Token)
    if (req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
        token = req.headers.authorization.split(" ")[1];
    } 
    // 2️⃣ Check if token is stored in cookies (for HTTP-only cookie auth)
    else if (req.cookies && req.cookies.authToken) {
        token = req.cookies.authToken;
    }

    // If no token is found, return unauthorized error
    if (!token) {
        return res.status(401).json({ error: "Unauthorized: No token provided" });
    }

    try {
        // Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Attach user data to request object
        next(); // Proceed to the next middleware
    } catch (err) {
        return res.status(403).json({ error: "Forbidden: Invalid or expired token" });
    }
};

// Middleware to restrict access to admins only
const requireAdmin = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ error: "Unauthorized: No user data available" });
    }

    if (req.user.role !== "admin") {
        return res.status(403).json({ error: "Forbidden: Admins only" });
    }

    next();
};

// ✅ Export middleware functions
export default { requireAuth, requireAdmin };
