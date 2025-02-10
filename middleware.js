import jwt from "jsonwebtoken";

// Middleware to verify authentication token
const requireAuth = (req, res, next) => {
    let token;

    // ✅ 1. Check for Token in Cookies
    if (req.cookies && req.cookies.authToken) {
        token = req.cookies.authToken;
    } 
    // ✅ 2. Check for Bearer Token in Headers
    else if (req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
        token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
        return res.status(401).json({ error: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: "Invalid or expired token" });
    }
};

// Middleware to verify admin role
const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== "admin") {
        return res.status(403).json({ error: "Forbidden: Admins only" });
    }
    next();
};

const verifySession = (req, res, next) => {
    console.log("Incoming request headers:", req.headers);

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Unauthorized: No token provided" });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log("Decoded Token:", decoded); // Debug log
        req.user = decoded; // Attach user data to request

        if (!req.user.id) {
            return res.status(401).json({ error: "Unauthorized: Admin ID missing" });
        }

        next();
    } catch (err) {
        console.error("JWT Verification Failed:", err);
        return res.status(401).json({ error: "Unauthorized: Invalid token" });
    }
};


// Export both middleware functions
export { requireAuth,verifySession };
