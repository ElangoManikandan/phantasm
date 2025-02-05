import jwt from "jsonwebtoken";

const requireAuth = (req, res, next) => {
    let token;

    // 1️⃣ Check for Bearer Token in Headers
    if (req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
        token = req.headers.authorization.split(" ")[1];
    } 
    // 2️⃣ Check for Token in Cookies
    else if (req.cookies && req.cookies.authToken) {
        token = req.cookies.authToken;
    }

    if (!token) {
        return res.status(401).json({ error: "Unauthorized: No token provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: "Forbidden: Invalid or expired token" });
    }
};


const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== "admin") {
        return res.status(403).json({ error: "Forbidden: Admins only" });
    }
    next();
};

// Export as ESM
export default { requireAuth, requireAdmin };
