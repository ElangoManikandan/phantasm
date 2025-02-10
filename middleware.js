import jwt from "jsonwebtoken";
import express from "express";

const router = express.Router();

// ✅ Middleware: Authenticate any logged-in user (User/Admin)
export const requireAuth = (req, res, next) => {
    console.log("🚀 [Middleware] requireAuth Executing...");

    let token = null;

    // ✅ 1. Check for Token in Cookies
    if (req.cookies && req.cookies.authToken) {
        token = req.cookies.authToken;
    } 
    // ✅ 2. Check for Bearer Token in Headers
    else if (req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
        token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
        console.error("❌ [Middleware] No token found in request");
        return res.status(401).json({ error: "Unauthorized: No token provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log("✅ [Middleware] Decoded Token:", decoded);  

        if (!decoded.role) {
            console.error("❌ [Middleware] Missing role in decoded token. Check your JWT generation.");
            return res.status(403).json({ error: "Forbidden: Invalid token data" });
        }

        req.user = decoded; // Attach user data to request object
        next(); // Proceed to the next middleware or route
    } catch (err) {
        console.error("❌ [Middleware] JWT Verification Failed:", err.message);
        return res.status(403).json({ error: "Forbidden: Invalid or expired token" });
    }
};

// ✅ Middleware: Restrict access to Admins only
export const requireAdmin = (req, res, next) => {
    console.log("🚀 [Middleware] requireAdmin Executing...");

    // Ensure requireAuth has already attached the user
    if (!req.user) {
        console.error("❌ [Middleware] No authenticated user found");
        return res.status(401).json({ error: "Unauthorized: Authentication required" });
    }

    if (req.user.role !== "admin") {
        console.error("❌ [Middleware] Access Denied - User is not an admin");
        return res.status(403).json({ error: "Forbidden: Admins only" });
    }

    console.log("✅ [Middleware] Admin authentication successful");
    next(); // Proceed to the next middleware or route
};
