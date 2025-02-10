import jwt from "jsonwebtoken";
import express from "express";
export const requireAuth = (req, res, next) => {
    console.log("🚀 [Middleware] requireAuth Executing...");

    let token = req.cookies?.authToken || req.headers.authorization?.split(" ")[1];

    if (!token) {
        console.error("❌ No token found in request");
        return res.status(401).json({ error: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log("✅ [Middleware] Decoded Token:", decoded);

        // Fix: Use `userId` instead of `id`
        if (!decoded.userId || !decoded.role) {
            console.error("❌ Token missing `userId` or `role`");
            return res.status(403).json({ error: "Invalid token structure" });
        }

        req.user = {
            id: decoded.userId, // Ensure it's correctly stored as `id`
            role: decoded.role
        };

        next();
    } catch (err) {
        console.error("❌ JWT Verification Failed:", err.message);
        return res.status(403).json({ error: "Invalid or expired token" });
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
