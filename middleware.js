import jwt from "jsonwebtoken";
import express from "express";
export const requireAuth = (req, res, next) => {
    console.log("🚀 [Middleware] requireAuth Executing...");

    let token = req.cookies?.authToken || req.headers.authorization?.split(" ")[1];

    if (!token) {
        console.error("❌ No token found in request");
          return res.status(401).json({ error: "Unauthorized:  Kindly Login to Register Events!" });
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


export const requireAdmin = (req, res, next) => {
    console.log("🚀 [Middleware] requireAdmin Executing...");

    if (!req.user) {
        console.error("❌ No user in request. `requireAuth` might have failed.");
        return res.status(403).json({ error: "Unauthorized access!" });
    }

    if (!req.user.id || !req.user.role) {
        console.error("❌ Admin token missing `id` or `role`.");
        return res.status(403).json({ error: "Invalid admin token!" });
    }

    if (req.user.role !== "admin") {
        console.error(`❌ Access denied. Role found: ${req.user.role}`);
        return res.status(403).json({ error: "Admin access required!" });
    }

    console.log("✅ [Middleware] Admin authentication successful");
    next();
};

