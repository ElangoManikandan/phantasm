import jwt from "jsonwebtoken";
import express from "express";
const router= express.Router();
export const requireAuth = (req, res, next) => {
    console.log("🚀 Middleware Execution Started");

    console.log("Received Cookies:", req.cookies); // Debugging
    console.log("Received Headers:", req.headers); // Debugging

    let token = null;

    // ✅ 1. Check for Token in Cookies
    if (req.cookies && req.cookies.authToken) {
        token = req.cookies.authToken;
        console.log("✅ Token Found in Cookies:", token);
    } 
    // ✅ 2. Check for Bearer Token in Headers
    else if (req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
        token = req.headers.authorization.split(" ")[1];
        console.log("✅ Token Found in Headers:", token);
    }

    if (!token) {
        console.error("❌ No token found in request");
        return res.status(401).json({ error: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log("✅ Decoded Token:", decoded);
        req.user = decoded;
        next();
    } catch (err) {
        console.error("❌ JWT Verification Failed:", err.message);
        return res.status(403).json({ error: "Invalid or expired token" });
    }
};


export const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== "admin") {
        return res.status(403).json({ error: "Forbidden: Admins only" });
    }
    next();
};
