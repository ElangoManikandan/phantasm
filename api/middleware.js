import jwt from "jsonwebtoken";
import express from "express";
const router = express.Router();

export const requireAuth = (req, res, next) => {
    console.log("🚀 Middleware Execution Started");

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
        console.error("❌ No token found in request");
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log("✅ Decoded Token:", decoded);  // 👀 Debug: Check if `role` exists

        if (!decoded.role) {
            console.error("❌ Missing role in decoded token. Check your JWT generation.");
        }

        req.user = decoded;
        next();
    } catch (err) {
        console.error("❌ JWT Verification Failed:", err.message);
        return res.status(403).json({ error: "Invalid or expired token" });
    }
};
