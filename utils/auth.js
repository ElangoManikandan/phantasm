import jwt from "jsonwebtoken";
import express from "express";
const router = express.Router();

const EXPIRATION_TIME = '24h' // JWT expiration time

export const createSession = (user) => {
  return jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: EXPIRATION_TIME }
  )
}

export const verifySession = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET)
  } catch (error) {
    throw new Error('Authentication failed')
  }
}

export const requireAuth = (req, res, next) => {
    console.log("Received Cookies:", req.cookies); // 🔍 Debugging

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
        console.error("No token found in request");
        return res.status(401).json({ error: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log("Decoded Token:", decoded); // 🔍 Debugging
        req.user = decoded;
        next();
    } catch (err) {
        console.error("JWT Verification Failed:", err.message);
        return res.status(403).json({ error: "Invalid or expired token" });
    }
};

// Admin check middleware
export const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: Admin access required' })
  }
  next()
}
;
