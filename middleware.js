import jwt from "jsonwebtoken";

export const requireAuth = (req, res, next) => {
    console.log("\n🚀 [Middleware] requireAuth Executing...");

    // ✅ Extract token from Authorization header
    let token = req.headers.authorization?.split(" ")[1];
    console.log("🔍 Extracted Token:", token ? "[Token Present]" : "[No Token]");

    if (!token || token === "null" || token === "undefined") {
        console.error("❌ No valid token found in request");
        return res.status(401).json({ error: "Authentication required" });
    }

    try {
        // ✅ Verify JWT
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log("✅ [Middleware] Decoded Token:", decoded);

        // ✅ Validate token structure
        if (!decoded.userId || !decoded.role) {
            console.error("❌ Token missing `userId` or `role`");
            return res.status(403).json({ error: "Invalid token structure" });
        }

        // ✅ Attach user data to request
        req.user = { id: decoded.userId, role: decoded.role };
        console.log(`✅ [Middleware] Authenticated User ID: ${req.user.id}, Role: ${req.user.role}`);

        next();
    } catch (err) {
        console.error("❌ JWT Verification Failed:", err.message);

        // ✅ Distinguish error types
        if (err.name === "TokenExpiredError") {
            return res.status(401).json({ error: "Token expired. Please log in again." });
        } else if (err.name === "JsonWebTokenError") {
            return res.status(403).json({ error: "Invalid token. Please log in again." });
        }

        return res.status(403).json({ error: "Authentication failed." });
    }
};


export const requireAdmin = (req, res, next) => {
    console.log("\n🚀 [Middleware] requireAdmin Executing...");
    console.log("🔍 User Object in Request:", req.user);

    if (!req.user || !req.user.id || !req.user.role) {
        console.error("❌ No valid user data in request. `requireAuth` might have failed.");
        return res.status(403).json({ error: "Unauthorized access!" });
    }

    // ✅ Check admin privileges
    if (req.user.role !== "admin") {
        console.error(`❌ Access denied. Role found: ${req.user.role}`);
        return res.status(403).json({ error: "Admin access required!" });
    }

    console.log("✅ [Middleware] Admin authentication successful");
    next();
};

