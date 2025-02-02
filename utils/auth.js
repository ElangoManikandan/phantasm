import jwt from "jsonwebtoken";
import express from "express";
const router = express.Router();

const EXPIRATION_TIME = '24h' // JWT expiration time

const createSession = (user) => {
  return jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: EXPIRATION_TIME }
  )
}

const verifySession = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET)
  } catch (error) {
    throw new Error('Authentication failed')
  }
}

// Authentication middleware
const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  const token = authHeader.split(' ')[1]

  try {
    const decoded = verifySession(token)
    req.user = decoded
    next()
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' })
  }
}

// Admin check middleware
const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: Admin access required' })
  }
  next()
}

export default {
  createSession,
  verifySession,
  requireAuth,
  requireAdmin
};
;
