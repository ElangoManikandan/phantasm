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

// Authentication middleware
export const requireAuth = (req, res, next) => {
  const authToken = req.headers.authorization

  if (!authToken || !authToken.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  const token = authToken.split(' ')[1]

  try {
    const decoded = verifySession(token)
    req.user = decoded
    next()
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' })
  }
}

// Admin check middleware
export const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: Admin access required' })
  }
  next()
}
;
