import jwt from 'jsonwebtoken'
import { redis } from './redis'

const EXPIRATION_TIME = 86400 // 24 hours in seconds

export const createSession = async (user) => {
  const token = jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: EXPIRATION_TIME }
  )
  
  await redis.set(`session:${user.id}`, JSON.stringify({
    user,
    valid: true,
    expires: Date.now() + EXPIRATION_TIME * 1000
  }))

  return token
}

export const verifySession = async (token) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    const session = await redis.get(`session:${decoded.id}`)
    
    if (!session?.valid || session.expires < Date.now()) {
      throw new Error('Invalid session')
    }
    
    return session.user
  } catch (error) {
    throw new Error('Authentication failed')
  }
}


/*// Authentication middleware
const requireAuth = (req, res, next) => {
  // Your auth logic
};

// Admin check middleware
const requireAdmin = (req, res, next) => {
  // Your admin check logic
};

module.exports = { requireAuth, requireAdmin };*/