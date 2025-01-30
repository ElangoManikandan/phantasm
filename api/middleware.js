import { verifySession } from '../utils/auth'

export default async function middleware(req, res) {
  // Skip middleware for public routes
  if (req.path === '/api/login' || req.path === '/api/register') {
    return
  }

  try {
    const token = req.cookies?.sessionToken
    if (!token) throw new Error('No token found')
    
    const user = await verifySession(token)
    req.user = user
  } catch (error) {
    return res.status(401).json({ error: 'Unauthorized' })
  }
}

