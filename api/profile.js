export default async (req, res) => {
    try {
      const user = req.user // From middleware
      
      res.json({
        name: user.name,
        email: user.email,
        role: user.role
      })
    } catch (error) {
      res.status(401).json({ error: 'Unauthorized' })
    }
  }