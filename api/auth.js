import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import QRCode from 'qrcode';
import path from 'path';
import fs from 'fs';
import db from '../../utils/db';

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

export default async function handler(req, res) {
    const { method } = req;
    
    switch (method) {
        case 'POST':
            if (req.body.type === 'login') {
                return handleLogin(req, res);
            } else if (req.body.type === 'register') {
                return handleRegister(req, res);
            } else if (req.body.type === 'password-reset') {
                return handlePasswordReset(req, res);
            }
            return res.status(400).json({ error: 'Invalid request type' });
        
        case 'GET':
            return checkAuth(req, res);
        
        default:
            return res.status(405).json({ error: 'Method Not Allowed' });
    }
}

async function handleLogin(req, res) {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required!' });
    }
    
    try {
        const [users] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found!' });
        }
        
        const user = users[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials!' });
        }
        
        const token = jwt.sign(
            { id: user.id, name: user.name, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );
        
        return res.status(200).json({
            message: 'Login successful!',
            token,
            redirectUrl: user.role === 'admin' ? '/adminprofile.html' : '/profile.html',
        });
    } catch (error) {
        return res.status(500).json({ error: 'Server error!' });
    }
}

async function handleRegister(req, res) {
    const { name, college, year, email, password, accommodation, role, admin_key } = req.body;
    if (!name || !college || !year || !email || !password || !accommodation || !role) {
        return res.status(400).json({ error: 'All fields are required!' });
    }
    if (role === 'admin' && admin_key !== process.env.ADMIN_KEY) {
        return res.status(400).json({ error: 'Invalid admin key!' });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await db.promise().query(
            'INSERT INTO users (name, college, year, email, password, accommodation, role) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [name, college, year, email, hashedPassword, accommodation, role]
        );
        
        const userId = result[0].insertId;
        const qr_code_id = `PSM_${userId}`;
        await db.promise().query('UPDATE users SET qr_code_id = ? WHERE id = ?', [qr_code_id, userId]);
        
        const qrCodePath = path.join(process.cwd(), 'public', 'qrcodes', `user_${userId}.png`);
        if (!fs.existsSync(path.dirname(qrCodePath))) {
            fs.mkdirSync(path.dirname(qrCodePath), { recursive: true });
        }
        await QRCode.toFile(qrCodePath, qr_code_id);
        
        return res.status(201).json({
            message: role === 'admin' ? 'Admin registered successfully!' : 'User registered successfully!',
            redirectUrl: role === 'admin' ? '/adminprofile.html' : '/profile.html',
            qrCodeUrl: `/qrcodes/user_${userId}.png`
        });
    } catch (error) {
        return res.status(500).json({ error: 'Server error!' });
    }
}

async function checkAuth(req, res) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return res.status(200).json({ message: 'Authenticated', user: decoded });
    } catch (error) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

async function handlePasswordReset(req, res) {
    const { email, newPassword } = req.body;
    if (!email || !newPassword || newPassword.length < 6) {
        return res.status(400).json({ success: false, message: 'Invalid email or password too short' });
    }
    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const result = await db.promise().query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
        if (result[0].affectedRows > 0) {
            return res.status(200).json({ success: true, message: 'Password successfully reset' });
        }
        return res.status(404).json({ success: false, message: 'Failed to reset password' });
    } catch (error) {
        return res.status(500).json({ success: false, message: 'Database error' });
    }
}
