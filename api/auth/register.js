// api/auth/register.js

import bcrypt from 'bcryptjs';
import { db } from '../../utils/db';  // Assuming you have a db utility
import QRCode from 'qrcode';
import path from 'path';
import fs from 'fs';

export default async function handler(req, res) {
  if (req.method === 'POST') {
    const { name, college, year, email, password, accommodation, role, admin_key } = req.body;

    // Ensure all required fields are provided
    if (!name || !college || !year || !email || !password || !accommodation || !role) {
      return res.status(400).json({ error: "All fields are required!" });
    }

    // Check if the role is either 'user' or 'admin'
    if (role !== 'user' && role !== 'admin') {
      return res.status(400).json({ error: "Invalid role! Choose either 'user' or 'admin'." });
    }

    try {
      // Hash the password before saving it
      const hashedPassword = await bcrypt.hash(password, 10);

      // If the role is 'admin', validate the admin key
      if (role === 'admin' && admin_key !== process.env.ADMIN_KEY) {
        return res.status(400).json({ error: "Invalid admin key!" });
      }

      // Insert the new user into the database
      const query = `INSERT INTO users (name, college, year, email, password, accommodation, role) VALUES (?, ?, ?, ?, ?, ?, ?)`;
      db.query(query, [name, college, year, email, hashedPassword, accommodation, role], async (err, result) => {
        if (err) {
          console.error("Database error:", err);
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: "Email already exists!" });
          }
          return res.status(500).json({ error: "Database error!", details: err });
        }

        const userId = result.insertId; // Get the inserted user's ID

        // Generate QR code ID based on the userId
        const qr_code_id = `PSM_${userId}`;

        // Update the user record with the generated QR code ID
        const updateQuery = `UPDATE users SET qr_code_id = ? WHERE id = ?`;
        db.query(updateQuery, [qr_code_id, userId], async (updateErr) => {
          if (updateErr) {
            return res.status(500).json({ error: "Error updating QR code ID" });
          }

          // Generate the QR code containing only qr_code_id
          const qrData = qr_code_id;  // QR code data now only contains qr_code_id
          const qrCodePath = path.join(process.cwd(), "public", "qrcodes", `user_${userId}.png`);

          // Ensure the QR code directory exists
          const qrCodeDirectory = path.dirname(qrCodePath);
          if (!fs.existsSync(qrCodeDirectory)) {
            fs.mkdirSync(qrCodeDirectory, { recursive: true });
          }

          try {
            await QRCode.toFile(qrCodePath, qrData); // Save the QR code as a file

            // Send appropriate response for user or admin
            if (role === "user") {
              return res.status(201).json({
                message: "User registered successfully!",
                redirectUrl: "/profile.html", // Redirect URL for users
                qrCodeUrl: `/qrcodes/user_${userId}.png` // QR code URL
              });
            } else if (role === "admin") {
              return res.status(201).json({
                message: "Admin registered successfully!",
                redirectUrl: "/adminprofile.html", // Redirect URL for admins
                qrCodeUrl: `/qrcodes/user_${userId}.png` // QR code URL
              });
            }
          } catch (qrError) {
            console.error("QR Code generation error:", qrError);
            return res.status(500).json({ error: "QR Code generation failed!" });
          }
        });
      });
    } catch (error) {
      res.status(500).json({ error: "Server error!" });
    }
  } else {
    // Handle any non-POST requests
    res.status(405).json({ error: "Method Not Allowed" });
  }
}
