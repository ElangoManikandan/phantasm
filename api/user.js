import express from 'express';
import db from "../utils/db.js"; // Assuming db.query is your SQL query function
import jwt from 'jsonwebtoken';
import { requireAuth } from "./middleware.js"; 

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET; // Use your secret for JWT


export default router;
