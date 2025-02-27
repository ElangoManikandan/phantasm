import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

// Decode the CA certificate from the .env file (Base64 format)
const caCert = process.env.TIDB_CA_CERT
  ? Buffer.from(process.env.TIDB_CA_CERT, "base64")
  : null;

const db = mysql.createPool({
  host: process.env.TIDB_HOST,
  user: process.env.TIDB_USER,
  password: process.env.TIDB_PASSWORD,
  database: process.env.TIDB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  ssl: caCert ? { ca: caCert, rejectUnauthorized: true } : undefined, // Only use SSL if CA exists
});

// ✅ Test Database Connection on Startup
async function testDbConnection() {
  try {
    const connection = await db.getConnection();
    console.log("✅ Database connected successfully!");
    connection.release();
  } catch (err) {
    console.error("❌ Database connection failed:", err.message);
  }
}

testDbConnection();

export default db;
