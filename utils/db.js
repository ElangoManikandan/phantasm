import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();
// CA certificate from the .env file
const caCert = Buffer.from(process.env.TIDB_CA_CERT, 'base64'); // Assuming base64 encoding for certificate

const db = mysql.createPool({
  host: process.env.TIDB_HOST,
  user: process.env.TIDB_USER,
  password: process.env.TIDB_PASSWORD,
  database: process.env.TIDB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  ssl: {
    ca: caCert,  // Using only the CA certificate for server verification
  },
});

export default db;
