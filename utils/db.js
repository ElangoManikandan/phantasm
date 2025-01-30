import mysql from 'mysql2/promise';

let pool;

export const getPool = () => {
  if (!pool) {
    pool = mysql.createPool({
      host: process.env.TIDB_HOST,
      user: process.env.TIDB_USER,
      password: process.env.TIDB_PASSWORD,
      database: process.env.TIDB_DATABASE,
      ssl: { rejectUnauthorized: true },
      waitForConnections: true,
      connectionLimit: 10, // Adjust as needed
      queueLimit: 0
    });
  }
  return pool;
};
