const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  uri: 'mysql://43yxnpPZ3zo884a.root:<PASSWORD>@gateway01.ap-southeast-1.prod.aws.tidbcloud.com:4000/symposium_db?ssl={"rejectUnauthorized":true}',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = db;
