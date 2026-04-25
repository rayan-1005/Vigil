// migrations/run.js
'use strict';

const fs   = require('fs');
const path = require('path');
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
});

(async () => {
  const sql = fs.readFileSync(path.join(__dirname, '001_init.sql'), 'utf8');
  try {
    await pool.query(sql);
    console.log('✅  Migration applied successfully');
  } catch (err) {
    console.error('❌  Migration failed:', err.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
})();
