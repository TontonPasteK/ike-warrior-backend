const { Pool } = require('pg');

const pool = new Pool({
  user: 'ike_warrior_db_user',
  host: 'dpg-cvg4m4vnoe9s73bmndn0g-a',
  database: 'ike_warrior_db',
  password: '63K3iTRztqjax8WqVA4KVAL1dBzqAw9j',
  port: 5432,
  ssl: {
    rejectUnauthorized: false
  }
});

module.exports = pool;
