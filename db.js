const { Pool } = require('pg');

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'Bitirmeprojesi',
  password: '12345',
  port: 5432,
});

pool.on('connect', () => {
  console.log('PostgreSQL veritabanına bağlanıldı');
});

pool.on('error', (err) => {
  console.error('PostgreSQL havuz hatası:', err);
});

module.exports = pool;
