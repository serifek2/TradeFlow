const fs = require('fs');
const pool = require('./db');
const path = require('path');

const migrationsDir = path.join(__dirname, 'migrations');
const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort();

async function run() {
  for (const file of files) {
    const sqlPath = path.join(migrationsDir, file);
    let sql = fs.readFileSync(sqlPath, 'utf8');
    const statements = sql
      .split('\n')
      .filter(line => !line.trim().startsWith('--'))
      .join('\n')
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0);
    console.log('\n---', file, '---');
    for (const stmt of statements) {
    try {
      await pool.query(stmt);
      console.log('OK:', stmt.substring(0, 60) + '...');
    } catch (err) {
      if (err.message.includes('already exists') || err.code === '42701') {
        console.log('Skip (zaten var):', stmt.substring(0, 50) + '...');
      } else {
        console.error('Hata:', err.message);
        console.error('  Statement:', stmt.substring(0, 100));
      }
    }
  }
  }
  console.log('\nMigration tamamlandı.');
  process.exit(0);
}

run().catch(e => {
  console.error(e);
  process.exit(1);
});
