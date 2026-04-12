const pool = require('../db');

async function run() {
  await pool.query('ALTER TABLE products ADD COLUMN IF NOT EXISTS category VARCHAR(255)');
  await pool.query(
    "CREATE INDEX IF NOT EXISTS idx_products_category ON products (category) WHERE category IS NOT NULL AND category <> ''"
  );
  console.log('OK: products.category hazır.');
  process.exit(0);
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
