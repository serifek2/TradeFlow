CREATE TABLE IF NOT EXISTS categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    min_stock_threshold INT
);

ALTER TABLE products
ADD COLUMN IF NOT EXISTS category VARCHAR(255);

ALTER TABLE products
ADD COLUMN IF NOT EXISTS category_id INT;

ALTER TABLE products
ADD CONSTRAINT fk_products_category
FOREIGN KEY (category_id)
REFERENCES categories(id);