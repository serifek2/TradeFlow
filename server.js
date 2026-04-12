
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('./db');

const app = express();

const JWT_SECRET = process.env.JWT_SECRET || 'demo-rbac-secret-change-in-production';
const JWT_EXPIRES = '8h';

const FIXED_USER_HASHES = {
  'admin.sistem': '$2b$10$W63rczQFEm9U4AgA.qucu.66jh8qO2VskpZQtVIfXTWTnxe/4DqGG',
  'ali.yilmaz': '$2b$10$.0Cto3qLJJYzG6YOVfa7WusZYPRRrc6WnyMXFPZp7TKMS1RkFsIou',
  'mehmet.demir': '$2b$10$4gv4uu2ftqKfXu4bVWq4Y.rQxlH84Vjl3i0XCb7rb9IKawvr2wXBG',
  'fatma.aydin': bcrypt.hashSync('Tedarik123!', 10)
};
const FIXED_USER_ROLES = {
  'admin.sistem': 'admin',
  'ali.yilmaz': 'kasa',
  'mehmet.demir': 'depo',
  'fatma.aydin': 'tedarik'
};
const PORT = 4000;

// RBAC: Patron=admin, Depo=depo, Satış=kasa, Satın Alma=tedarik
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Yetkili değilsiniz. Giriş yapın.' });
  }
  const token = authHeader.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { username: payload.username, role: payload.role };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Oturum süresi doldu. Tekrar giriş yapın.' });
  }
}

function requireRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Yetkili değilsiniz.' });
    if (allowedRoles.includes(req.user.role)) return next();
    return res.status(403).json({ error: 'Bu işlem için yetkiniz yok.' });
  };
}

// Stok uyarı eşikleri: 20 ve altı = kritik, 21-29 = uyarı seviyesi (30 dahil değil)
const STOCK_CRITICAL_MAX = 20;
const STOCK_WARNING_MIN = 21;
const STOCK_WARNING_MAX = 29;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let registeredUsers = [];

const SIMPLE_PASSWORDS = ['1234', '12345', '123456', '1234567', '12345678', 'password', 'admin', 'qwerty', 'abc123', '111111', '000000'];
function isSimplePassword(pwd) {
  if (!pwd || typeof pwd !== 'string') return true;
  const p = pwd.trim();
  if (p.length < 8) return true;
  if (SIMPLE_PASSWORDS.includes(p.toLowerCase())) return true;
  if (/^\d+$/.test(p)) return true;
  if (/^[a-zA-Z]+$/.test(p)) return true;
  return false;
}

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Backend ayakta, PostgreSQL bağlantılı.' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  console.log('Login isteği:', username);

  if (isSimplePassword(password)) {
    return res.status(401).json({ success: false, error: 'Şifre çok zayıf. En az 8 karakter, harf ve rakam içermelidir.' });
  }

  try {
    const uname = username.trim();
    const hash = FIXED_USER_HASHES[uname];
    let role = null;
    if (hash && await bcrypt.compare(password, hash)) {
      role = FIXED_USER_ROLES[uname];
    } else {
      const user = registeredUsers.find(u => u.username === uname);
      if (user && user.passwordHash && await bcrypt.compare(password, user.passwordHash)) {
        role = user.role;
      }
    }
    if (role) {
      const token = jwt.sign({ username: uname, role }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
      return res.json({ success: true, role, username: uname, token });
    }

    return res.status(401).json({ success: false, error: 'Kullanıcı adı veya şifre hatalı' });
  } catch (err) {
    console.error('Login hash hatası:', err);
    return res.status(500).json({ success: false, error: 'Giriş işlemi başarısız' });
  }
});

// Sadece admin yeni kullanıcı ekleyebilir; rol seçimi zorunlu (kasa, depo, tedarik)
app.post('/api/register', authMiddleware, requireRoles('admin'), async (req, res) => {
  const { fullName, username, password, phone, role } = req.body;

  const allowedRoles = ['kasa', 'depo', 'tedarik'];
  const selectedRole = role && allowedRoles.includes(role) ? role : 'kasa';

  if (!fullName || !username || !password) {
    return res.status(400).json({ error: 'Ad Soyad, kullanıcı adı ve şifre zorunludur' });
  }

  if (username.length < 5) {
    return res.status(400).json({ error: 'Kullanıcı adı en az 5 karakter olmalıdır' });
  }

  if (!/^[a-zA-ZçğıöşüÇĞİÖŞÜ]{2,}[._][a-zA-ZçğıöşüÇĞİÖŞÜ]{2,}$/.test(username.trim())) {
    return res.status(400).json({ error: 'Kullanıcı adı ad.soyad formatında olmalıdır (örn: ahmet.yilmaz)' });
  }

  if (isSimplePassword(password)) {
    return res.status(400).json({ error: 'Şifre çok zayıf. En az 8 karakter, hem harf hem rakam içermelidir.' });
  }

  const reservedUsernames = ['admin.sistem', 'ali.yilmaz', 'mehmet.demir', 'fatma.aydin'];
  const uname = username.trim();
  if (reservedUsernames.includes(uname)) {
    return res.status(409).json({ error: 'Bu kullanıcı adı alınmış' });
  }

  const existingUser = registeredUsers.find(u => u.username === uname);
  if (existingUser) {
    return res.status(409).json({ error: 'Bu kullanıcı adı zaten kayıtlı' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);

    const newUser = {
      id: registeredUsers.length + 1,
      fullName: fullName.trim(),
      username: uname,
      passwordHash,
      phone: phone ? phone.trim() : null,
      role: selectedRole,
      created_at: new Date().toISOString()
    };

    registeredUsers.push(newUser);

    console.log('Yeni kullanıcı kaydedildi:', username, 'rol:', selectedRole);
    res.status(201).json({ ok: true, role: selectedRole });
  } catch (err) {
    console.error('Kayıt hash hatası:', err);
    res.status(500).json({ error: 'Kayıt işlemi başarısız' });
  }
});

app.get('/api/users', authMiddleware, requireRoles('admin'), (req, res) => {
  const usersWithoutPasswords = registeredUsers.map(({ passwordHash, ...user }) => user);
  res.json({ users: usersWithoutPasswords, count: registeredUsers.length });
});

app.get('/api/suppliers', authMiddleware, requireRoles('admin', 'tedarik'), async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM suppliers ORDER BY name');
    res.json({ suppliers: result.rows });
  } catch (err) {
    if (err.code === '42P01') return res.json({ suppliers: [] });
    console.error('Tedarikçi listesi hatası:', err);
    res.status(500).json({ error: 'Tedarikçiler alınamadı' });
  }
});
app.post('/api/suppliers', authMiddleware, requireRoles('admin', 'tedarik'), async (req, res) => {
  const { name, contact_person, phone, email, address, tax_number } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Tedarikçi adı zorunludur' });
  try {
    const result = await pool.query(
      `INSERT INTO suppliers (name, contact_person, phone, email, address, tax_number)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [name.trim(), contact_person?.trim() || null, phone?.trim() || null, email?.trim() || null, address?.trim() || null, tax_number?.trim() || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '42P01') return res.status(500).json({ error: 'suppliers tablosu bulunamadı. migrations/001_add_features.sql çalıştırın.' });
    console.error('Tedarikçi ekleme hatası:', err);
    res.status(500).json({ error: err.message });
  }
});
app.put('/api/suppliers/:id', authMiddleware, requireRoles('admin', 'tedarik'), async (req, res) => {
  const { id } = req.params;
  const { name, contact_person, phone, email, address, tax_number } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Tedarikçi adı zorunludur' });
  try {
    const result = await pool.query(
      `UPDATE suppliers SET name=$1, contact_person=$2, phone=$3, email=$4, address=$5, tax_number=$6
       WHERE id=$7 RETURNING *`,
      [name.trim(), contact_person?.trim() || null, phone?.trim() || null, email?.trim() || null, address?.trim() || null, tax_number?.trim() || null, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Tedarikçi bulunamadı' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Tedarikçi güncelleme hatası:', err);
    res.status(500).json({ error: err.message });
  }
});
app.delete('/api/suppliers/:id', authMiddleware, requireRoles('admin', 'tedarik'), async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM suppliers WHERE id=$1 RETURNING id', [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Tedarikçi bulunamadı' });
    res.json({ success: true });
  } catch (err) {
    console.error('Tedarikçi silme hatası:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/customers', authMiddleware, requireRoles('admin', 'kasa'), async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM customers ORDER BY name');
    res.json({ customers: result.rows });
  } catch (err) {
    if (err.code === '42P01') return res.json({ customers: [] });
    console.error('Müşteri listesi hatası:', err);
    res.status(500).json({ error: 'Müşteriler alınamadı' });
  }
});
app.post('/api/customers', authMiddleware, requireRoles('admin', 'kasa'), async (req, res) => {
  const { name, contact_person, phone, email, address, tax_number } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Müşteri adı zorunludur' });
  try {
    const result = await pool.query(
      `INSERT INTO customers (name, contact_person, phone, email, address, tax_number)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [name.trim(), contact_person?.trim() || null, phone?.trim() || null, email?.trim() || null, address?.trim() || null, tax_number?.trim() || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '42P01') return res.status(500).json({ error: 'customers tablosu bulunamadı. migrations/001_add_features.sql çalıştırın.' });
    console.error('Müşteri ekleme hatası:', err);
    res.status(500).json({ error: err.message });
  }
});
app.put('/api/customers/:id', authMiddleware, requireRoles('admin', 'kasa'), async (req, res) => {
  const { id } = req.params;
  const { name, contact_person, phone, email, address, tax_number } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Müşteri adı zorunludur' });
  try {
    const result = await pool.query(
      `UPDATE customers SET name=$1, contact_person=$2, phone=$3, email=$4, address=$5, tax_number=$6
       WHERE id=$7 RETURNING *`,
      [name.trim(), contact_person?.trim() || null, phone?.trim() || null, email?.trim() || null, address?.trim() || null, tax_number?.trim() || null, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Müşteri bulunamadı' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Müşteri güncelleme hatası:', err);
    res.status(500).json({ error: err.message });
  }
});
app.delete('/api/customers/:id', authMiddleware, requireRoles('admin', 'kasa'), async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM customers WHERE id=$1 RETURNING id', [req.params.id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Müşteri bulunamadı' });
    res.json({ success: true });
  } catch (err) {
    console.error('Müşteri silme hatası:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/visits', authMiddleware, requireRoles('admin', 'kasa'), (req, res) => {
  const { customerName, visitNote } = req.body;

  console.log('Ziyaret ekleme isteği:', { customerName, visitNote });

  if (!customerName || !visitNote) {
    return res.status(400).json({ error: 'Müşteri adı ve ziyaret notu zorunludur' });
  }

  const visitData = {
    id: Date.now(),
    customerName: customerName,
    visitNote: visitNote,
    date: new Date().toISOString().split('T')[0],
    createdAt: new Date().toISOString()
  };

  res.json({ success: true, visit: visitData });
});

app.get('/api/alerts/stock', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, barcode, name, stock_quantity, min_stock
      FROM products
      WHERE stock_quantity <= $1
      ORDER BY stock_quantity ASC
    `, [STOCK_WARNING_MAX]);
    const rows = result.rows || [];
    const criticalStock = rows.filter((p) => Number(p.stock_quantity) <= STOCK_CRITICAL_MAX);
    const warningLevel = rows.filter((p) => {
      const q = Number(p.stock_quantity);
      return q >= STOCK_WARNING_MIN && q <= STOCK_WARNING_MAX;
    });
    res.json({
      criticalStock,
      warningLevel,
      hasAlerts: rows.length > 0
    });
  } catch (err) {
    console.error('Stok uyarı hatası:', err);
    res.status(500).json({ error: 'Stok uyarıları alınamadı' });
  }
});
// Tüm ürünler (stok takibi vb.): kategori adı category_id → categories.name; yoksa eski products.category metin alanı
app.get('/api/products', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        p.id,
        p.barcode,
        p.name,
        p.unit_price::float8 AS unit_price,
        p.stock_quantity,
        p.min_stock,
        p.critical_stock,
        p.expiry_date,
        p.category_id,
        COALESCE(c.name, p.category) AS category_name,
        c.min_stock_threshold AS category_low_threshold
      FROM products p
      LEFT JOIN categories c ON p.category_id = c.id
      ORDER BY p.name ASC
    `);

    const products = (result.rows || []).map((row) => {
      const name =
        row.category_name != null && String(row.category_name).trim() !== ''
          ? String(row.category_name).trim()
          : null;
      let minStock = null;
      if (row.min_stock != null && row.min_stock !== '') {
        const n = Number(row.min_stock);
        if (Number.isFinite(n)) minStock = n;
      }
      return {
        id: row.id,
        barcode: row.barcode,
        name: row.name,
        unit_price: row.unit_price,
        stock_quantity: row.stock_quantity,
        min_stock: minStock,
        critical_stock: row.critical_stock,
        expiry_date: row.expiry_date,
        category_id: row.category_id,
        category: name,
        category_name: name,
        category_low_threshold: row.category_low_threshold,
      };
    });

    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.json({ products });
  } catch (err) {
    console.error('Ürün listesi hatası:', err);
    res.status(500).json({ error: err.message || 'Ürün listesi alınamadı' });
  }
});

// Toplu kategori atama: { assignments: [{ barcode, category }, ...] }
app.post('/api/products/categorize', authMiddleware, requireRoles('admin', 'depo'), async (req, res) => {
  const { assignments } = req.body;
  if (!assignments || !Array.isArray(assignments) || assignments.length === 0) {
    return res.status(400).json({ error: 'assignments gerekli: [{ barcode, category }, ...]' });
  }
  const client = await pool.connect();
  const updated = [];
  const notFound = [];
  try {
    await client.query('BEGIN');
    for (const row of assignments) {
      const bc = String(row.barcode || '').trim();
      const cat = row.category != null ? String(row.category).trim() : '';
      if (!bc) continue;
      const r = await client.query(
        'UPDATE products SET category = $1 WHERE barcode = $2 RETURNING id, barcode, category',
        [cat || null, bc]
      );
      if (r.rowCount === 0) notFound.push(bc);
      else updated.push(r.rows[0]);
    }
    await client.query('COMMIT');
    res.json({ ok: true, updatedCount: updated.length, notFound, updated });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Kategori toplu güncelleme:', e);
    res.status(500).json({ error: e.message || 'Güncelleme başarısız' });
  } finally {
    client.release();
  }
});

// Ürün güncelleme (SKT, min_stock, name, category - depo; admin tüm alanları güncelleyebilir)
app.put('/api/products/:id', authMiddleware, requireRoles('admin', 'depo'), async (req, res) => {
  const { id } = req.params;
  const { name, min_stock, expiry_date, unit_price, category } = req.body;
  const isAdmin = req.user && req.user.role === 'admin';
  try {
    const prodRes = await pool.query('SELECT id, name, min_stock, expiry_date, unit_price FROM products WHERE id = $1', [id]);
    if (prodRes.rowCount === 0) return res.status(404).json({ error: 'Ürün bulunamadı' });
    if (name !== undefined) {
      const dupName = await pool.query(
        `SELECT id FROM products WHERE LOWER(TRIM(name)) = LOWER(TRIM($1)) AND id <> $2`,
        [String(name), id]
      );
      if (dupName.rowCount > 0) {
        return res.status(409).json({
          error: 'Bu ürün adı başka bir kayıtta kullanılıyor. Farklı bir ad seçin veya diğer kaydı düzenleyin.',
        });
      }
    }
    const updates = [];
    const vals = [];
    let idx = 1;
    if (name !== undefined) { updates.push(`name = $${idx}`); vals.push(String(name)); idx++; }
    if (min_stock !== undefined) { updates.push(`min_stock = $${idx}`); vals.push(Number(min_stock)); idx++; }
    if (expiry_date !== undefined) { updates.push(`expiry_date = $${idx}`); vals.push(expiry_date && String(expiry_date).trim() ? expiry_date : null); idx++; }
    if (category !== undefined) {
      updates.push(`category = $${idx}`);
      vals.push(category != null && String(category).trim() !== '' ? String(category).trim() : null);
      idx++;
    }
    if (isAdmin && unit_price !== undefined) { updates.push(`unit_price = $${idx}`); vals.push(Number(unit_price)); idx++; }
    if (updates.length === 0) return res.status(400).json({ error: 'Güncellenecek alan yok' });
    vals.push(id);
    await pool.query(
      `UPDATE products SET ${updates.join(', ')} WHERE id = $${idx}`,
      vals
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Ürün güncelleme hatası:', err);
    res.status(500).json({ error: err.message || 'Güncelleme başarısız' });
  }
});

// Manuel stok giriş/çıkış/düzeltme (admin, depo)
app.post('/api/stock/adjust', authMiddleware, requireRoles('admin', 'depo'), async (req, res) => {
  const { product_id, movement_type, quantity, reason } = req.body;
  const username = req.user?.username || 'unknown';
  if (!product_id || !movement_type || quantity === undefined) {
    return res.status(400).json({ error: 'product_id, movement_type ve quantity zorunlu' });
  }
  const validTypes = ['GIRIS', 'CIKIS', 'DUZELTME'];
  if (!validTypes.includes(movement_type)) {
    return res.status(400).json({ error: 'movement_type: GIRIS, CIKIS veya DUZELTME olmalı' });
  }
  const qty = Number(quantity);
  if (!Number.isFinite(qty) || qty < 0) {
    return res.status(400).json({ error: 'quantity geçerli bir pozitif sayı olmalı' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const prodRes = await client.query('SELECT id, name, stock_quantity FROM products WHERE id = $1', [product_id]);
    if (prodRes.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Ürün bulunamadı' });
    }
    const prod = prodRes.rows[0];
    const prevQty = Number(prod.stock_quantity);
    let newQty;
    if (movement_type === 'GIRIS') {
      newQty = prevQty + qty;
    } else if (movement_type === 'CIKIS') {
      newQty = prevQty - qty;
      if (newQty < 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: `Yetersiz stok. Mevcut: ${prevQty}, çıkış: ${qty}` });
      }
    } else {
      newQty = qty;
    }
    await client.query('UPDATE products SET stock_quantity = $1 WHERE id = $2', [newQty, product_id]);
    await client.query(
      `INSERT INTO stock_movements (product_id, movement_type, quantity, previous_quantity, new_quantity, reason, username)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [product_id, movement_type, qty, prevQty, newQty, reason || null, username]
    );
    await client.query('COMMIT');
    res.json({ success: true, previous_quantity: prevQty, new_quantity: newQty });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Stok düzeltme hatası:', err);
    if (err.message && err.message.includes('stock_movements')) {
      return res.status(500).json({ error: 'stock_movements tablosu bulunamadı. node migrate.js çalıştırın.' });
    }
    res.status(500).json({ error: err.message || 'Stok düzeltme başarısız' });
  } finally {
    client.release();
  }
});

// Stok hareketleri listesi (admin, depo)
app.get('/api/stock/movements', authMiddleware, requireRoles('admin', 'depo'), async (req, res) => {
  const { product_id, limit = 100 } = req.query;
  try {
    let sql = `
      SELECT sm.id, sm.product_id, p.name AS product_name, p.barcode, sm.movement_type, sm.quantity,
             sm.previous_quantity, sm.new_quantity, sm.reason, sm.username, sm.created_at
      FROM stock_movements sm
      JOIN products p ON p.id = sm.product_id
    `;
    const params = [];
    if (product_id) { params.push(product_id); sql += ` WHERE sm.product_id = $${params.length}`; }
    sql += ` ORDER BY sm.created_at DESC LIMIT $${params.length + 1}`;
    params.push(Math.min(parseInt(limit, 10) || 100, 500));
    const result = await pool.query(sql, params);
    res.json({ movements: result.rows || [] });
  } catch (err) {
    console.error('Stok hareketleri hatası:', err);
    if (err.message && err.message.includes('stock_movements')) {
      return res.json({ movements: [] });
    }
    res.status(500).json({ error: 'Stok hareketleri alınamadı' });
  }
});

// Kritik (≤20) ve uyarı seviyesi (21-29) stoktaki ürünler
app.get('/api/products/critical-stock', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, barcode, name, stock_quantity, min_stock
      FROM products
      WHERE stock_quantity <= $1
      ORDER BY stock_quantity ASC
    `, [STOCK_WARNING_MAX]);
    const rows = result.rows || [];
    const critical = rows.filter((p) => Number(p.stock_quantity) <= STOCK_CRITICAL_MAX);
    const warning = rows.filter((p) => {
      const q = Number(p.stock_quantity);
      return q >= STOCK_WARNING_MIN && q <= STOCK_WARNING_MAX;
    });
    res.json({ critical, warning, products: [...critical, ...warning] });
  } catch (err) {
    console.error('Kritik stok listesi hatası:', err);
    res.status(500).json({ error: 'Kritik stok listesi alınamadı' });
  }
});

app.get('/api/alerts/skt', authMiddleware, async (req, res) => {
  try {
    const todayStr = new Date().toISOString().split('T')[0];
    const thirtyDaysLater = new Date();
    thirtyDaysLater.setDate(thirtyDaysLater.getDate() + 30);
    const thirtyDaysStr = thirtyDaysLater.toISOString().split('T')[0];

    try {
      const [expiredRes, upcomingRes] = await Promise.all([
        pool.query(
          `SELECT id, name, expiry_date, stock_quantity FROM products
           WHERE expiry_date IS NOT NULL AND expiry_date < $1
           ORDER BY expiry_date ASC`,
          [todayStr]
        ),
        pool.query(
          `SELECT id, name, expiry_date, stock_quantity FROM products
           WHERE expiry_date IS NOT NULL AND expiry_date >= $1 AND expiry_date <= $2
           ORDER BY expiry_date ASC`,
          [todayStr, thirtyDaysStr]
        )
      ]);
      res.json({ expired: expiredRes.rows, items: upcomingRes.rows });
    } catch (err) {
      if (err.message && err.message.includes('expiry_date')) {
        return res.json({ expired: [], items: [] });
      }
      throw err;
    }
  } catch (err) {
    console.error('SKT uyarı hatası:', err);
    res.status(500).json({ error: 'Uyarı kontrolü yapılamadı' });
  }
});

app.get('/products/:barcode', authMiddleware, async (req, res) => {
  const { barcode } = req.params;
  console.log('Barkod sorgusu:', barcode);

  try {
    const result = await pool.query(
      `
      SELECT 
        id, 
        barcode, 
        name, 
        unit_price::float8 AS unit_price,
        stock_quantity, 
        min_stock,
        category
      FROM products 
      WHERE barcode = $1
      `,
      [barcode]
    );

    if (result.rowCount === 0) {
      console.log('Ürün bulunamadı');
      return res.status(404).json({ message: 'Ürün bulunamadı' });
    }

    const row = result.rows[0];
    console.log('Ürün bulundu:', row.name);
    res.json(row);
  } catch (err) {
    console.error('Postgre ürün sorgu hatası:', err);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

app.post('/products', authMiddleware, requireRoles('admin', 'depo'), async (req, res) => {
  const { barcode, name, unit_price, stock_quantity, min_stock, critical_stock, expiry_date } = req.body;

  if (!barcode || !name || unit_price === undefined) {
    return res.status(400).json({ error: 'barcode, name ve unit_price zorunlu' });
  }

  const price = Number(unit_price);
  const stockQ = stock_quantity === undefined ? 0 : Number(stock_quantity);
  const minS = min_stock === undefined ? 0 : Number(min_stock);
  const critS = critical_stock === undefined ? 0 : Number(critical_stock);
  const expiryDate = (expiry_date && typeof expiry_date === 'string' && expiry_date.trim() !== '') ? expiry_date : null;

  if (!Number.isFinite(price) || price < 0) {
    return res.status(400).json({ error: 'unit_price geçersiz' });
  }
  if (!Number.isFinite(stockQ) || stockQ < 0) {
    return res.status(400).json({ error: 'stock_quantity geçersiz' });
  }
  if (!Number.isFinite(minS) || minS < 0) {
    return res.status(400).json({ error: 'min_stock geçersiz' });
  }

  const nameTrim = String(name).trim();
  const barcodeStr = String(barcode);

  try {
    const existingByBarcode = await pool.query('SELECT id FROM products WHERE barcode = $1 LIMIT 1', [barcodeStr]);
    if (existingByBarcode.rowCount === 0) {
      const dupName = await pool.query(
        `SELECT id, barcode FROM products WHERE LOWER(TRIM(name)) = LOWER($1) AND barcode <> $2`,
        [nameTrim, barcodeStr]
      );
      if (dupName.rowCount > 0) {
        const other = dupName.rows[0];
        return res.status(409).json({
          error:
            'Bu ürün adı zaten başka bir barkodla kayıtlı. Faturada o barkodu kullanın veya ürün adını ayırt edici yapın.',
          existingBarcode: other.barcode,
          existingId: other.id,
        });
      }
    }

    let result;
    const withExpiry = expiryDate !== null;
    
    if (withExpiry) {
      try {
        result = await pool.query(
          `
          INSERT INTO products (barcode, name, unit_price, stock_quantity, min_stock, expiry_date)
          VALUES ($1, $2, $3, $4, $5, $6)
          ON CONFLICT (barcode) DO UPDATE SET
            name = EXCLUDED.name,
            unit_price = EXCLUDED.unit_price,
            stock_quantity = EXCLUDED.stock_quantity,
            min_stock = EXCLUDED.min_stock,
            expiry_date = EXCLUDED.expiry_date
          RETURNING id, barcode, name, unit_price::float8 AS unit_price, stock_quantity, min_stock, expiry_date
          `,
          [String(barcode), String(name), price, stockQ, minS, expiryDate]
        );
      } catch (expiryErr) {
        console.log('expiry_date kolonu bulunamadı, kolon olmadan devam ediliyor...');
        result = await pool.query(
          `
          INSERT INTO products (barcode, name, unit_price, stock_quantity, min_stock)
          VALUES ($1, $2, $3, $4, $5)
          ON CONFLICT (barcode) DO UPDATE SET
            name = EXCLUDED.name,
            unit_price = EXCLUDED.unit_price,
            stock_quantity = EXCLUDED.stock_quantity,
            min_stock = EXCLUDED.min_stock
          RETURNING id, barcode, name, unit_price::float8 AS unit_price, stock_quantity, min_stock
          `,
          [String(barcode), String(name), price, stockQ, minS]
        );
      }
    } else {
      try {
        result = await pool.query(
          `
          INSERT INTO products (barcode, name, unit_price, stock_quantity, min_stock, expiry_date)
          VALUES ($1, $2, $3, $4, $5, NULL)
          ON CONFLICT (barcode) DO UPDATE SET
            name = EXCLUDED.name,
            unit_price = EXCLUDED.unit_price,
            stock_quantity = EXCLUDED.stock_quantity,
            min_stock = EXCLUDED.min_stock,
            expiry_date = EXCLUDED.expiry_date
          RETURNING id, barcode, name, unit_price::float8 AS unit_price, stock_quantity, min_stock, expiry_date
          `,
          [String(barcode), String(name), price, stockQ, minS]
        );
      } catch (expiryErr) {
        result = await pool.query(
          `
          INSERT INTO products (barcode, name, unit_price, stock_quantity, min_stock)
          VALUES ($1, $2, $3, $4, $5)
          ON CONFLICT (barcode) DO UPDATE SET
            name = EXCLUDED.name,
            unit_price = EXCLUDED.unit_price,
            stock_quantity = EXCLUDED.stock_quantity,
            min_stock = EXCLUDED.min_stock
          RETURNING id, barcode, name, unit_price::float8 AS unit_price, stock_quantity, min_stock
          `,
          [String(barcode), String(name), price, stockQ, minS]
        );
      }
    }

    return res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Ürün ekleme hatası:', err);
    return res.status(500).json({ error: 'Ürün eklenemedi: ' + err.message });
  }
});

// Faturaları listele: SATIS için admin/kasa/depo, ALIS için admin/tedarik/depo
app.get('/api/invoices', authMiddleware, async (req, res) => {
  const { type = 'SATIS', limit = 50, startDate, endDate } = req.query;
  const role = req.user?.role;
  const canSatis = role === 'admin' || role === 'kasa' || role === 'depo';
  const canAlis = role === 'admin' || role === 'tedarik' || role === 'depo';
  if (type === 'SATIS' && !canSatis) return res.status(403).json({ error: 'Yetkiniz yok' });
  if (type === 'ALIS' && !canAlis) return res.status(403).json({ error: 'Yetkiniz yok' });
  try {
    const params = [type];
    let sql = `SELECT id, invoice_number, date, customer_name, type, total_amount::float8 AS total_amount
       FROM invoices WHERE type = $1`;
    if (startDate) { params.push(startDate); sql += ` AND date >= $${params.length}`; }
    if (endDate) { params.push(endDate); sql += ` AND date <= $${params.length}`; }
    params.push(Math.min(parseInt(limit, 10) || 50, 100));
    sql += ` ORDER BY date DESC, id DESC LIMIT $${params.length}`;
    const result = await pool.query(sql, params);
    res.json({ invoices: result.rows || [] });
  } catch (err) {
    console.error('Fatura listesi hatası:', err);
    res.status(500).json({ error: 'Fatura listesi alınamadı' });
  }
});

// Fatura detay + kalemler (PDF çıktıları: admin/depo her tür; kasa satış; tedarik alış)
app.get('/api/invoices/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const role = req.user?.role;
  try {
    const invRes = await pool.query(
      `SELECT id, invoice_number, date, customer_name, type, total_amount::float8 AS total_amount, supplier_id, customer_id
       FROM invoices WHERE id = $1`,
      [id]
    );
    if (invRes.rowCount === 0) return res.status(404).json({ error: 'Fatura bulunamadı' });
    const inv = invRes.rows[0];
    const canDetail =
      role === 'admin' ||
      role === 'depo' ||
      (role === 'kasa' && inv.type === 'SATIS') ||
      (role === 'tedarik' && inv.type === 'ALIS');
    if (!canDetail) return res.status(403).json({ error: 'Bu faturayı görüntüleme yetkiniz yok.' });
    const itemsRes = await pool.query(
      `SELECT ii.product_id, ii.quantity, ii.unit_price::float8 AS unit_price, ii.line_total::float8 AS line_total,
              p.name AS product_name, p.barcode
       FROM invoice_items ii JOIN products p ON p.id = ii.product_id WHERE ii.invoice_id = $1 ORDER BY ii.id`,
      [id]
    );
    res.json({ invoice: inv, items: itemsRes.rows || [] });
  } catch (err) {
    console.error('Fatura detay hatası:', err);
    res.status(500).json({ error: 'Fatura alınamadı' });
  }
});

// Fatura kalemlerini getir (iade ekranı için)
app.get('/api/invoices/:id/items', authMiddleware, requireRoles('admin', 'kasa'), async (req, res) => {
  try {
    const invRes = await pool.query(
      'SELECT id, invoice_number, date, customer_name, type FROM invoices WHERE id = $1',
      [req.params.id]
    );
    if (invRes.rowCount === 0) return res.status(404).json({ error: 'Fatura bulunamadı' });
    if (invRes.rows[0].type !== 'SATIS') return res.status(400).json({ error: 'Sadece satış faturaları iade edilebilir' });
    const itemsRes = await pool.query(
      `SELECT ii.product_id, ii.quantity, ii.unit_price::float8 AS unit_price, p.name AS product_name, p.barcode
       FROM invoice_items ii JOIN products p ON p.id = ii.product_id WHERE ii.invoice_id = $1`,
      [req.params.id]
    );
    res.json({ invoice: invRes.rows[0], items: itemsRes.rows || [] });
  } catch (err) {
    console.error('Fatura kalemleri hatası:', err);
    res.status(500).json({ error: 'Fatura kalemleri alınamadı' });
  }
});

// Satış iadesi: ürünleri stoka geri ekler (admin, kasa)
app.post('/api/sales/return', authMiddleware, requireRoles('admin', 'kasa'), async (req, res) => {
  const { invoice_id, items, reason } = req.body;
  const username = req.user?.username || 'unknown';
  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'En az bir iade kalemi gerekli' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let invoiceNumber = '';
    if (invoice_id) {
      const inv = await client.query('SELECT invoice_number, type FROM invoices WHERE id = $1', [invoice_id]);
      if (inv.rowCount === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Fatura bulunamadı' }); }
      if (inv.rows[0].type !== 'SATIS') { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Sadece satış faturası iade edilebilir' }); }
      invoiceNumber = inv.rows[0].invoice_number;
    }
    const movReason = invoiceNumber ? `Satış iadesi - Fatura ${invoiceNumber}` : (reason || 'Satış iadesi');
    for (const row of items) {
      const productId = row.product_id;
      const qty = Math.abs(parseInt(row.quantity, 10) || 0);
      if (!productId || qty <= 0) continue;
      const prodRes = await client.query('SELECT id, name, stock_quantity FROM products WHERE id = $1', [productId]);
      if (prodRes.rowCount === 0) continue;
      const prevQty = Number(prodRes.rows[0].stock_quantity);
      const newQty = prevQty + qty;
      await client.query('UPDATE products SET stock_quantity = $1 WHERE id = $2', [newQty, productId]);
      try {
        await client.query(
          `INSERT INTO stock_movements (product_id, movement_type, quantity, previous_quantity, new_quantity, reason, username)
           VALUES ($1, 'GIRIS', $2, $3, $4, $5, $6)`,
          [productId, qty, prevQty, newQty, movReason, username]
        );
      } catch (e) {
        if (!e.message || !e.message.includes('stock_movements')) throw e;
      }
    }
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Satış iadesi hatası:', err);
    res.status(500).json({ error: err.message || 'İade işlemi başarısız' });
  } finally {
    client.release();
  }
});

app.post('/invoices', authMiddleware, async (req, res) => {
  const { customerName, date, type, items, supplier_id, customer_id } = req.body;

  if (!req.user) return res.status(401).json({ error: 'Yetkili değilsiniz.' });
  if (type === 'SATIS' && !['admin', 'kasa'].includes(req.user.role))
    return res.status(403).json({ error: 'Satış faturası oluşturma yetkiniz yok.' });
  if (type === 'ALIS' && !['admin', 'tedarik'].includes(req.user.role))
    return res.status(403).json({ error: 'Alış faturası oluşturma yetkiniz yok.' });

  let dateStr = (date != null && String(date).trim()) ? String(date).trim() : '';
  if (dateStr.length > 10) dateStr = dateStr.substring(0, 10);
  console.log('Fatura oluşturma isteği:', { customerName, date: dateStr, type, itemsCount: items?.length, supplier_id, customer_id });

  if (!customerName || !dateStr || !type || !items || items.length === 0) {
    return res.status(400).json({ error: 'Eksik fatura bilgisi' });
  }

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    if (!item.id || item.unit_price === undefined || item.quantity === undefined) {
      return res.status(400).json({ error: `Ürün ${i + 1} eksik bilgi içeriyor (id, unit_price veya quantity)` });
    }
  }

  let total = 0;
  items.forEach(item => {
    const unitPrice = Number(item.unit_price);
    const qty = Number(item.quantity);
    total += unitPrice * qty;
  });

  const invoiceNumber = 'INV-' + Date.now();
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const insertCols = ['invoice_number', 'date', 'customer_name', 'type', 'total_amount'];
    const insertVals = [invoiceNumber, dateStr, customerName, type, total];
    if (supplier_id != null) { insertCols.push('supplier_id'); insertVals.push(supplier_id); }
    if (customer_id != null) { insertCols.push('customer_id'); insertVals.push(customer_id); }
    const placeholders = insertVals.map((_, i) => `$${i + 1}`).join(', ');
    const insertSql = `INSERT INTO invoices (${insertCols.join(', ')}) VALUES (${placeholders}) RETURNING id`;
    const insertInvoiceResult = await client.query(insertSql, insertVals);

    const invoiceId = insertInvoiceResult.rows[0].id;
    const criticalProducts = [];

    for (const item of items) {
      const unitPrice = Number(item.unit_price);
      const qty = Number(item.quantity);
      const lineTotal = unitPrice * qty;

      await client.query(
        `
        INSERT INTO invoice_items (invoice_id, product_id, quantity, unit_price, line_total)
        VALUES ($1, $2, $3, $4, $5)
        `,
        [invoiceId, item.id, qty, unitPrice, lineTotal]
      );

      // Ürünün mevcut stok bilgisini al
      const prodRes = await client.query(
        'SELECT stock_quantity, min_stock, name FROM products WHERE id = $1',
        [item.id]
      );

      if (prodRes.rowCount > 0) {
        const prod = prodRes.rows[0];
        let newStock = Number(prod.stock_quantity);

        if (type === 'SATIS') {
          newStock -= qty;
          if (newStock < 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({
              error: 'Yetersiz stok',
              detail: `"${prod.name}" için mevcut stok: ${Number(prod.stock_quantity)}, satılmak istenen: ${qty}. Stok negatif olamaz.`
            });
          }
        } else if (type === 'ALIS') {
          newStock += qty;
        }

        await client.query(
          'UPDATE products SET stock_quantity = $1 WHERE id = $2',
          [newStock, item.id]
        );

        // Stok hareketi kaydı (stock_movements tablosu varsa)
        const movType = type === 'SATIS' ? 'CIKIS' : 'GIRIS';
        const prevQty = Number(prod.stock_quantity);
        try {
          await client.query(
            `INSERT INTO stock_movements (product_id, movement_type, quantity, previous_quantity, new_quantity, reason, username)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [item.id, movType, qty, prevQty, newStock, `Fatura ${invoiceNumber}`, req.user?.username || 'sistem']
          );
        } catch (movErr) {
          // PostgreSQL: transaction içinde hata sonrası başka komut çalıştırılamaz; mutlaka rollback
          throw movErr;
        }

        // Kritik stok kontrolü
        if (newStock < prod.min_stock) {
          criticalProducts.push({
            productId: item.id,
            name: prod.name,
            stock: newStock,
            minStock: prod.min_stock
          });
        }
      }
    }

    await client.query('COMMIT');

    res.json({
      invoiceId,
      invoiceNumber,
      total,
      criticalProducts
    });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Fatura kaydı/işleme hatası:', err);
    const errorMessage = err.message || 'Fatura kaydedilemedi';
    res.status(500).json({ error: errorMessage });
  } finally {
    client.release();
  }
});

//MUHASEBE RAPORLARI
// Kâr/Zarar raporu
app.get('/api/reports/profit-loss', authMiddleware, requireRoles('admin'), async (req, res) => {
  const { startDate, endDate } = req.query;
  try {
    const satis = await pool.query(
      `SELECT COALESCE(SUM(total_amount), 0)::float8 AS total FROM invoices WHERE type='SATIS' AND date BETWEEN $1 AND $2`,
      [startDate || '1900-01-01', endDate || '2100-12-31']
    );
    const alis = await pool.query(
      `SELECT COALESCE(SUM(total_amount), 0)::float8 AS total FROM invoices WHERE type='ALIS' AND date BETWEEN $1 AND $2`,
      [startDate || '1900-01-01', endDate || '2100-12-31']
    );
    const gelir = Number(satis.rows[0]?.total || 0);
    const gider = Number(alis.rows[0]?.total || 0);
    const karZarar = gelir - gider;
    res.json({ gelir, gider, karZarar, period: { startDate: startDate || 'tümü', endDate: endDate || 'tümü' } });
  } catch (err) {
    console.error('Kâr/zarar raporu hatası:', err);
    res.status(500).json({ error: 'Rapor alınamadı' });
  }
});

app.get('/api/reports/income-expense', authMiddleware, requireRoles('admin'), async (req, res) => {
  const { startDate, endDate } = req.query;
  try {
    const result = await pool.query(
      `SELECT type, COALESCE(SUM(total_amount), 0)::float8 AS total
       FROM invoices WHERE date BETWEEN $1 AND $2 GROUP BY type`,
      [startDate || '1900-01-01', endDate || '2100-12-31']
    );
    const gelir = result.rows.find(r => r.type === 'SATIS')?.total || 0;
    const gider = result.rows.find(r => r.type === 'ALIS')?.total || 0;
    res.json({ gelir: Number(gelir), gider: Number(gider) });
  } catch (err) {
    console.error('Gelir-gider hatası:', err);
    res.status(500).json({ error: 'Rapor alınamadı' });
  }
});

app.get('/api/reports/stock-cost', authMiddleware, requireRoles('admin'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.id, p.name, p.barcode, p.stock_quantity,
             COALESCE(p.cost_price, p.unit_price, 0)::float8 AS cost_price,
             p.unit_price::float8 AS unit_price,
             (p.stock_quantity * COALESCE(p.cost_price, p.unit_price, 0))::float8 AS total_cost
      FROM products p
      WHERE p.stock_quantity > 0
    `);
    const rows = result.rows.map(r => ({ ...r, total_cost: Number(r.total_cost) }));
    const toplamMaliyet = rows.reduce((s, r) => s + r.total_cost, 0);
    res.json({ items: rows, toplamMaliyet });
  } catch (err) {
    if (err.message && err.message.includes('cost_price')) {
      const result = await pool.query(`
        SELECT id, name, barcode, stock_quantity, unit_price::float8 AS unit_price,
               (stock_quantity * unit_price)::float8 AS total_cost FROM products WHERE stock_quantity > 0
      `);
      const rows = result.rows.map(r => ({ ...r, cost_price: r.unit_price, total_cost: Number(r.total_cost) }));
      const toplamMaliyet = rows.reduce((s, r) => s + r.total_cost, 0);
      return res.json({ items: rows, toplamMaliyet });
    }
    console.error('Stok maliyet hatası:', err);
    res.status(500).json({ error: 'Rapor alınamadı' });
  }
});

app.get('/api/analytics/daily', authMiddleware, requireRoles('admin', 'kasa', 'tedarik'), async (req, res) => {
  const { startDate, endDate } = req.query;
  const start = startDate || '1900-01-01';
  const end = endDate || '2100-12-31';
  const role = req.user?.role;
  const canSeeExpenses = role === 'admin' || role === 'tedarik';
  const tedarikOnly = role === 'tedarik';
  try {
    let satisRes = { rows: [] };
    let giderRes = { rows: [] };
    if (tedarikOnly) {
      giderRes = await pool.query(
        `SELECT date, COALESCE(SUM(total_amount), 0)::float8 AS total FROM invoices WHERE type='ALIS' AND date BETWEEN $1 AND $2 GROUP BY date ORDER BY date`,
        [start, end]
      );
    } else {
      const [s, g] = await Promise.all([
        pool.query(
          `SELECT date, COALESCE(SUM(total_amount), 0)::float8 AS total FROM invoices WHERE type='SATIS' AND date BETWEEN $1 AND $2 GROUP BY date ORDER BY date`,
          [start, end]
        ),
        canSeeExpenses ? pool.query(
          `SELECT date, COALESCE(SUM(total_amount), 0)::float8 AS total FROM invoices WHERE type='ALIS' AND date BETWEEN $1 AND $2 GROUP BY date ORDER BY date`,
          [start, end]
        ) : { rows: [] }
      ]);
      satisRes = s;
      giderRes = g;
    }
    const giderByDate = {};
    (giderRes.rows || []).forEach(r => { giderByDate[r.date] = Number(r.total); });
    const satisByDate = {};
    (satisRes.rows || []).forEach(r => { satisByDate[r.date] = Number(r.total); });
    const allDates = [...new Set([...(satisRes.rows || []).map(r => r.date), ...(giderRes.rows || []).map(r => r.date)])].sort();
    const data = allDates.map(date => ({
      date,
      total: tedarikOnly ? 0 : (satisByDate[date] || 0),
      totalGider: canSeeExpenses ? (giderByDate[date] || 0) : 0
    }));
    res.json({ data });
  } catch (err) {
    console.error('Günlük analitik hatası:', err);
    res.status(500).json({ error: 'Veri alınamadı' });
  }
});

app.get('/api/analytics/monthly', authMiddleware, requireRoles('admin', 'kasa', 'tedarik'), async (req, res) => {
  const { year } = req.query;
  const y = year || new Date().getFullYear();
  const role = req.user?.role;
  const canSeeExpenses = role === 'admin' || role === 'tedarik';
  const tedarikOnly = role === 'tedarik';
  try {
    let satisRes = { rows: [] };
    let giderRes = { rows: [] };
    if (tedarikOnly) {
      giderRes = await pool.query(
        `SELECT TO_CHAR(date, 'YYYY-MM') AS month, COALESCE(SUM(total_amount), 0)::float8 AS total FROM invoices WHERE type='ALIS' AND EXTRACT(YEAR FROM date) = $1 GROUP BY TO_CHAR(date, 'YYYY-MM') ORDER BY month`,
        [y]
      );
    } else {
      const [s, g] = await Promise.all([
        pool.query(
          `SELECT TO_CHAR(date, 'YYYY-MM') AS month, COALESCE(SUM(total_amount), 0)::float8 AS total FROM invoices WHERE type='SATIS' AND EXTRACT(YEAR FROM date) = $1 GROUP BY TO_CHAR(date, 'YYYY-MM') ORDER BY month`,
          [y]
        ),
        canSeeExpenses ? pool.query(
          `SELECT TO_CHAR(date, 'YYYY-MM') AS month, COALESCE(SUM(total_amount), 0)::float8 AS total FROM invoices WHERE type='ALIS' AND EXTRACT(YEAR FROM date) = $1 GROUP BY TO_CHAR(date, 'YYYY-MM') ORDER BY month`,
          [y]
        ) : { rows: [] }
      ]);
      satisRes = s;
      giderRes = g;
    }
    const giderByMonth = {};
    (giderRes.rows || []).forEach(r => { giderByMonth[r.month] = Number(r.total); });
    const allMonths = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12'].map(m => y + '-' + m);
    const satisByMonth = {};
    (satisRes.rows || []).forEach(r => { satisByMonth[r.month] = Number(r.total); });
    const data = allMonths.map(month => ({
      month,
      total: tedarikOnly ? 0 : (satisByMonth[month] || 0),
      totalGider: canSeeExpenses ? (giderByMonth[month] || 0) : 0
    }));
    res.json({ data });
  } catch (err) {
    console.error('Aylık analitik hatası:', err);
    res.status(500).json({ error: 'Veri alınamadı' });
  }
});

// En çok satan ürünler (tarih aralığına göre)
app.get('/api/analytics/top-products', authMiddleware, requireRoles('admin', 'kasa'), async (req, res) => {
  const { startDate, endDate, limit } = req.query;
  const lim = Math.min(parseInt(limit, 10) || 10, 50);
  try {
    const result = await pool.query(
      `SELECT p.id, p.name, p.barcode,
              SUM(ii.quantity) AS total_quantity,
              COALESCE(SUM(ii.line_total), 0)::float8 AS total_amount
       FROM invoice_items ii
       JOIN products p ON p.id = ii.product_id
       JOIN invoices i ON i.id = ii.invoice_id AND i.type = 'SATIS'
       WHERE i.date BETWEEN $1 AND $2
       GROUP BY p.id, p.name, p.barcode
       ORDER BY total_quantity DESC
       LIMIT $3`,
      [startDate || '1900-01-01', endDate || '2100-12-31', lim]
    );
    res.json({
      data: result.rows.map(r => ({
        id: r.id,
        name: r.name,
        barcode: r.barcode,
        total_quantity: Number(r.total_quantity),
        total_amount: Number(r.total_amount)
      }))
    });
  } catch (err) {
    console.error('En çok satan ürünler hatası:', err);
    res.status(500).json({ error: 'Veri alınamadı' });
  }
});

app.get('/api/analytics/dashboard', authMiddleware, async (req, res) => {
  try {
    // Yerel tarih kullan (UTC değil); fatura tarihleri kullanıcının yerel günü ile uyumlu olsun
    const now = new Date();
    const today = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0');
    const thisMonth = today.substring(0, 7);
    const lastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1).toISOString().split('T')[0].substring(0, 7);
    const canSeeSales = req.user && ['admin', 'kasa', 'depo'].includes(req.user.role);
    const canSeeExpenses = req.user && (req.user.role === 'admin' || req.user.role === 'tedarik');

    const [gunluk, aylik, oncekiAylik, gunlukGiderQ, aylikGiderQ, stokUyari, sktUyari] = await Promise.all([
      canSeeSales ? pool.query(`SELECT COALESCE(SUM(total_amount), 0)::float8 AS total FROM invoices WHERE type='SATIS' AND date = $1`, [today]) : { rows: [{ total: 0 }] },
      canSeeSales ? pool.query(`SELECT COALESCE(SUM(total_amount), 0)::float8 AS total FROM invoices WHERE type='SATIS' AND TO_CHAR(date, 'YYYY-MM') = $1`, [thisMonth]) : { rows: [{ total: 0 }] },
      canSeeSales ? pool.query(`SELECT COALESCE(SUM(total_amount), 0)::float8 AS total FROM invoices WHERE type='SATIS' AND TO_CHAR(date, 'YYYY-MM') = $1`, [lastMonth]) : { rows: [{ total: 0 }] },
      canSeeExpenses ? pool.query(`SELECT COALESCE(SUM(total_amount), 0)::float8 AS total FROM invoices WHERE type='ALIS' AND date = $1`, [today]) : { rows: [{ total: 0 }] },
      canSeeExpenses ? pool.query(`SELECT COALESCE(SUM(total_amount), 0)::float8 AS total FROM invoices WHERE type='ALIS' AND TO_CHAR(date, 'YYYY-MM') = $1`, [thisMonth]) : { rows: [{ total: 0 }] },
      pool.query(`SELECT COUNT(*) AS cnt FROM products WHERE stock_quantity <= $1`, [STOCK_WARNING_MAX]).catch(() => ({ rows: [{ cnt: 0 }] })),
      pool.query(`SELECT COUNT(*) AS cnt FROM products WHERE expiry_date IS NOT NULL AND expiry_date <= $1`, [new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]]).catch(() => ({ rows: [{ cnt: 0 }] }))
    ]);

    const gunlukSatis = Number(gunluk.rows[0]?.total || 0);
    const aylikSatis = Number(aylik.rows[0]?.total || 0);
    const oncekiAylikSatis = Number(oncekiAylik.rows[0]?.total || 0);
    const aylikDegisim = oncekiAylikSatis > 0 ? ((aylikSatis - oncekiAylikSatis) / oncekiAylikSatis * 100).toFixed(1) : 0;
    const gunlukGider = Number(gunlukGiderQ.rows[0]?.total || 0);
    const aylikGider = Number(aylikGiderQ.rows[0]?.total || 0);

    res.json({
      gunlukSatis,
      aylikSatis,
      oncekiAylikSatis,
      aylikDegisimYuzde: Number(aylikDegisim),
      gunlukGider,
      aylikGider,
      stokUyariSayisi: Number(stokUyari.rows[0]?.cnt || 0),
      sktUyariSayisi: Number(sktUyari.rows[0]?.cnt || 0)
    });
  } catch (err) {
    console.error('Dashboard hatası:', err);
    res.status(500).json({ error: 'Dashboard verisi alınamadı' });
  }
});

// Root → index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  const before = registeredUsers.length;
  registeredUsers = registeredUsers.filter(u => u.passwordHash);
  if (before > registeredUsers.length) {
    console.log(`${before - registeredUsers.length} eski format kullanıcı kaydı kaldırıldı.`);
  }
  console.log(`Sunucu ${PORT} portunda ayakta: http://localhost:${PORT}`);
});
