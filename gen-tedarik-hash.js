#!/usr/bin/env node
// Tedarik123! şifresi için bcrypt hash üretir. Çıktıyı server.js'te fatma.aydin satırına yapıştırın.
const bcrypt = require('bcrypt');
const h = bcrypt.hashSync('Tedarik123!', 10);
console.log(h);
