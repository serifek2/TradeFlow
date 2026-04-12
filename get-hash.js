const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const h = bcrypt.hashSync('Tedarik123!', 10);
const outPath = path.join(__dirname, 'public', 'tedarik-hash-temp.txt');
fs.writeFileSync(outPath, h);
