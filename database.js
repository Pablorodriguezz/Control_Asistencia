// database.js (CÓDIGO ACTUALIZADO)

const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

// 1. Determinar la ruta para los datos persistentes
// Render define 'RENDER_DISK_PATH'. Si no, usamos el directorio local para desarrollo.
const dataDir = process.env.RENDER_DISK_PATH || __dirname;
const dbPath = path.join(dataDir, 'asistencia.db');

// 2. Asegurarse de que el directorio de datos existe
// Esto es crucial para el primer arranque en Render, donde el directorio del disco puede no existir.
if (!fs.existsSync(dataDir)){
    fs.mkdirSync(dataDir, { recursive: true });
    console.log(`Directorio de datos creado en: ${dataDir}`);
}

// 3. Crear la conexión a la base de datos en la ruta correcta
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("Error al abrir la base de datos:", err.message);
    } else {
        console.log(`Conectado a la base de datos en: ${dbPath}`);
    }
});

// El resto del código no cambia
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        usuario TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        rol TEXT NOT NULL CHECK(rol IN ('empleado', 'admin'))
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS registros (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER,
        fecha_hora DATETIME NOT NULL,
        tipo TEXT NOT NULL CHECK(tipo IN ('entrada', 'salida')),
        foto_path TEXT,
        FOREIGN KEY (usuario_id) REFERENCES usuarios (id) ON DELETE CASCADE
    )`);

    const adminUser = 'admin';
    const adminPass = 'admin123';
    db.get('SELECT * FROM usuarios WHERE usuario = ?', [adminUser], (err, row) => {
        if (!row) {
            bcrypt.hash(adminPass, 10, (err, hash) => {
                db.run('INSERT INTO usuarios (nombre, usuario, password, rol) VALUES (?, ?, ?, ?)',
                    ['Administrador', adminUser, hash, 'admin']
                );
            });
        }
    });
});

module.exports = db;