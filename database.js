const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

// --- LÓGICA DE RUTA INTELIGENTE PARA LA BASE DE DATOS ---
const dbPath = process.env.NODE_ENV === 'production'
    ? '/var/data/asistencia.db' // Ruta para Render
    : './asistencia.db';      // Ruta para tu ordenador

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("Error fatal al abrir la base de datos:", err.message);
        process.exit(1);
    }
    console.log(`Conectado exitosamente a la base de datos en: ${dbPath}`);
});

// --- CREACIÓN DE TABLAS ---
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

    // --- CREACIÓN DE USUARIO ADMIN POR DEFECTO ---
    const adminUser = 'admin';
    const adminPass = 'admin123';
    db.get('SELECT * FROM usuarios WHERE usuario = ?', [adminUser], (err, row) => {
        if (err) return console.error("Error al buscar admin:", err.message);
        if (!row) {
            bcrypt.hash(adminPass, 10, (err, hash) => {
                if (err) return console.error("Error al hashear contraseña:", err.message);
                db.run('INSERT INTO usuarios (nombre, usuario, password, rol) VALUES (?, ?, ?, ?)',
                    ['Administrador', adminUser, hash, 'admin'],
                    (insertErr) => {
                        if (insertErr) return console.error("Error al insertar admin:", insertErr.message);
                        console.log('Usuario administrador por defecto creado.');
                    }
                );
            });
        }
    });
});

module.exports = db;