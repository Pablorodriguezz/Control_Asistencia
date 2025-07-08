// database.js
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const db = new sqlite3.Database('./asistencia.db', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Conectado a la base de datos asistencia.db.');
});

db.serialize(() => {
    // Crear tabla de usuarios
    db.run(`CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        usuario TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        rol TEXT NOT NULL CHECK(rol IN ('empleado', 'admin'))
    )`);

    // Crear tabla de registros
    db.run(`CREATE TABLE IF NOT EXISTS registros (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER,
        fecha_hora DATETIME NOT NULL,
        tipo TEXT NOT NULL CHECK(tipo IN ('entrada', 'salida')),
        foto_path TEXT,
        FOREIGN KEY (usuario_id) REFERENCES usuarios (id) ON DELETE CASCADE
    )`);

    // Insertar un usuario administrador por defecto (SOLO PARA EMPEZAR)
    const adminUser = 'admin';
    const adminPass = 'admin123'; // ¡Cambia esta contraseña!

    db.get('SELECT * FROM usuarios WHERE usuario = ?', [adminUser], (err, row) => {
        if (!row) {
            bcrypt.hash(adminPass, 10, (err, hash) => {
                db.run('INSERT INTO usuarios (nombre, usuario, password, rol) VALUES (?, ?, ?, ?)',
                    ['Administrador', adminUser, hash, 'admin']);
                console.log('Usuario administrador creado.');
            });
        }
    });
});

module.exports = db;