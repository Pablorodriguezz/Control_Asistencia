const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

// --- LÓGICA DE RUTA INTELIGENTE PARA LA BASE DE DATOS ---
// Determina si estamos en el entorno de producción de Render o en desarrollo local.
const isProduction = process.env.NODE_ENV === 'production';

// Define la ruta del directorio de datos. En Render, es una ruta fija en el disco persistente.
const dataDir = isProduction ? '/var/data' : '.';
const dbPath = path.join(dataDir, 'asistencia.db');

// En producción (Render), nos aseguramos de que el directorio de datos exista antes de usarlo.
if (isProduction) {
    if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
        console.log(`Directorio de datos creado en: ${dataDir}`);
    }
}
// -------------------------------------------------------------

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("Error fatal al abrir la base de datos:", err.message);
        // Si no se puede abrir la base de datos, no tiene sentido continuar.
        // En un entorno real, esto podría lanzar una excepción para detener la aplicación.
        process.exit(1);
    }
    console.log(`Conectado exitosamente a la base de datos en: ${dbPath}`);
});

// Serializamos las operaciones para asegurar que se ejecuten en orden.
db.serialize(() => {
    // Crear tabla de usuarios si no existe
    db.run(`CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        usuario TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        rol TEXT NOT NULL CHECK(rol IN ('empleado', 'admin'))
    )`);

    // Crear tabla de registros si no existe, con la regla ON DELETE CASCADE
    db.run(`CREATE TABLE IF NOT EXISTS registros (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id INTEGER,
        fecha_hora DATETIME NOT NULL,
        tipo TEXT NOT NULL CHECK(tipo IN ('entrada', 'salida')),
        foto_path TEXT,
        FOREIGN KEY (usuario_id) REFERENCES usuarios (id) ON DELETE CASCADE
    )`);

    // --- USUARIO ADMINISTRADOR POR DEFECTO ---
    // Comprueba si el usuario 'admin' ya existe para no intentar crearlo de nuevo.
    const adminUser = 'admin';
    const adminPass = 'admin123'; // ¡Considera cambiar esta contraseña por defecto!

    db.get('SELECT * FROM usuarios WHERE usuario = ?', [adminUser], (err, row) => {
        if (err) {
            console.error("Error al buscar el usuario admin:", err.message);
            return;
        }
        // Si no se encuentra ninguna fila con ese usuario, lo creamos.
        if (!row) {
            bcrypt.hash(adminPass, 10, (err, hash) => {
                if (err) {
                    console.error("Error al encriptar la contraseña del admin:", err.message);
                    return;
                }
                db.run('INSERT INTO usuarios (nombre, usuario, password, rol) VALUES (?, ?, ?, ?)',
                    ['Administrador', adminUser, hash, 'admin'],
                    (insertErr) => {
                        if (insertErr) {
                            console.error("Error al insertar el usuario admin:", insertErr.message);
                        } else {
                            console.log('Usuario administrador por defecto creado.');
                        }
                    }
                );
            });
        }
    });
});

module.exports = db;