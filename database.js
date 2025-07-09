// database.js
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// El paquete 'pg' lee automáticamente la variable de entorno DATABASE_URL que Render configura.
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Esta configuración es necesaria para las conexiones en Render
    ssl: {
        rejectUnauthorized: false
    }
});

// Función para inicializar la base de datos
async function initializeDatabase() {
    const client = await pool.connect();
    try {
        console.log("Conectado a PostgreSQL. Inicializando esquemas...");

        // La sintaxis de PostgreSQL usa SERIAL para claves autoincrementales y TIMESTAMPTZ para fechas con zona horaria.
        await client.query(`
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                nombre TEXT NOT NULL,
                usuario TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                rol TEXT NOT NULL CHECK(rol IN ('empleado', 'admin'))
            );
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS registros (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                fecha_hora TIMESTAMPTZ NOT NULL,
                tipo TEXT NOT NULL CHECK(tipo IN ('entrada', 'salida')),
                foto_path TEXT
            );
        `);

        console.log("Tablas verificadas. Comprobando usuario administrador...");
        const adminUser = 'admin';
        const adminPass = 'admin123';

        // En PostgreSQL, los parámetros se indican con $1, $2, etc.
        const res = await client.query('SELECT * FROM usuarios WHERE usuario = $1', [adminUser]);

        if (res.rows.length === 0) {
            console.log("Creando usuario administrador por defecto...");
            const hash = await bcrypt.hash(adminPass, 10);
            await client.query(
                'INSERT INTO usuarios (nombre, usuario, password, rol) VALUES ($1, $2, $3, $4)',
                ['Administrador', adminUser, hash, 'admin']
            );
            console.log("Usuario administrador creado.");
        } else {
             console.log("El usuario administrador ya existe.");
        }
         console.log("Inicialización de la base de datos completada.");

    } catch (err) {
        console.error("Error grave durante la inicialización de la base de datos:", err);
    } finally {
        // Libera al cliente para que vuelva al pool de conexiones
        client.release();
    }
}

// Ejecutamos la inicialización al arrancar el servidor
initializeDatabase();

// Exportamos un objeto con un método 'query' para usarlo en toda la aplicación
module.exports = {
    query: (text, params) => pool.query(text, params),
};