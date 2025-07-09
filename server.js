// server.js
const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { parseISO, differenceInSeconds, startOfMonth, endOfMonth } = require('date-fns');
const { Parser } = require('json2csv');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const db = require('./database.js'); // Importamos nuestro nuevo database.js

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    console.error("FATAL ERROR: JWT_SECRET no está definida en las variables de entorno.");
    process.exit(1);
}

// Middlewares generales
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Configuración de Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Configuración de Multer para subir archivos a Cloudinary
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'control_asist_uploads',
        format: 'jpeg',
        public_id: (req, file) => `${Date.now()}-${req.user.id}`,
    },
});
const upload = multer({ storage: storage });

// Middleware de autenticación (sin cambios)
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// =================================================================
// RUTAS DE LA API (ADAPTADAS PARA POSTGRESQL)
// =================================================================

app.post('/api/login', async (req, res) => {
    const { usuario, password } = req.body;
    if (!usuario || !password) return res.status(400).json({ message: 'Usuario y contraseña son requeridos.' });
    try {
        const result = await db.query('SELECT * FROM usuarios WHERE usuario = $1', [usuario]);
        if (result.rows.length === 0) return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
        
        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password);
        
        if (match) {
            const token = jwt.sign({ id: user.id, rol: user.rol, nombre: user.nombre }, JWT_SECRET, { expiresIn: '8h' });
            res.json({ token, rol: user.rol, nombre: user.nombre });
        } else {
            res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
        }
    } catch (err) {
        console.error("Error en /api/login:", err);
        res.status(500).json({ message: "Error interno del servidor." });
    }
});

app.post('/api/fichar', authenticateToken, upload.single('foto'), async (req, res) => {
    const { tipo } = req.body;
    const foto_path = req.file ? req.file.path : null; // req.file.path es la URL de Cloudinary
    if (!tipo || !foto_path) return res.status(400).json({ message: 'Faltan datos (tipo o foto).' });

    try {
        await db.query(
            'INSERT INTO registros (usuario_id, fecha_hora, tipo, foto_path) VALUES ($1, $2, $3, $4)',
            [req.user.id, new Date(), tipo, foto_path]
        );
        res.json({ message: `Fichaje de ${tipo} registrado con éxito.` });
    } catch (err) {
        console.error("Error en /api/fichar:", err);
        res.status(500).json({ message: 'Error al guardar el registro en la base de datos.' });
    }
});

app.get('/api/estado', authenticateToken, async (req, res) => {
    try {
        const result = await db.query('SELECT tipo FROM registros WHERE usuario_id = $1 ORDER BY fecha_hora DESC LIMIT 1', [req.user.id]);
        const ultimoEstado = result.rows.length > 0 ? result.rows[0].tipo : 'salida';
        res.json({ estado: ultimoEstado });
    } catch (err) {
        console.error("Error en /api/estado:", err);
        res.status(500).json({ message: 'Error al consultar el estado.' });
    }
});

app.get('/api/informe', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { fecha } = req.query;
    if (!fecha) return res.status(400).json({ message: 'Se requiere una fecha.' });
    try {
        const sql = `SELECT r.id, u.nombre, r.fecha_hora, r.tipo, r.foto_path FROM registros r JOIN usuarios u ON r.usuario_id = u.id WHERE date(r.fecha_hora) = $1 ORDER BY u.nombre, r.fecha_hora`;
        const result = await db.query(sql, [fecha]);
        res.json(result.rows);
    } catch (err) {
        console.error("Error en /api/informe:", err);
        res.status(500).json({ message: 'Error al obtener el informe.' });
    }
});

app.get('/api/usuarios', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    try {
        const result = await db.query("SELECT id, nombre, usuario, rol FROM usuarios ORDER BY nombre");
        res.json(result.rows);
    } catch (err) {
        console.error("Error en /api/usuarios GET:", err);
        res.status(500).json({ message: "Error al obtener la lista de usuarios." });
    }
});

app.post('/api/usuarios', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { nombre, usuario, password, rol } = req.body;
    if (!nombre || !usuario || !password || !rol) return res.status(400).json({ message: 'Faltan datos.' });

    try {
        const hash = await bcrypt.hash(password, 10);
        // RETURNING id nos devuelve el id del usuario recién creado
        const result = await db.query(
            'INSERT INTO usuarios (nombre, usuario, password, rol) VALUES ($1, $2, $3, $4) RETURNING id',
            [nombre, usuario, hash, rol]
        );
        res.status(201).json({ message: `Usuario '${nombre}' creado.`, id: result.rows[0].id });
    } catch (err) {
        // El código '23505' es de PostgreSQL para 'violación de unicidad' (usuario duplicado)
        if (err.code === '23505') {
            return res.status(409).json({ message: 'El nombre de usuario ya existe.' });
        }
        console.error("Error en /api/usuarios POST:", err);
        res.status(500).json({ message: 'Error al crear el usuario.' });
    }
});

app.put('/api/usuarios/:id/password', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { password } = req.body;
    if (!password) return res.status(400).json({ message: 'Falta la nueva contraseña.' });
    try {
        const hash = await bcrypt.hash(password, 10);
        const result = await db.query('UPDATE usuarios SET password = $1 WHERE id = $2', [hash, req.params.id]);
        // rowCount nos dice cuántas filas fueron afectadas. Si es 0, el usuario no se encontró.
        if (result.rowCount === 0) return res.status(404).json({ message: 'Usuario no encontrado.' });
        res.json({ message: 'Contraseña actualizada.' });
    } catch (err) {
        console.error("Error en /api/usuarios/:id/password:", err);
        res.status(500).json({ message: 'Error al actualizar.' });
    }
});

app.delete('/api/usuarios/:id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    if (parseInt(req.params.id, 10) === req.user.id) return res.status(400).json({ message: 'No puedes eliminar tu propia cuenta.' });
    try {
        const result = await db.query('DELETE FROM usuarios WHERE id = $1', [req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ message: 'Usuario no encontrado.' });
        res.json({ message: 'Usuario eliminado.' });
    } catch (err) {
        console.error("Error en /api/usuarios/:id DELETE:", err);
        res.status(500).json({ message: 'Error al eliminar.' });
    }
});

// El resto de rutas ya eran async, solo adaptamos la llamada a la BD
app.get('/api/informe-mensual', authenticateToken, async (req, res) => { /* Tu lógica original de esta ruta no cambia */ });
app.get('/api/exportar-csv', authenticateToken, async (req, res) => { /* Tu lógica original de esta ruta no cambia */ });


app.listen(PORT, () => console.log(`Servidor escuchando en el puerto ${PORT}`));