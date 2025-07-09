// =================================================================
// server.js (VERSIÓN FINAL CON LOGS MEJORADOS)
// =================================================================

// 1. IMPORTACIÓN DE MÓDULOS
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt =require('jsonwebtoken');
const { parseISO, differenceInSeconds, startOfMonth, endOfMonth } = require('date-fns');
const { Parser } = require('json2csv');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const db = require('./database.js');

// 2. INICIALIZACIÓN Y CONFIGURACIÓN
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    console.error("FATAL ERROR: JWT_SECRET no está definida en las variables de entorno.");
    process.exit(1);
}

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'control_asist_uploads',
        format: 'jpeg',
        public_id: (req, file) => `${Date.now()}-${req.user.id}`,
    },
});
const upload = multer({ storage: storage });

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
// RUTAS DE LA API (CON LOGS MEJORADOS)
// =================================================================

// --- En cada bloque CATCH, cambiamos console.error(err) por console.error(err.message, err.stack) ---

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
        console.error("Error en /api/login:", err.message, err.stack);
        res.status(500).json({ message: "Error interno del servidor." });
    }
});

app.post('/api/fichar', authenticateToken, upload.single('foto'), async (req, res) => {
    const { tipo } = req.body;
    const foto_path = req.file ? req.file.path : null;
    if (!tipo || !foto_path) return res.status(400).json({ message: 'Faltan datos (tipo o foto).' });

    try {
        await db.query(
            'INSERT INTO registros (usuario_id, fecha_hora, tipo, foto_path) VALUES ($1, $2, $3, $4)',
            [req.user.id, new Date(), tipo, foto_path]
        );
        res.json({ message: `Fichaje de ${tipo} registrado con éxito.` });
    } catch (err) {
        console.error("Error en /api/fichar:", err.message, err.stack);
        res.status(500).json({ message: 'Error al guardar el registro en la base de datos.' });
    }
});

app.get('/api/estado', authenticateToken, async (req, res) => {
    try {
        const result = await db.query('SELECT tipo FROM registros WHERE usuario_id = $1 ORDER BY fecha_hora DESC LIMIT 1', [req.user.id]);
        const ultimoEstado = result.rows.length > 0 ? result.rows[0].tipo : 'salida';
        res.json({ estado: ultimoEstado });
    } catch (err) {
        console.error("Error en /api/estado:", err.message, err.stack);
        res.status(500).json({ message: 'Error al consultar el estado.' });
    }
});

// ... (El resto de las rutas también se benefician del log mejorado)
// ... Te pego todas para que solo copies y pegues el archivo entero ...

app.get('/api/informe', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { fecha } = req.query;
    if (!fecha) return res.status(400).json({ message: 'Se requiere una fecha.' });
    try {
        const sql = `SELECT r.id, u.nombre, r.fecha_hora, r.tipo, r.foto_path FROM registros r JOIN usuarios u ON r.usuario_id = u.id WHERE date(r.fecha_hora) = $1 ORDER BY u.nombre, r.fecha_hora`;
        const result = await db.query(sql, [fecha]);
        res.json(result.rows);
    } catch (err) {
        console.error("Error en /api/informe:", err.message, err.stack);
        res.status(500).json({ message: 'Error al obtener el informe.' });
    }
});

app.get('/api/usuarios', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    try {
        const result = await db.query("SELECT id, nombre, usuario, rol FROM usuarios ORDER BY nombre");
        res.json(result.rows);
    } catch (err) {
        console.error("Error en /api/usuarios GET:", err.message, err.stack);
        res.status(500).json({ message: "Error al obtener la lista de usuarios." });
    }
});

app.post('/api/usuarios', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { nombre, usuario, password, rol } = req.body;
    if (!nombre || !usuario || !password || !rol) return res.status(400).json({ message: 'Faltan datos.' });

    try {
        const hash = await bcrypt.hash(password, 10);
        const result = await db.query(
            'INSERT INTO usuarios (nombre, usuario, password, rol) VALUES ($1, $2, $3, $4) RETURNING id',
            [nombre, usuario, hash, rol]
        );
        res.status(201).json({ message: `Usuario '${nombre}' creado.`, id: result.rows[0].id });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ message: 'El nombre de usuario ya existe.' });
        }
        console.error("Error en /api/usuarios POST:", err.message, err.stack);
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
        if (result.rowCount === 0) return res.status(404).json({ message: 'Usuario no encontrado.' });
        res.json({ message: 'Contraseña actualizada.' });
    } catch (err) {
        console.error("Error en /api/usuarios/:id/password:", err.message, err.stack);
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
        console.error("Error en /api/usuarios/:id DELETE:", err.message, err.stack);
        res.status(500).json({ message: 'Error al eliminar.' });
    }
});

app.get('/api/informe-mensual', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { anio, mes, usuarioId } = req.query;
    if (!anio || !mes || !usuarioId) return res.status(400).json({ message: 'Parámetros incompletos.' });

    try {
        const fechaInicio = startOfMonth(new Date(anio, mes - 1, 1));
        const fechaFin = endOfMonth(fechaInicio);
        const sql = `SELECT fecha_hora, tipo FROM registros WHERE usuario_id = $1 AND fecha_hora BETWEEN $2 AND $3 ORDER BY fecha_hora ASC`;
        const result = await db.query(sql, [usuarioId, fechaInicio.toISOString(), fechaFin.toISOString()]);
        const registros = result.rows;
        const periodosTrabajados = [];
        let entradaActual = null;
        for (const registro of registros) {
            if (registro.tipo === 'entrada' && !entradaActual) {
                entradaActual = registro.fecha_hora;
            } else if (registro.tipo === 'salida' && entradaActual) {
                const duracionSegundos = differenceInSeconds(registro.fecha_hora, entradaActual);
                if (duracionSegundos >= 0) {
                    periodosTrabajados.push({
                        fecha: entradaActual.toISOString().split('T')[0],
                        entrada: entradaActual.toISOString(),
                        salida: registro.fecha_hora.toISOString(),
                        duracionSegundos: duracionSegundos
                    });
                }
                entradaActual = null;
            }
        }
        res.json(periodosTrabajados);
    } catch (e) {
        console.error("Error crítico en /informe-mensual:", e.message, e.stack);
        res.status(500).json({ message: "Error interno del servidor." });
    }
});

app.get('/api/exportar-csv', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { anio, mes, usuarioId } = req.query;
    if (!anio || !mes || !usuarioId) return res.status(400).json({ message: 'Faltan parámetros.' });

    try {
        const fechaInicio = startOfMonth(new Date(anio, mes - 1, 1));
        const fechaFin = endOfMonth(fechaInicio);
        const sql = `SELECT u.nombre, r.fecha_hora, r.tipo FROM registros r JOIN usuarios u ON r.usuario_id = u.id WHERE r.usuario_id = $1 AND r.fecha_hora BETWEEN $2 AND $3 ORDER BY r.fecha_hora ASC`;
        const result = await db.query(sql, [usuarioId, fechaInicio.toISOString(), fechaFin.toISOString()]);
        const fields = ['nombre', 'fecha_hora', 'tipo'];
        const json2csvParser = new Parser({ fields });
        const csv = json2csvParser.parse(result.rows);
        res.header('Content-Type', 'text/csv');
        res.attachment(`informe-${anio}-${mes}-usuario-${usuarioId}.csv`);
        res.send(csv);
    } catch (err) {
        console.error("Error en /exportar-csv:", err.message, err.stack);
        res.status(500).json({ message: 'Error al obtener datos para exportar.' });
    }
});

app.listen(PORT, () => console.log(`Servidor escuchando en el puerto ${PORT}`));