// =================================================================
// SERVIDOR PARA LA APLICACIÓN DE CONTROL DE ASISTENCIA (VERSIÓN FINAL)
// =================================================================

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const db = require('./database.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { parseISO, differenceInSeconds, startOfMonth, endOfMonth, getWeek } = require('date-fns');
const { Parser } = require('json2csv');

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secreto-local-para-desarrollo';
const isProduction = process.env.NODE_ENV === 'production';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// --- CONFIGURACIÓN DE MULTER ---
const uploadDir = isProduction ? '/var/data/uploads' : path.join(__dirname, 'public/uploads');

// En local, nos aseguramos de que la carpeta de uploads exista
if (!isProduction && !fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: uploadDir,
    filename: (req, file, cb) => {
        const userId = req.user ? req.user.id : 'unknown';
        cb(null, `${Date.now()}-${userId}.jpeg`);
    }
});
const upload = multer({ storage });

// --- RUTA EXTRA PARA SERVIR FOTOS EN PRODUCCIÓN ---
if (isProduction) {
    app.use('/uploads', express.static(uploadDir));
}

// --- MIDDLEWARE DE AUTENTICACIÓN ---
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

// --- RUTAS DE LA API ---
app.post('/api/login', (req, res) => { /* ...código... */ });
app.get('/api/estado', authenticateToken, (req, res) => { /* ...código... */ });
app.post('/api/fichar', authenticateToken, upload.single('foto'), (req, res) => { /* ...código... */ });
app.get('/api/informe', authenticateToken, (req, res) => { /* ...código... */ });
app.get('/api/usuarios', authenticateToken, (req, res) => { /* ...código... */ });
app.post('/api/usuarios', authenticateToken, (req, res) => { /* ...código... */ });
app.put('/api/usuarios/:id/password', authenticateToken, (req, res) => { /* ...código... */ });
app.delete('/api/usuarios/:id', authenticateToken, (req, res) => { /* ...código... */ });
app.get('/api/informe-mensual', authenticateToken, (req, res) => { /* ...código... */ });
app.get('/api/exportar-csv', authenticateToken, (req, res) => { /* ...código... */ });


// --- PEGADO DE CÓDIGO DE RUTAS ---
// Para que no te líes, aquí está el código completo de todas las rutas que he puesto arriba como "...código..."
app.post('/api/login', (req, res) => {
    const { usuario, password } = req.body;
    if (!usuario || !password) return res.status(400).json({ message: 'Usuario y contraseña son requeridos.' });
    db.get('SELECT * FROM usuarios WHERE usuario = ?', [usuario], (err, user) => {
        if (err || !user) return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                const token = jwt.sign({ id: user.id, rol: user.rol, nombre: user.nombre }, JWT_SECRET, { expiresIn: '8h' });
                res.json({ token, rol: user.rol, nombre: user.nombre });
            } else {
                res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
            }
        });
    });
});
app.get('/api/estado', authenticateToken, (req, res) => {
    const usuario_id = req.user.id;
    db.get('SELECT tipo FROM registros WHERE usuario_id = ? ORDER BY fecha_hora DESC LIMIT 1', [usuario_id], (err, row) => {
        if (err) return res.status(500).json({ message: 'Error al consultar el estado.' });
        const ultimoEstado = row ? row.tipo : 'salida';
        res.json({ estado: ultimoEstado });
    });
});
app.post('/api/fichar', authenticateToken, upload.single('foto'), (req, res) => {
    const { tipo } = req.body;
    const usuario_id = req.user.id;
    const fecha_hora = new Date().toISOString();
    const foto_path = req.file ? `/uploads/${req.file.filename}` : null;
    if (!tipo || (tipo !== 'entrada' && tipo !== 'salida')) return res.status(400).json({ message: 'Tipo de fichaje inválido.' });
    if (!foto_path) return res.status(400).json({ message: 'No se ha proporcionado la foto de verificación.' });
    const sql = 'INSERT INTO registros (usuario_id, fecha_hora, tipo, foto_path) VALUES (?, ?, ?, ?)';
    db.run(sql, [usuario_id, fecha_hora, tipo, foto_path], function(err) {
        if (err) return res.status(500).json({ message: 'Error al guardar el registro.' });
        res.json({ message: `Fichaje de ${tipo} registrado con foto.` });
    });
});
app.get('/api/informe', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { fecha } = req.query;
    if (!fecha) return res.status(400).json({ message: 'Se requiere una fecha.' });
    const sql = `SELECT r.id, u.nombre, r.fecha_hora, r.tipo, r.foto_path FROM registros r JOIN usuarios u ON r.usuario_id = u.id WHERE date(r.fecha_hora) = ? ORDER BY u.nombre, r.fecha_hora`;
    db.all(sql, [fecha], (err, rows) => {
        if (err) return res.status(500).json({ message: 'Error al obtener el informe.' });
        res.json(rows);
    });
});
app.get('/api/usuarios', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    db.all("SELECT id, nombre, usuario, rol FROM usuarios ORDER BY nombre", [], (err, rows) => {
        if (err) return res.status(500).json({ message: "Error al obtener la lista de usuarios." });
        res.json(rows);
    });
});
app.post('/api/usuarios', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { nombre, usuario, password, rol } = req.body;
    if (!nombre || !usuario || !password || !rol) return res.status(400).json({ message: 'Faltan datos.' });
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ message: 'Error al encriptar.' });
        db.run('INSERT INTO usuarios (nombre, usuario, password, rol) VALUES (?, ?, ?, ?)', [nombre, usuario, hash, rol], function(err) {
            if (err) return res.status(500).json({ message: 'Error al crear el usuario.' });
            res.status(201).json({ message: `Usuario '${nombre}' creado.`, id: this.lastID });
        });
    });
});
app.put('/api/usuarios/:id/password', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    const { password } = req.body;
    if (!password) return res.status(400).json({ message: 'Falta la nueva contraseña.' });
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ message: 'Error al encriptar.' });
        db.run('UPDATE usuarios SET password = ? WHERE id = ?', [hash, req.params.id], function(err) {
            if (err) return res.status(500).json({ message: 'Error al actualizar.' });
            if (this.changes === 0) return res.status(404).json({ message: 'Usuario no encontrado.' });
            res.json({ message: 'Contraseña actualizada.' });
        });
    });
});
app.delete('/api/usuarios/:id', authenticateToken, (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ message: 'Acceso denegado.' });
    if (parseInt(req.params.id, 10) === req.user.id) return res.status(400).json({ message: 'No puedes eliminar tu propia cuenta.' });
    db.run('DELETE FROM usuarios WHERE id = ?', req.params.id, function(err) {
        if (err) return res.status(500).json({ message: 'Error al eliminar.' });
        if (this.changes === 0) return res.status(404).json({ message: 'Usuario no encontrado.' });
        res.json({ message: 'Usuario eliminado.' });
    });
});
app.get('/api/informe-mensual', authenticateToken, (req, res) => {
    const { anio, mes, usuarioId } = req.query;
    if (!anio || !mes || !usuarioId) return res.status(400).json({ message: 'Parámetros incompletos.' });
    const fechaInicio = startOfMonth(new Date(anio, mes - 1, 1));
    const fechaFin = endOfMonth(fechaInicio);
    const sql = `SELECT fecha_hora, tipo FROM registros WHERE usuario_id = ? AND fecha_hora BETWEEN ? AND ? ORDER BY fecha_hora ASC`;
    db.all(sql, [usuarioId, fechaInicio.toISOString(), fechaFin.toISOString()], (err, registros) => {
        if (err) return res.status(500).json({ message: 'Error en la base de datos.' });
        const periodosTrabajados = []; let entradaActual = null;
        for (const registro of registros) {
            if (registro.tipo === 'entrada' && !entradaActual) entradaActual = registro.fecha_hora;
            else if (registro.tipo === 'salida' && entradaActual) {
                const duracionSegundos = differenceInSeconds(parseISO(registro.fecha_hora), parseISO(entradaActual));
                if (duracionSegundos >= 0) periodosTrabajados.push({ entrada: entradaActual, salida: registro.fecha_hora, duracionSegundos });
                entradaActual = null;
            }
        }
        res.json(periodosTrabajados);
    });
});
app.get('/api/exportar-csv', authenticateToken, (req, res) => {
    const { anio, mes, usuarioId } = req.query;
    if (!anio || !mes || !usuarioId) return res.status(400).json({ message: 'Faltan parámetros.' });
    const fechaInicio = startOfMonth(new Date(anio, mes - 1, 1));
    const fechaFin = endOfMonth(fechaInicio);
    const sql = `SELECT u.nombre, r.fecha_hora, r.tipo FROM registros r JOIN usuarios u ON r.usuario_id = u.id WHERE r.usuario_id = ? AND r.fecha_hora BETWEEN ? AND ? ORDER BY r.fecha_hora ASC`;
    db.all(sql, [usuarioId, fechaInicio.toISOString(), fechaFin.toISOString()], (err, data) => {
        if (err) return res.status(500).json({ message: 'Error al obtener datos.' });
        const fields = ['nombre', 'fecha_hora', 'tipo'];
        const json2csvParser = new Parser({ fields });
        const csv = json2csvParser.parse(data);
        res.header('Content-Type', 'text/csv');
        res.attachment(`informe-${anio}-${mes}-usuario-${usuarioId}.csv`);
        res.send(csv);
    });
});

// --- INICIO DEL SERVIDOR ---
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});