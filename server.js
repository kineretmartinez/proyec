const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const db = require('./db');
const multer = require('multer');
const fs = require('fs');
const ExcelJS = require('exceljs')
const app = express();
const PORT = process.env.PORT || 3000;

// CONFIGURACIÓN DE MULTER
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const name = path.basename(file.originalname, ext);
        cb(null, `${name}-${Date.now()}${ext}`);
    }
});

const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' ||
            file.mimetype === 'application/vnd.ms-excel' ||
            file.mimetype === 'text/csv') {
            cb(null, true);
        } else {
            cb(null, false);
            return cb(new Error('Solo se permiten archivos Excel (.xlsx, .xls) o CSV (.csv).'));
        }
    }
});

// Middlewares 
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Configuración de EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Configuración de la sesión 
app.use(session({
    secret: 'tu_secreto_muy_seguro_y_largo_aqui',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// MIDDLEWARES DE AUTORIZACIÓN Y SESIÓN 
async function loadUser(req, res, next) {
    if (req.session.userId) {
        try {
            const [rows] = await db.query('SELECT id, nombre, email, rol, activo FROM usuarios WHERE id = ?', [req.session.userId]);
            if (rows.length > 0) {
                req.user = rows[0];
            } else {
                req.session.destroy();
            }
        } catch (error) {
            console.error('Error al cargar datos de usuario:', error);
        }
    }
    next();
}

app.use(loadUser);

function verificarAcceso(req, res, next) {
    if (!req.user) {
        return res.redirect('/login');
    }
    if (req.user.activo === 1) {
        return next();
    } else {
        req.session.destroy(err => {
            if (err) { console.error(err); }
            res.clearCookie('connect.sid');
            return res.status(403).render('acceso_denegado', {
                mensaje: 'Tu cuenta ha sido desactivada por el administrador.'
            });
        });
    }
}

function soloAdmin(req, res, next) {
    if (req.user && req.user.rol === 'admin') {
        return next();
    }
    res.status(403).send('Acceso Prohibido: Se requiere rol de Administrador.');
}

function soloAdminOTecnico(req, res, next) {
    if (req.user && (req.user.rol === 'admin' || req.user.rol === 'usuario_tecnico')) {
        return next();
    }
    res.status(403).send('Acceso Prohibido: Se requiere rol de Administrador o Usuario Técnico.');
}

// RUTAS DE AUTENTICACIÓN
app.get('/login', (req, res) => res.render('login', { error: null }));

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [rows] = await db.query('SELECT id, password, rol, activo FROM usuarios WHERE email = ?', [email]);
        if (rows.length > 0) {
            const user = rows[0];
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                if (user.activo === 1) {
                    req.session.userId = user.id;
                    return res.redirect('/');
                }
                return res.render('login', { error: 'Tu cuenta está pendiente de activación.' });
            }
        }
        res.render('login', { error: 'Email o contraseña incorrectos.' });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error interno.');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

app.get('/register', (req, res) => res.render('register'));

app.post('/register', async (req, res) => {
    const { nombre, email, password } = req.body;
    try {
        const hashed = await bcrypt.hash(password, 10);
        await db.query('INSERT INTO usuarios (nombre, email, password, activo, rol) VALUES (?, ?, ?, 0, "usuario_normal")', [nombre, email, hashed]);
        res.render('login', { error: 'Registro exitoso. Espera activación de administrador.' });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error al registrar usuario.');
    }
});

// RUTAS PRINCIPALES Y DASHBOARD 
app.get('/', verificarAcceso, async (req, res) => {

    //  Capturar el año de la URL o usar '2025' por defecto. 
    const currentYear = req.query.Año || '2025';
    let mensaje = null;

    try {
        // Filtrar TODAS las consultas por el año
        const [indicadores] = await db.query('SELECT * FROM indicadores_sociales WHERE Año = ?', [currentYear]);
        const [datosRadar] = await db.query('SELECT * FROM datos_radar WHERE Año = ?', [currentYear]);
        const [puntosMapa] = await db.query('SELECT * FROM puntos_interes');
        const [educacionCultura] = await db.query('SELECT * FROM indicadores_educacion_cultura WHERE Año = ?', [currentYear]);
        const [saludBienestar] = await db.query('SELECT * FROM indicadores_salud WHERE Año = ?', [currentYear]);
        const [inclusionViviendaSeguridad] = await db.query('SELECT * FROM indicadores_inclusion WHERE Año = ?', [currentYear]);

        // Si todas las tablas están vacías, mostrar mensaje
        const sinDatos = [
            indicadores.length,
            datosRadar.length,
            educacionCultura.length,
            saludBienestar.length,
            inclusionViviendaSeguridad.length
        ].every(len => len === 0);

        if (sinDatos) {
            mensaje = `⚠️ No hay datos disponibles para el año ${currentYear}. Se mostrarán valores vacíos.`;
        }

        res.render('dashboard', {
            user: req.user,
            indicadores: indicadores[0] || {},
            datosRadar: datosRadar || [],
            puntosMapa: puntosMapa || [],
            educacionCultura: educacionCultura[0] || {},
            saludBienestar: saludBienestar[0] || {},
            inclusionViviendaSeguridad: inclusionViviendaSeguridad[0] || {},
            currentYear: currentYear,
            mensaje
        });
    } catch (error) {
        console.error('Error al obtener los datos del dashboard:', error);
        res.status(500).send('Error interno del servidor');
    }
});

// RUTAS DE ADMINISTRACIÓN
// 1. Panel de Gestión de Usuarios (SOLO ADMIN)
app.get('/admin/usuarios', soloAdmin, async (req, res) => {
    try {
        const [usuarios] = await db.query('SELECT id, nombre, email, rol, activo FROM usuarios');
        res.render('admin_usuarios', { usuarios });
    } catch (error) {
        console.error('Error al obtener lista de usuarios:', error);
        res.status(500).send('Error al cargar la lista de usuarios.');
    }
});

// 2. Panel de Carga de Datos (ADMIN O TÉCNICO)
app.get('/admin/carga-datos', soloAdminOTecnico, (req, res) => {
    res.render('admin_carga_datos', { user: req.user });
});

// 3. API para Activar/Desactivar Acceso (SOLO ADMIN)
app.post('/admin/toggle-acceso/:userId', soloAdmin, async (req, res) => {
    const userId = req.params.userId;
    try {
        const [rows] = await db.query('SELECT activo FROM usuarios WHERE id = ?', [userId]);
        if (rows.length === 0) return res.status(404).json({ mensaje: 'Usuario no encontrado' });
        const nuevoEstado = rows[0].activo === 1 ? 0 : 1;
        await db.query('UPDATE usuarios SET activo = ? WHERE id = ?', [nuevoEstado, userId]);
        res.json({ mensaje: 'Estado de acceso actualizado con éxito', activo: nuevoEstado });
    } catch (error) {
        console.error('Error al actualizar acceso:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// 4. API para Cambiar el Rol (SOLO ADMIN)
app.post('/admin/set-rol/:userId', soloAdmin, async (req, res) => {
    const userId = req.params.userId;
    const { rol } = req.body;

    if (!['admin', 'usuario_tecnico', 'usuario_normal'].includes(rol)) {
        return res.status(400).json({ mensaje: 'Rol inválido.' });
    }

    try {
        await db.query('UPDATE usuarios SET rol = ? WHERE id = ?', [rol, userId]);
        res.json({ mensaje: 'Rol actualizado con éxito', nuevoRol: rol });
    } catch (error) {
        console.error('Error al actualizar rol:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// 5. API para la Carga de Archivos con Multer (ADMIN O TÉCNICO) CARGA DE ARCHIVOS (Excel/CSV)

app.post('/api/upload-data', soloAdminOTecnico, upload.single('datafile'), async (req, res) => {
    if (!req.file) return res.status(400).send('No se subió ningún archivo.');

    const filePath = req.file.path;
    const { tipoTabla } = req.body;
    const validTables = ['indicadores_sociales', 'indicadores_educacion_cultura', 'indicadores_salud', 'indicadores_inclusion', 'datos_radar'];

    if (!validTables.includes(tipoTabla)) {
        fs.unlinkSync(filePath);
        return res.status(400).send('Tabla destino inválida.');
    }

    try {
        const workbook = new ExcelJS.Workbook();
        const ext = path.extname(req.file.originalname).toLowerCase();

        // Detectar delimitador automático
        if (ext === '.csv') {
            const content = fs.readFileSync(filePath, 'utf8');
            const delimiter = content.includes(';') ? ';' : ',';
            await workbook.csv.readFile(filePath, { parserOptions: { delimiter } });
        } else if (ext === '.xlsx' || ext === '.xls') {
            await workbook.xlsx.readFile(filePath);
        } else {
            throw new Error("Formato de archivo no soportado.");
        }

        // Detectar encabezados (fila 1)
        const worksheet = workbook.worksheets[0];
        const headerRow = worksheet.getRow(1);
        const headers = [];
        headerRow.eachCell(cell => {
            if (cell.value) headers.push(String(cell.value).trim().toLowerCase().replace(/ /g, '_'));
        });

        // Normalizar encabezados y eliminar acentos (por ejemplo, "Año" → "ano")
        const headerNormalizado = headers.map(h => h.normalize("NFD").replace(/[\u0300-\u036f]/g, '').toLowerCase());

        // Verificar si existe la columna de año (puede ser "Año", "ano" o similar)
        if (!headerNormalizado.includes('año') && !headerNormalizado.includes('ano') && !headerNormalizado.includes('año_')) {
            throw new Error("El archivo debe contener la columna 'Año' o 'Ano'.");
        }


        const dataRows = [];
        worksheet.eachRow((row, rowNumber) => {
            if (rowNumber > 1) {
                const rowData = {};
                row.eachCell({ includeEmpty: true }, (cell, col) => {
                    const key = headers[col - 1];
                    if (key) rowData[key] = cell.value ?? null;
                });
                if (Object.values(rowData).some(v => v !== null)) dataRows.push(rowData);
            }
        });

        if (dataRows.length === 0) throw new Error("No se encontraron datos válidos.");

        const excluded = ['nombreindicador', 'nota',];
        const cols = headers.filter(h => !excluded.includes(h));
        const sql = `INSERT INTO ${tipoTabla} (${cols.join(', ')}) VALUES ${dataRows.map(() => `(${cols.map(() => '?').join(', ')})`).join(', ')}`;
        const values = dataRows.flatMap(row => cols.map(c => row[c]));

        await db.query(sql, values);

        fs.unlinkSync(filePath);
        res.redirect('/admin/carga-datos?success=Datos cargados exitosamente.');
    } catch (err) {
        console.error('Error al procesar archivo:', err);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        res.redirect(`/admin/carga-datos?error=${encodeURIComponent(err.message)}`);
    }
});

// Inicio del servidor
app.listen(PORT, () => {
    console.log(`Servidor escuchando en http://localhost:${PORT}`);
});