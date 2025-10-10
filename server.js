const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const db = require('./db'); 
const multer = require('multer'); 
const fs = require('fs'); // Necesario para crear la carpeta si no existe

const app = express();
const PORT = process.env.PORT || 3000;

//  CONFIGURACIÓN DE MULTER
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// Configuración de almacenamiento: Guarda el archivo en la carpeta 'uploads' 
// con su nombre original más la fecha.
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir); // Directorio donde se guardará el archivo
    },
    filename: (req, file, cb) => {
        // Renombrar el archivo: [nombre original]_[timestamp].[extensión]
        const ext = path.extname(file.originalname);
        const name = path.basename(file.originalname, ext);
        cb(null, `${name}-${Date.now()}${ext}`);
    }
});

const upload = multer({ 
    storage: storage,
    // Opcional: Filtro para aceptar solo archivos Excel/CSV
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' || // .xlsx
            file.mimetype === 'application/vnd.ms-excel' || // .xls
            file.mimetype === 'text/csv') { // .csv
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
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

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
                } else {
                    return res.render('login', { error: 'Tu cuenta está pendiente de activación por un administrador.' });
                }
            }
        }
        res.render('login', { error: 'Email o contraseña incorrectos.' });
    } catch (error) {
        console.error('Error en el login:', error);
        res.status(500).send('Error interno del servidor.');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) { return res.redirect('/'); }
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { nombre, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query('INSERT INTO usuarios (nombre, email, password, activo, rol) VALUES (?, ?, ?, 0, "usuario_normal")', [nombre, email, hashedPassword]);
        res.render('login', { error: 'Registro exitoso. Tu cuenta está pendiente de activación por un administrador.' });
    } catch (error) {
        console.error('Error al registrar usuario:', error);
        res.status(500).send('Error al registrar el usuario.');
    }
});

// RUTAS PRINCIPALES Y DASHBOARD 
app.get('/', verificarAcceso, async (req, res) => {
    try {
        const [indicadores] = await db.query('SELECT * FROM indicadores_sociales WHERE ano = ?', [req.query.ano || 2025]);
        const [datosRadar] = await db.query('SELECT * FROM datos_radar WHERE ano = ?', [req.query.ano || 2025]);
        const [puntosMapa] = await db.query('SELECT * FROM puntos_interes');
        const [educacionCultura] = await db.query('SELECT * FROM indicadores_educacion_cultura WHERE ano = ?', [req.query.ano || 2025]);
        const [saludBienestar] = await db.query('SELECT * FROM indicadores_salud WHERE ano = ?', [req.query.ano || 2025]);
        const [inclusionViviendaSeguridad] = await db.query('SELECT * FROM indicadores_inclusion WHERE ano = ?', [req.query.ano || 2025]);

        res.render('dashboard', {
            user: req.user,
            indicadores: indicadores[0],
            datosRadar: datosRadar,
            puntosMapa: puntosMapa,
            educacionCultura: educacionCultura[0],
            saludBienestar: saludBienestar[0],
            inclusionViviendaSeguridad: inclusionViviendaSeguridad[0]
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
app.get('/admin/carga-datos', soloAdminOTecnico, async (req, res) => {
    try {
        res.render('admin_carga_datos', { user: req.user });
    } catch (error) {
        console.error('Error al cargar panel de datos:', error);
        res.status(500).send('Error al cargar el panel de Carga de Datos.');
    }
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

// 5. API para la Carga de Archivos con Multer (ADMIN O TÉCNICO)
app.post('/api/upload-data', soloAdminOTecnico, upload.single('datafile'), async (req, res) => {
    
    // --- 1. Manejo de Errores Iniciales ---
    if (req.fileValidationError) {
        return res.status(400).send(req.fileValidationError);
    }
    if (!req.file) {
        return res.status(400).send('No se ha subido ningún archivo.');
    }

    const filePath = req.file.path; 
    const { nombreIndicador, tipoTabla, nota } = req.body;

    // Verificar que la tabla destino sea válida para evitar inyección SQL básica
    const validTables = ['indicadores_sociales', 'indicadores_educacion_cultura', 'indicadores_salud', 'indicadores_inclusion'];
    if (!validTables.includes(tipoTabla)) {
        fs.unlinkSync(filePath); // Borrar el archivo si la tabla no es válida
        return res.status(400).send('Tabla destino inválida.');
    }

    try {
        // --- 2. Lectura y Procesamiento del Archivo con ExcelJS ---
        const workbook = new ExcelJS.Workbook();
        await workbook.xlsx.readFile(filePath);
        
        const worksheet = workbook.worksheets[0];
        const rowsToInsert = [];
        let headers = [];

        // Leer encabezados (Fila 1)
        worksheet.getRow(1).eachCell((cell) => {
            headers.push(cell.value.toLowerCase().replace(/ /g, '_')); // Formatea a 'columna_ejemplo'
        });
        
        if (!headers.includes('ano') || !headers.includes('mes')) {
             throw new Error("El archivo debe contener las columnas 'Ano' y 'Mes'.");
        }

        // Leer filas de datos (a partir de la Fila 2)
        worksheet.eachRow((row, rowNumber) => {
            if (rowNumber > 1) { // Ignorar la fila de encabezados
                const rowData = {};
                row.eachCell({ includeEmpty: false }, (cell, colNumber) => {
                    const headerName = headers[colNumber - 1];
                    rowData[headerName] = cell.value;
                });
                if (Object.keys(rowData).length > 0) {
                     rowsToInsert.push(rowData);
                }
            }
        });

        // --- 3. Construcción y Ejecución de la Inserción Masiva ---
        if (rowsToInsert.length === 0) {
             throw new Error("No se encontraron datos válidos en el archivo.");
        }
        
        // Excluir 'nombreIndicador' y 'nota' de los encabezados de las columnas de la tabla
        const dataHeaders = headers.filter(h => h !== 'ano' && h !== 'mes' && h !== 'nombreindicador' && h !== 'nota');
        const columnNames = [...dataHeaders, 'ano', 'mes'].join(', ');

        const values = [];
        rowsToInsert.forEach(row => {
            const rowValues = [];
            dataHeaders.forEach(header => {
                rowValues.push(row[header] || null); // Añadir valor o null
            });
            rowValues.push(row['ano'] || null);
            rowValues.push(row['mes'] || null);
            values.push(rowValues);
        });

        // Crear la cadena de placeholders (?, ?, ...), ejemplo: (?, ?, ?), (?, ?, ?)
        const placeholders = values.map(() => `(${Array(dataHeaders.length + 2).fill('?').join(', ')})`).join(', ');

        // Aplanar el array de arrays de valores para la consulta de MySQL
        const flatValues = values.flat();

        const sql = `INSERT INTO ${tipoTabla} (${columnNames}) VALUES ${placeholders}`;
        
        // Ejecutar la inserción
        await db.query(sql, flatValues);
        
        // --- 4. Limpieza y Respuesta Final ---
        fs.unlinkSync(filePath); // Eliminar el archivo temporal
        
        // Redirigir al panel de carga con un mensaje de éxito
        res.redirect('/admin/carga-datos?success=Datos cargados exitosamente.');

    } catch (error) {
        console.error('Error al procesar el archivo y actualizar la base de datos:', error);
        
        // Asegurar la eliminación del archivo ante cualquier error
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath); 
        }

        // Redirigir con mensaje de error
        res.redirect(`/admin/carga-datos?error=Error al cargar los datos: ${error.message}`);
    }
});

// Inicio del servidor
app.listen(PORT, () => {
    console.log(`Servidor escuchando en http://localhost:${PORT}`);
});