const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Configuración de EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Configuración de la sesión
app.use(session({
    secret: 'tu_secreto_muy_seguro_y_largo_aqui', // CAMBIA ESTO
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } 
}));

// Middleware para proteger rutas
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    res.redirect('/login');
}

// Rutas de Autenticación
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [rows] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
        if (rows.length > 0) {
            const user = rows[0];
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                req.session.userId = user.id;
                return res.redirect('/');
            }
        }
        res.render('login', { error: 'Email o contraseña incorrectos.' });
    } catch (error) {
        console.error('Error en el login:', error);
        res.status(500).send('Error interno del servidor.');
    }
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { nombre, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query('INSERT INTO usuarios (nombre, email, password) VALUES (?, ?, ?)', [nombre, email, hashedPassword]);
        res.redirect('/login');
    } catch (error) {
        console.error('Error al registrar usuario:', error);
        res.status(500).send('Error al registrar el usuario.');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/');
        }
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

// Ruta principal del Dashboard
app.get('/', isAuthenticated, async (req, res) => {
    try {
        // Consultas para el dashboard principal
        const [indicadores] = await db.query('SELECT * FROM indicadores_sociales WHERE ano = ?', [req.query.ano || 2025]);
        const [datosRadar] = await db.query('SELECT * FROM datos_radar WHERE ano = ?', [req.query.ano || 2025]);
        const [puntosMapa] = await db.query('SELECT * FROM puntos_interes');
        
        // Consultas para la pestaña de Educación y Cultura
        const [educacionCultura] = await db.query('SELECT * FROM indicadores_educacion_cultura WHERE ano = ?', [req.query.ano || 2025]);

        // Consultas para la pestaña de Salud y Bienestar
        const [saludBienestar] = await db.query('SELECT * FROM indicadores_salud WHERE ano = ?', [req.query.ano || 2025]);

        // Consultas para la pestaña de Inclusión, Vivienda y Seguridad
        const [inclusionViviendaSeguridad] = await db.query('SELECT * FROM indicadores_inclusion WHERE ano = ?', [req.query.ano || 2025]);
        
        res.render('dashboard', { 
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

// Inicio del servidor
app.listen(PORT, () => {
    console.log(`Servidor escuchando en http://localhost:${PORT}`);
});