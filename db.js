const mysql = require('mysql2');

const pool = mysql.createPool({
    host: 'localhost', // O la dirección de tu servidor MySQL
    user: 'root',      // Tu usuario de MySQL
    password: '', // Tu contraseña
    database: 'prueba', // El nombre de tu base de datos
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

pool.getConnection((err, connection) => {
    if (err) {
        console.error('Error al conectar con la base de datos:', err);
    } else {
        console.log('Conexión a la base de datos exitosa.');
        connection.release();
    }
});

module.exports = pool.promise();