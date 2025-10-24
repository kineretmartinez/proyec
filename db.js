const mysql = require('mysql2');

const pool = mysql.createPool({
    host: 'localhost', // dirección de tu servidor MySQL
    user: 'root',      //  usuario de MySQL
    password: '', // contraseña
    database: 'dashboard_db', // El nombre de la base de datos
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