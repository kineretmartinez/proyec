const mysql = require('mysql2');

const pool = mysql.createPool({
    host: 'localhost', 
    user: 'root',     
    password: '', 
    database: 'dashboard_db', 
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