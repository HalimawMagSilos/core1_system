const mysql = require('mysql2/promise');
require('dotenv').config();

const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'hospital_management_system',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    acquireTimeout: 60000,
    timeout: 60000,
    reconnect: true
};

class Database {
    constructor() {
        this.pool = mysql.createPool(dbConfig);
    }

    async getConnection() {
        try {
            const connection = await this.pool.getConnection();
            console.log('✅ Database connected successfully');
            return connection;
        } catch (error) {
            console.error('❌ Database connection failed:', error.message);
            throw error;
        }
    }

    async query(sql, params = []) {
        try {
            const [results] = await this.pool.execute(sql, params);
            return results;
        } catch (error) {
            console.error('❌ Database query error:', error.message);
            throw error;
        }
    }

    async testConnection() {
        try {
            const connection = await this.getConnection();
            connection.release();
            return true;
        } catch (error) {
            return false;
        }
    }
}

module.exports = new Database();