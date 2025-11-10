const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const http = require('http');
require('dotenv').config();

const database = require('./config/database');
const EmailService = require('./utils/emailService');
const socketManager = require('./config/socket');
const authRoutes = require('./routes/authRoutes');
const {
    generalLimiter,
    speedLimiter
} = require('./middlewares/rateLimiter');

class Server {
    constructor() {
        this.app = express();
        this.server = http.createServer(this.app);
        this.port = process.env.PORT || 5000;
        this.io = null;
        
        this.initializeMiddlewares();
        this.initializeSocketIO();
        this.initializeRoutes();
        this.initializeErrorHandling();
    }

    initializeMiddlewares() {
        // Security middleware
        this.app.use(helmet({
            crossOriginResourcePolicy: { policy: "cross-origin" },
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'"],
                    connectSrc: ["'self'", process.env.CLIENT_URL || 'http://localhost:3000', 'ws:', 'wss:']
                }
            }
        }));
        
        // CORS configuration
        this.app.use(cors({
            origin: process.env.CLIENT_URL || 'http://localhost:3000',
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Socket-ID']
        }));

        // Rate limiting
        this.app.use(generalLimiter);
        this.app.use(speedLimiter);

        // Body parsing middleware
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

        // Request logging
        this.app.use((req, res, next) => {
            console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - IP: ${req.ip}`);
            next();
        });

        // Add socket.io to request object for use in routes
        this.app.use((req, res, next) => {
            req.io = this.io;
            next();
        });
    }

    initializeSocketIO() {
        // Initialize Socket.IO with the HTTP server
        this.io = socketManager.initialize(this.server);
        
        // Socket.IO connection logging
        this.io.on('connection', (socket) => {
            console.log(`🔌 Socket connected: ${socket.id} - User: ${socket.user?.email || 'Unknown'}`);
            
            socket.on('disconnect', (reason) => {
                console.log(`🔌 Socket disconnected: ${socket.id} - Reason: ${reason}`);
            });

            socket.on('error', (error) => {
                console.error(`🔌 Socket error (${socket.id}):`, error);
            });
        });

        console.log('✅ Socket.IO initialized');
    }

    initializeRoutes() {
        // Health check endpoint with real-time stats
        this.app.get('/health', (req, res) => {
            const socketStats = socketManager.getServerStats();
            
            res.json({
                status: 'OK',
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                environment: process.env.NODE_ENV,
                realtime: {
                    connectedUsers: socketStats.connectedUsers,
                    connectedAdmins: socketStats.connectedAdmins,
                    totalRooms: socketStats.totalRooms
                },
                memory: {
                    used: process.memoryUsage().heapUsed / 1024 / 1024,
                    total: process.memoryUsage().heapTotal / 1024 / 1024
                }
            });
        });

        // Socket.IO status endpoint
        this.app.get('/socket-status', (req, res) => {
            const stats = socketManager.getServerStats();
            res.json({
                success: true,
                realtime: stats
            });
        });

        // API routes
        this.app.use('/api/auth', authRoutes);
        
        // Add other routes here
        // this.app.use('/api/admin', adminRoutes);
        // this.app.use('/api/users', userRoutes);

        // Real-time data endpoints
        this.initializeRealtimeRoutes();

        // 404 handler
        this.app.use('*', (req, res) => {
            res.status(404).json({
                error: 'Endpoint not found',
                message: `The requested endpoint ${req.originalUrl} does not exist`
            });
        });
    }

    initializeRealtimeRoutes() {
        // Broadcast real-time update (admin only)
        this.app.post('/api/realtime/broadcast', (req, res) => {
            // This would typically be protected with admin authentication
            const { event, data, room } = req.body;
            
            if (!event || !data) {
                return res.status(400).json({
                    success: false,
                    error: 'Event and data are required'
                });
            }

            try {
                if (room) {
                    // Send to specific room
                    socketManager.emitToRoom(room, event, data);
                } else {
                    // Broadcast to all connected clients
                    socketManager.broadcast(event, data);
                }

                res.json({
                    success: true,
                    message: `Real-time update sent to ${room || 'all clients'}`,
                    event,
                    timestamp: new Date().toISOString()
                });
            } catch (error) {
                console.error('Broadcast error:', error);
                res.status(500).json({
                    success: false,
                    error: 'Failed to send real-time update'
                });
            }
        });

        // Get connected users list (admin only)
        this.app.get('/api/realtime/connected-users', (req, res) => {
            // This would typically be protected with admin authentication
            const connectedUsers = Array.from(socketManager.connectedUsers.values()).map(conn => ({
                socketId: conn.socketId,
                user: conn.user,
                connectedAt: conn.connectedAt,
                lastActivity: conn.lastActivity
            }));

            res.json({
                success: true,
                connectedUsers,
                total: connectedUsers.length
            });
        });

        // Force disconnect user (admin only)
        this.app.post('/api/realtime/disconnect-user', (req, res) => {
            // This would typically be protected with admin authentication
            const { userId } = req.body;
            
            if (!userId) {
                return res.status(400).json({
                    success: false,
                    error: 'User ID is required'
                });
            }

            try {
                socketManager.disconnectUser(userId);
                
                res.json({
                    success: true,
                    message: `User ${userId} disconnected`,
                    timestamp: new Date().toISOString()
                });
            } catch (error) {
                console.error('Force disconnect error:', error);
                res.status(500).json({
                    success: false,
                    error: 'Failed to disconnect user'
                });
            }
        });
    }

    initializeErrorHandling() {
        // Global error handler
        this.app.use((error, req, res, next) => {
            console.error('Global error handler:', error);

            if (error.type === 'entity.parse.failed') {
                return res.status(400).json({
                    error: 'Invalid JSON',
                    message: 'The request contains invalid JSON'
                });
            }

            // Emit error event to admin room for real-time monitoring
            if (this.io && error.severity === 'high') {
                socketManager.emitToRoom('admin_dashboard', 'system_error', {
                    error: error.message,
                    stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
                    timestamp: new Date().toISOString(),
                    path: req.path,
                    method: req.method
                });
            }

            res.status(500).json({
                error: 'Internal server error',
                message: 'An unexpected error occurred. Please try again later.'
            });
        });
    }

    async start() {
        try {
            // Test database connection
            const dbConnected = await database.testConnection();
            if (!dbConnected) {
                throw new Error('Failed to connect to database');
            }

            // Test email service
            const emailConnected = await EmailService.verifyConnection();
            if (!emailConnected) {
                console.warn('⚠️ Email service connection failed. Email functionality may not work.');
            }

            // Start server
            this.server.listen(this.port, () => {
                const socketStats = socketManager.getServerStats();
                
                console.log(`
🚀 Hospital Management System Backend Started!
📍 Port: ${this.port}
🌍 Environment: ${process.env.NODE_ENV}
📊 Database: ${process.env.DB_NAME}
📧 Email: ${emailConnected ? '✅ Connected' : '❌ Failed'}
🔌 Real-time: ✅ Socket.IO Enabled
👥 Connected: ${socketStats.connectedUsers} users, ${socketStats.connectedAdmins} admins
🕒 Time: ${new Date().toISOString()}
                `);
            });

        } catch (error) {
            console.error('❌ Failed to start server:', error.message);
            process.exit(1);
        }
    }

    // Method to broadcast system-wide notifications
    broadcastSystemNotification(message, type = 'info') {
        if (this.io) {
            socketManager.broadcast('system_notification', {
                message,
                type,
                timestamp: new Date().toISOString()
            });
        }
    }

    // Method to get real-time server statistics
    getRealtimeStats() {
        return socketManager.getServerStats();
    }

    // Graceful shutdown method
    async shutdown() {
        console.log('🛑 Starting graceful shutdown...');
        
        // Notify all connected clients
        this.broadcastSystemNotification('Server is shutting down for maintenance. Please save your work.', 'warning');
        
        // Wait a moment for clients to receive the message
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Close Socket.IO connections
        if (this.io) {
            this.io.close();
            console.log('🔌 Socket.IO server closed');
        }
        
        // Close HTTP server
        this.server.close(() => {
            console.log('🛑 HTTP server closed');
            process.exit(0);
        });
    }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    
    // Notify admins about critical error
    const serverInstance = global.serverInstance;
    if (serverInstance) {
        serverInstance.broadcastSystemNotification('Critical system error occurred. Please check server logs.', 'error');
    }
    
    process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    
    // Notify admins about unhandled rejection
    const serverInstance = global.serverInstance;
    if (serverInstance) {
        serverInstance.broadcastSystemNotification('Unhandled promise rejection detected.', 'warning');
    }
});

// Graceful shutdown handlers
process.on('SIGTERM', () => {
    console.log('🛑 SIGTERM received. Shutting down gracefully...');
    const serverInstance = global.serverInstance;
    if (serverInstance) {
        serverInstance.shutdown();
    } else {
        process.exit(0);
    }
});

process.on('SIGINT', () => {
    console.log('🛑 SIGINT received. Shutting down gracefully...');
    const serverInstance = global.serverInstance;
    if (serverInstance) {
        serverInstance.shutdown();
    } else {
        process.exit(0);
    }
});

// Start the server
const server = new Server();
global.serverInstance = server; // Make server instance globally available for signal handlers

// Export server for testing purposes
module.exports = { server, Server };

server.start();