const socketIo = require('socket.io');
const jwt = require('jsonwebtoken');
const redis = require('./redis');
const UserModel = require('../models/userModel');

class SocketManager {
    constructor() {
        this.io = null;
        this.connectedUsers = new Map();
        this.adminRooms = new Set();
    }

    initialize(server) {
        this.io = socketIo(server, {
            cors: {
                origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
                methods: ['GET', 'POST'],
                credentials: true
            },
            transports: ['websocket', 'polling']
        });

        this.setupMiddleware();
        this.setupEventHandlers();
        this.startCleanupInterval();

        console.log('Socket.IO server initialized');
        return this.io;
    }

    // Authentication middleware for Socket.IO
    setupMiddleware() {
        this.io.use(async (socket, next) => {
            try {
                const token = socket.handshake.auth.token || socket.handshake.headers.authorization;
                
                if (!token) {
                    return next(new Error('Authentication token required'));
                }

                // Extract token from Bearer format
                const actualToken = token.startsWith('Bearer ') ? token.slice(7) : token;
                
                // Verify JWT token
                const decoded = jwt.verify(actualToken, process.env.JWT_SECRET);
                
                // Verify user exists and is active
                const user = await UserModel.findUserById(decoded.user_id);
                if (!user || !user.is_active) {
                    return next(new Error('Invalid or inactive user'));
                }

                // Attach user data to socket
                socket.user = {
                    user_id: user.user_id,
                    email: user.email,
                    role_id: user.role_id,
                    role_name: user.role_name
                };

                next();
            } catch (error) {
                console.error('Socket authentication error:', error);
                next(new Error('Authentication failed'));
            }
        });
    }

    // Setup event handlers
    setupEventHandlers() {
        this.io.on('connection', (socket) => {
            console.log(`User ${socket.user.email} connected with socket ID: ${socket.id}`);

            // Store user connection
            this.connectedUsers.set(socket.user.user_id, {
                socketId: socket.id,
                user: socket.user,
                connectedAt: new Date(),
                lastActivity: new Date()
            });

            // Join user to their personal room
            socket.join(`user:${socket.user.user_id}`);

            // Join admin to admin dashboard room if applicable
            if (socket.user.role_id === UserModel.ROLES.ADMIN) {
                socket.join('admin_dashboard');
                this.adminRooms.add(socket.user.user_id);
                console.log(`Admin ${socket.user.email} joined admin dashboard`);
            }

            // Handle real-time data requests
            this.setupDataHandlers(socket);

            // Handle disconnection
            socket.on('disconnect', (reason) => {
                this.handleDisconnect(socket, reason);
            });

            // Handle ping/pong for connection health
            socket.on('ping', (data) => {
                socket.emit('pong', {
                    timestamp: new Date().toISOString(),
                    serverTime: Date.now()
                });
            });

            // Emit connection success
            socket.emit('connected', {
                success: true,
                user: {
                    user_id: socket.user.user_id,
                    email: socket.user.email,
                    role_name: socket.user.role_name
                },
                socketId: socket.id,
                timestamp: new Date().toISOString()
            });
        });
    }

    // Setup data event handlers
    setupDataHandlers(socket) {
        // Request real-time dashboard data
        socket.on('request_dashboard_data', async (data) => {
            try {
                if (socket.user.role_id !== UserModel.ROLES.ADMIN) {
                    socket.emit('error', {
                        message: 'Access denied: Admin privileges required'
                    });
                    return;
                }

                const dashboardData = await UserModel.getAdminDashboardData(socket.user.user_id);
                
                socket.emit('dashboard_data', {
                    ...dashboardData,
                    realTime: true,
                    socketId: socket.id
                });

                // Update last activity
                this.updateUserActivity(socket.user.user_id);

            } catch (error) {
                console.error('Error fetching dashboard data:', error);
                socket.emit('error', {
                    message: 'Failed to fetch dashboard data'
                });
            }
        });

        // Request real-time users table
        socket.on('request_users_table', async (filters) => {
            try {
                if (socket.user.role_id !== UserModel.ROLES.ADMIN) {
                    socket.emit('error', {
                        message: 'Access denied: Admin privileges required'
                    });
                    return;
                }

                const usersData = await UserModel.getRealTimeUsersTable(filters, socket.user.user_id);
                
                socket.emit('users_table_data', {
                    ...usersData,
                    realTime: true,
                    socketId: socket.id
                });

                this.updateUserActivity(socket.user.user_id);

            } catch (error) {
                console.error('Error fetching users table:', error);
                socket.emit('error', {
                    message: 'Failed to fetch users data'
                });
            }
        });

        // Request real-time security events
        socket.on('request_security_events', async (filters) => {
            try {
                if (socket.user.role_id !== UserModel.ROLES.ADMIN) {
                    socket.emit('error', {
                        message: 'Access denied: Admin privileges required'
                    });
                    return;
                }

                const eventsData = await UserModel.getRealTimeSecurityEventsTable(filters, socket.user.user_id);
                
                socket.emit('security_events_data', {
                    ...eventsData,
                    realTime: true,
                    socketId: socket.id
                });

                this.updateUserActivity(socket.user.user_id);

            } catch (error) {
                console.error('Error fetching security events:', error);
                socket.emit('error', {
                    message: 'Failed to fetch security events'
                });
            }
        });

        // Request refresh of all real-time data
        socket.on('refresh_real_time_data', async () => {
            try {
                if (socket.user.role_id !== UserModel.ROLES.ADMIN) {
                    socket.emit('error', {
                        message: 'Access denied: Admin privileges required'
                    });
                    return;
                }

                await UserModel.refreshRealTimeData(socket.user.user_id);
                
                socket.emit('real_time_data_refreshed', {
                    success: true,
                    message: 'Real-time data refreshed successfully',
                    timestamp: new Date().toISOString()
                });

                this.updateUserActivity(socket.user.user_id);

            } catch (error) {
                console.error('Error refreshing real-time data:', error);
                socket.emit('error', {
                    message: 'Failed to refresh real-time data'
                });
            }
        });

        // Subscribe to live updates
        socket.on('subscribe_live_updates', (channels) => {
            if (!Array.isArray(channels)) {
                channels = [channels];
            }

            channels.forEach(channel => {
                if (this.isValidChannel(channel, socket.user)) {
                    socket.join(channel);
                    console.log(`User ${socket.user.email} subscribed to ${channel}`);
                }
            });
        });

        // Unsubscribe from live updates
        socket.on('unsubscribe_live_updates', (channels) => {
            if (!Array.isArray(channels)) {
                channels = [channels];
            }

            channels.forEach(channel => {
                socket.leave(channel);
                console.log(`User ${socket.user.email} unsubscribed from ${channel}`);
            });
        });
    }

    // Handle disconnection
    handleDisconnect(socket, reason) {
        console.log(`User ${socket.user?.email} disconnected. Reason: ${reason}`);

        if (socket.user) {
            // Remove from connected users
            this.connectedUsers.delete(socket.user.user_id);
            
            // Remove from admin rooms if applicable
            if (this.adminRooms.has(socket.user.user_id)) {
                this.adminRooms.delete(socket.user.user_id);
            }

            // Log disconnection event
            this.logDisconnection(socket.user, reason);
        }
    }

    // Update user activity timestamp
    updateUserActivity(userId) {
        const userConnection = this.connectedUsers.get(userId);
        if (userConnection) {
            userConnection.lastActivity = new Date();
        }
    }

    // Validate if user can join a channel
    isValidChannel(channel, user) {
        const publicChannels = ['notifications', 'alerts'];
        const adminChannels = ['admin_dashboard', 'security_monitoring', 'user_activity'];
        
        if (publicChannels.includes(channel)) {
            return true;
        }
        
        if (adminChannels.includes(channel) && user.role_id === UserModel.ROLES.ADMIN) {
            return true;
        }
        
        if (channel.startsWith('user:') && channel === `user:${user.user_id}`) {
            return true;
        }

        return false;
    }

    // Log disconnection event
    async logDisconnection(user, reason) {
        try {
            await UserModel.logSecurityEvent(
                user.user_id,
                null,
                'socket_disconnected',
                `User disconnected from real-time socket. Reason: ${reason}`,
                'low'
            );
        } catch (error) {
            console.error('Error logging socket disconnection:', error);
        }
    }

    // Emit to specific room
    emitToRoom(room, event, data) {
        if (this.io) {
            this.io.to(room).emit(event, {
                ...data,
                timestamp: new Date().toISOString()
            });
        }
    }

    // Emit to specific user
    emitToUser(userId, event, data) {
        if (this.io) {
            this.io.to(`user:${userId}`).emit(event, {
                ...data,
                timestamp: new Date().toISOString()
            });
        }
    }

    // Broadcast to all connected users
    broadcast(event, data) {
        if (this.io) {
            this.io.emit(event, {
                ...data,
                timestamp: new Date().toISOString()
            });
        }
    }

    // Get connected users count
    getConnectedUsersCount() {
        return this.connectedUsers.size;
    }

    // Get connected admins count
    getConnectedAdminsCount() {
        return this.adminRooms.size;
    }

    // Get user connection info
    getUserConnection(userId) {
        return this.connectedUsers.get(userId);
    }

    // Check if user is connected
    isUserConnected(userId) {
        return this.connectedUsers.has(userId);
    }

    // Force disconnect user
    disconnectUser(userId) {
        const userConnection = this.connectedUsers.get(userId);
        if (userConnection && this.io) {
            const socket = this.io.sockets.sockets.get(userConnection.socketId);
            if (socket) {
                socket.disconnect(true);
            }
        }
    }

    // Clean up inactive connections
    startCleanupInterval() {
        setInterval(() => {
            this.cleanupInactiveConnections();
        }, 5 * 60 * 1000); // Clean every 5 minutes
    }

    // Clean up connections inactive for more than 30 minutes
    cleanupInactiveConnections() {
        const now = new Date();
        const inactiveThreshold = 30 * 60 * 1000; // 30 minutes

        for (const [userId, connection] of this.connectedUsers.entries()) {
            if (now - connection.lastActivity > inactiveThreshold) {
                console.log(`Cleaning up inactive connection for user: ${connection.user.email}`);
                this.disconnectUser(userId);
            }
        }
    }

    // Get server statistics
    getServerStats() {
        return {
            connectedUsers: this.getConnectedUsersCount(),
            connectedAdmins: this.getConnectedAdminsCount(),
            totalRooms: this.io ? Object.keys(this.io.sockets.adapter.rooms).length : 0,
            uptime: process.uptime(),
            timestamp: new Date().toISOString()
        };
    }
}

// Create singleton instance
const socketManager = new SocketManager();

module.exports = socketManager;