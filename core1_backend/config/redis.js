const redis = require('redis');

class RedisManager {
    constructor() {
        this.client = null;
        this.isConnected = false;
        this.useMemoryFallback = false;
        this.memoryCache = new Map();
    }

    async connect() {
        try {
            // Check if Redis is available
            if (!process.env.REDIS_URL && !process.env.REDIS_PASSWORD) {
                console.log('⚠️  Redis not configured, using in-memory fallback');
                this.useMemoryFallback = true;
                this.isConnected = true;
                return this;
            }

            this.client = redis.createClient({
                url: process.env.REDIS_URL || 'redis://localhost:6379',
                password: process.env.REDIS_PASSWORD,
                socket: {
                    connectTimeout: 5000, // Reduced timeout
                    lazyConnect: true,
                    reconnectStrategy: (retries) => {
                        if (retries > 3) { // Reduced retries
                            console.log('⚠️  Redis connection failed, using in-memory fallback');
                            this.useMemoryFallback = true;
                            this.isConnected = true;
                            return false; // Stop retrying
                        }
                        return Math.min(retries * 100, 1000);
                    }
                }
            });

            // Event handlers
            this.client.on('connect', () => {
                console.log('✅ Redis client connected');
                this.isConnected = true;
                this.useMemoryFallback = false;
            });

            this.client.on('error', (err) => {
                console.error('❌ Redis client error:', err.message);
                this.isConnected = false;
            });

            this.client.on('disconnect', () => {
                console.log('⚠️ Redis client disconnected');
                this.isConnected = false;
            });

            await this.client.connect();
            return this;
        } catch (error) {
            console.log('⚠️  Redis connection failed, using in-memory fallback:', error.message);
            this.useMemoryFallback = true;
            this.isConnected = true;
            return this;
        }
    }

    // Memory fallback methods
    async get(key) {
        if (this.useMemoryFallback) {
            const value = this.memoryCache.get(key);
            return value || null;
        }
        
        if (!this.isConnected) {
            throw new Error('Redis client not connected');
        }
        return await this.client.get(key);
    }

    async set(key, value, expireSeconds = null) {
        if (this.useMemoryFallback) {
            this.memoryCache.set(key, value);
            if (expireSeconds) {
                setTimeout(() => {
                    this.memoryCache.delete(key);
                }, expireSeconds * 1000);
            }
            return 'OK';
        }
        
        if (!this.isConnected) {
            throw new Error('Redis client not connected');
        }
        
        if (expireSeconds) {
            return await this.client.setEx(key, expireSeconds, value);
        } else {
            return await this.client.set(key, value);
        }
    }

    async setex(key, seconds, value) {
        return await this.set(key, value, seconds);
    }

    async del(...keys) {
        if (this.useMemoryFallback) {
            keys.forEach(key => this.memoryCache.delete(key));
            return keys.length;
        }
        
        if (!this.isConnected) {
            throw new Error('Redis client not connected');
        }
        return await this.client.del(keys);
    }

    async exists(key) {
        if (this.useMemoryFallback) {
            return this.memoryCache.has(key) ? 1 : 0;
        }
        
        if (!this.isConnected) {
            throw new Error('Redis client not connected');
        }
        return await this.client.exists(key);
    }

    async expire(key, seconds) {
        if (this.useMemoryFallback) {
            // Memory fallback doesn't support precise expiration
            return 1;
        }
        
        if (!this.isConnected) {
            throw new Error('Redis client not connected');
        }
        return await this.client.expire(key, seconds);
    }

    async keys(pattern) {
        if (this.useMemoryFallback) {
            const allKeys = Array.from(this.memoryCache.keys());
            const regex = new RegExp(pattern.replace('*', '.*'));
            return allKeys.filter(key => regex.test(key));
        }
        
        if (!this.isConnected) {
            throw new Error('Redis client not connected');
        }
        return await this.client.keys(pattern);
    }

    async quit() {
        if (this.client && !this.useMemoryFallback) {
            await this.client.quit();
            this.isConnected = false;
        }
    }

    // Health check
    async healthCheck() {
        if (this.useMemoryFallback) {
            return { 
                status: 'fallback', 
                message: 'Using in-memory cache',
                cacheSize: this.memoryCache.size 
            };
        }
        
        try {
            if (!this.isConnected) {
                return { status: 'disconnected', error: 'Redis client not connected' };
            }
            
            await this.client.ping();
            return { status: 'connected', timestamp: new Date().toISOString() };
        } catch (error) {
            return { status: 'error', error: error.message };
        }
    }
}

// Create singleton instance
const redisManager = new RedisManager();

// Initialize connection without blocking startup
redisManager.connect().catch(error => {
    console.log('Redis initialization completed with fallback');
});

module.exports = redisManager;