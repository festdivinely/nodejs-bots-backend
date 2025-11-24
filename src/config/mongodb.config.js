// config/mongodb.config.js
import mongoose from 'mongoose';

class Database {
    constructor() {
        this.isConnected = false;
        this.connection = null;
        this.connectionAttempts = 0;
        this.maxConnectionAttempts = 3;
        this.reconnectInterval = 5000;
    }

    async connect() {
        if (this.isConnected && this.connection) {
            console.log('✅ Using existing database connection');
            return this.connection;
        }

        try {
            const mongoUri = process.env.MONGODB_URI;

            if (!mongoUri) {
                throw new Error('MONGODB_URI environment variable is required');
            }

            if (!this.isValidMongoURI(mongoUri)) {
                throw new Error('Invalid MongoDB URI format');
            }

            const options = {
                maxPoolSize: process.env.NODE_ENV === 'production' ? 100 : 10,
                minPoolSize: process.env.NODE_ENV === 'production' ? 10 : 5,
                maxIdleTimeMS: 30000,
                serverSelectionTimeoutMS: 30000,
                socketTimeoutMS: 45000,
                connectTimeoutMS: 30000,
                retryWrites: true,
                retryReads: true,
                bufferCommands: true,
                autoIndex: process.env.NODE_ENV !== 'production',
                tls: true,
                w: 'majority',
                readPreference: 'primaryPreferred',
            };

            console.log(`🔗 Connecting to MongoDB Atlas...`);
            console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);

            mongoose.set('strictQuery', true);

            this.connection = await mongoose.connect(mongoUri, options);
            this.isConnected = true;
            this.connectionAttempts = 0;

            await this.setupEventHandlers();
            await this.setupProcessHandlers();

            console.log('✅ MongoDB Atlas connected successfully');
            console.log(`📈 Connection pool size: ${options.maxPoolSize}`);
            console.log(`🏠 Database: ${mongoose.connection.db?.databaseName || 'unknown'}`);

            return this.connection;

        } catch (error) {
            this.connectionAttempts++;
            console.error(`❌ MongoDB Atlas connection attempt ${this.connectionAttempts} failed:`, error.message);

            if (this.connectionAttempts < this.maxConnectionAttempts) {
                console.log(`🔄 Retrying connection in ${this.reconnectInterval / 1000} seconds...`);
                await this.delay(this.reconnectInterval);
                return this.connect();
            }

            console.error('💥 Critical: Unable to connect to MongoDB Atlas. Exiting...');
            process.exit(1);
        }
    }

    isValidMongoURI(uri) {
        try {
            const url = new URL(uri);
            return url.protocol === 'mongodb:' || url.protocol === 'mongodb+srv:';
        } catch {
            return false;
        }
    }

    async setupEventHandlers() {
        mongoose.connection.on('connected', () => {
            this.isConnected = true;
            console.log('✅ MongoDB Atlas connection established');
        });

        mongoose.connection.on('error', (err) => {
            this.isConnected = false;
            console.error('❌ MongoDB Atlas connection error:', err.message);

            setTimeout(() => {
                if (!this.isConnected) {
                    console.log('🔄 Attempting to reconnect to MongoDB Atlas...');
                    this.connect().catch(console.error);
                }
            }, this.reconnectInterval);
        });

        mongoose.connection.on('disconnected', () => {
            this.isConnected = false;
            console.log('⚠️ MongoDB Atlas connection lost');
        });

        mongoose.connection.on('reconnected', () => {
            this.isConnected = true;
            console.log('🔄 MongoDB Atlas reconnected');
        });
    }

    async setupProcessHandlers() {
        const gracefulShutdown = async (signal) => {
            console.log(`\n${signal} received. Starting graceful shutdown...`);

            try {
                await this.disconnect();
                console.log('✅ Graceful shutdown completed');
                process.exit(0);
            } catch (error) {
                console.error('❌ Error during shutdown:', error);
                process.exit(1);
            }
        };

        process.on('SIGINT', () => gracefulShutdown('SIGINT'));
        process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
        process.on('SIGUSR2', () => gracefulShutdown('SIGUSR2'));
    }

    async disconnect() {
        try {
            if (mongoose.connection.readyState !== 0) {
                await mongoose.connection.close();
                console.log('🔌 MongoDB Atlas connection closed');
            }

            this.isConnected = false;
            this.connection = null;

        } catch (error) {
            console.error('❌ Error disconnecting from MongoDB Atlas:', error);
            throw error;
        }
    }

    // Health check method - FIXED: Make sure this exists
    async healthCheck() {
        try {
            if (!this.isConnected || mongoose.connection.readyState !== 1) {
                return {
                    status: 'disconnected',
                    readyState: mongoose.connection.readyState,
                    timestamp: new Date().toISOString(),
                    error: 'Not connected to database'
                };
            }

            const startTime = Date.now();
            await mongoose.connection.db.admin().ping();
            const responseTime = Date.now() - startTime;

            const dbStats = await mongoose.connection.db.stats();

            return {
                status: 'healthy',
                readyState: mongoose.connection.readyState,
                responseTime: `${responseTime}ms`,
                timestamp: new Date().toISOString(),
                database: {
                    name: mongoose.connection.db.databaseName,
                    collections: dbStats.collections,
                    objects: dbStats.objects,
                    dataSize: this.formatBytes(dbStats.dataSize),
                    storageSize: this.formatBytes(dbStats.storageSize),
                    indexSize: this.formatBytes(dbStats.indexSize)
                },
                connection: {
                    host: mongoose.connection.host,
                    port: mongoose.connection.port,
                    name: mongoose.connection.name
                }
            };
        } catch (error) {
            return {
                status: 'unhealthy',
                readyState: mongoose.connection.readyState,
                timestamp: new Date().toISOString(),
                error: error.message
            };
        }
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    getConnectionState() {
        const states = {
            0: 'disconnected',
            1: 'connected',
            2: 'connecting',
            3: 'disconnecting'
        };
        return {
            code: mongoose.connection.readyState,
            state: states[mongoose.connection.readyState] || 'unknown'
        };
    }
}

// Create singleton instance
const database = new Database();

// FIXED: Export the healthCheck method correctly
export const connectDb = () => database.connect();
export const disconnectDb = () => database.disconnect();
export const dbHealthCheck = () => database.healthCheck(); // This was missing!
export const getConnectionState = () => database.getConnectionState();
export default database;