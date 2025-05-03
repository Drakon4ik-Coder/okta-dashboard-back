import os
import mongoengine
from django.conf import settings
import logging
from pymongo import MongoClient
import time
import sys

logger = logging.getLogger(__name__)

"""Singleton class to manage MongoDB connection"""
class DatabaseService:
    _instance = None
    _is_connected = False
    _connection = None
    _client = None
    _last_ping = 0
    _ping_interval = 60  # Check connection every 60 seconds
    
    @classmethod
    def reset_instance(cls):
        """Reset the singleton instance - helpful for testing environments"""
        if cls._instance:
            cls._instance.disconnect()
        cls._instance = None
        cls._is_connected = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseService, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._is_connected:
            self.connect()

    def connect(self):
        """Establish connection to MongoDB with optimized connection pooling"""
        try:
            # Force disconnect of all existing connections
            DatabaseService._is_connected = False
            self._connection = None
            if self._client:
                self._client.close()
                self._client = None
            
            # Explicitly disconnect all mongoengine connections
            mongoengine.disconnect_all()
            
            # Get MongoDB connection settings
            mongo_host = settings.MONGODB_SETTINGS['host']
            
            # Configure connection pool settings
            pool_settings = {
                'maxPoolSize': 100,  # Maximum number of connections in the pool
                'minPoolSize': 10,   # Minimum number of connections in the pool
                'maxIdleTimeMS': 30000,  # Max time a connection can be idle (30 seconds)
                'waitQueueTimeoutMS': 5000,  # How long to wait for an available connection
                'socketTimeoutMS': 20000,  # Socket timeout in milliseconds
                'connectTimeoutMS': 10000,  # Connection timeout in milliseconds
                'serverSelectionTimeoutMS': 10000  # Server selection timeout
            }
            
            # Add pool settings to connection string if not SRV URI
            if 'mongodb://' in mongo_host and '?' not in mongo_host:
                mongo_host += '?'
                params = []
                for key, value in pool_settings.items():
                    params.append(f"{key}={value}")
                mongo_host += '&'.join(params)
                
            logger.debug(f"Connecting to MongoDB with optimized connection pool")
            
            # Create MongoClient instance with connection pooling
            self._client = MongoClient(mongo_host)
            
            # Create mongoengine connection with a unique alias for this session
            # Use an alias based on timestamp to ensure uniqueness in test environments
            connection_alias = f"default_{int(time.time())}" if "test" in sys.argv else "default"
            
            self._connection = mongoengine.connect(
                host=mongo_host,
                alias=connection_alias
            )
            
            # Test connection
            self._client.admin.command('ping')
            self._last_ping = time.time()
            DatabaseService._is_connected = True
            logger.info(f"Successfully connected to MongoDB with optimized connection pool (alias: {connection_alias})")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {str(e)}")
            DatabaseService._is_connected = False
            raise

    def is_connected(self):
        """Check if database is connected with connection refresh"""
        # Check if we should test the connection based on ping interval
        current_time = time.time()
        should_ping = (current_time - self._last_ping) > self._ping_interval
        
        if not self._is_connected or not self._connection or not self._client:
            return False
            
        if should_ping:
            try:
                # Test connection with a ping
                self._client.admin.command('ping')
                self._last_ping = current_time
                return True
            except Exception as e:
                logger.warning(f"MongoDB connection test failed: {e}")
                self._is_connected = False
                # Try to reconnect
                try:
                    logger.info("Attempting to reconnect to MongoDB")
                    self.connect()
                    return self._is_connected
                except Exception as reconnect_error:
                    logger.error(f"Failed to reconnect to MongoDB: {reconnect_error}")
                    return False
        return True

    def disconnect(self):
        """Disconnect from MongoDB"""
        if self._client:
            self._client.close()
        mongoengine.disconnect_all()
        self._connection = None
        self._client = None
        DatabaseService._is_connected = False
        logger.info("Disconnected from MongoDB")
        
    def get_client(self):
        """Get the raw MongoDB client for advanced operations"""
        if not self._is_connected:
            self.connect()
        return self._client
        
    def get_collection(self, db_name, collection_name):
        """Get a MongoDB collection with connection check"""
        if not self.is_connected():
            self.connect()
        return self._client[db_name][collection_name]