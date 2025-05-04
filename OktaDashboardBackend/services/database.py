import os
import mongoengine
from django.conf import settings
import logging
from pymongo import MongoClient
import time
import environ

logger = logging.getLogger(__name__)
env = environ.Env()

"""Singleton class to manage MongoDB connection"""
class DatabaseService:
    _instance = None
    _is_connected = False
    _connection = None
    _client = None
    _last_ping = 0
    _ping_interval = 60  # Check connection every 60 seconds

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseService, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._is_connected:
            self.connect()

    @classmethod
    def reset(cls):
        """Reset the singleton instance and disconnect any existing connections"""
        if cls._instance and cls._instance._client:
            cls._instance._client.close()
        
        # Clear mongoengine's connection registry
        mongoengine.disconnect_all()
        
        # Clear connection registry in mongoengine
        if hasattr(mongoengine.connection, '_connections'):
            mongoengine.connection._connections = {}
        if hasattr(mongoengine.connection, '_connection_settings'):
            mongoengine.connection._connection_settings = {}
        if hasattr(mongoengine.connection, '_dbs'):
            mongoengine.connection._dbs = {}
        
        # Reset instance variables
        cls._instance = None
        cls._is_connected = False
        cls._connection = None
        cls._client = None
        cls._last_ping = 0

    def connect(self):
        """Establish connection to MongoDB with optimized connection pooling"""
        try:
            # First ensure all existing connections are properly cleaned up
            self.__class__.reset()
            
            # First try MONGODB_URL if it exists
            mongo_url = env("MONGODB_URL", default=None)
            
            # If no direct URL is provided, build one from components
            if not mongo_url:
                mongo_host = settings.MONGODB_SETTINGS.get('host', 'localhost')
                mongo_port = settings.MONGODB_SETTINGS.get('port', 27017)
                mongo_db = settings.MONGODB_SETTINGS.get('db', 'OktaDashboardDB')
                mongo_user = settings.MONGODB_SETTINGS.get('username')
                mongo_pass = settings.MONGODB_SETTINGS.get('password')
                
                # Build connection URL
                if mongo_user and mongo_pass:
                    auth_part = f"{mongo_user}:{mongo_pass}@"
                else:
                    auth_part = ""
                    
                mongo_url = f"mongodb://{auth_part}{mongo_host}:{mongo_port}/{mongo_db}"
            
            # Configure connection pool settings
            pool_settings = {
                'maxPoolSize': settings.MONGODB_SETTINGS.get('maxPoolSize', 100),
                'minPoolSize': settings.MONGODB_SETTINGS.get('minPoolSize', 10),
                'maxIdleTimeMS': settings.MONGODB_SETTINGS.get('maxIdleTimeMS', 30000),
                'waitQueueTimeoutMS': settings.MONGODB_SETTINGS.get('waitQueueTimeoutMS', 5000),
                'socketTimeoutMS': settings.MONGODB_SETTINGS.get('socketTimeoutMS', 20000),
                'connectTimeoutMS': settings.MONGODB_SETTINGS.get('connectTimeoutMS', 10000),
                'serverSelectionTimeoutMS': settings.MONGODB_SETTINGS.get('serverSelectionTimeoutMS', 10000)
            }
            
            # Add pool settings to connection string if not SRV URI and no existing params
            if 'mongodb://' in mongo_url and '?' not in mongo_url:
                mongo_url += '?'
                params = []
                for key, value in pool_settings.items():
                    params.append(f"{key}={value}")
                mongo_url += '&'.join(params)
                
            logger.debug(f"Connecting to MongoDB with optimized connection pool")
            
            # Create MongoClient instance with connection pooling
            self._client = MongoClient(mongo_url)
            
            # Create mongoengine connection
            self._connection = mongoengine.connect(
                host=mongo_url,
                alias='default'
            )
            
            # Test connection
            self._client.admin.command('ping')
            self._last_ping = time.time()
            DatabaseService._is_connected = True
            logger.info("Successfully connected to MongoDB with optimized connection pool")
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