import os
import mongoengine
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

"""Singleton class to manage MongoDB connection"""
class DatabaseService:
    _instance = None
    _is_connected = False
    _connection = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseService, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._is_connected:
            self.connect()

    def connect(self):
        """Establish connection to MongoDB"""
        try:
            mongoengine.disconnect_all()  # Disconnect any existing connections
            self._connection = mongoengine.connect(
                host=settings.MONGODB_SETTINGS['host'],
                alias='default'
            )
            # Test connection
            self._connection.server_info()
            DatabaseService._is_connected = True
            logger.info("Successfully connected to MongoDB")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {str(e)}")
            DatabaseService._is_connected = False
            raise

    def is_connected(self):
        """Check if database is connected"""
        if not self._is_connected or not self._connection:
            return False
        try:
            self._connection.server_info()
            return True
        except Exception:
            self._is_connected = False
            return False

    def disconnect(self):
        """Disconnect from MongoDB"""
        mongoengine.disconnect_all()
        self._connection = None
        DatabaseService._is_connected = False
        logger.info("Disconnected from MongoDB")