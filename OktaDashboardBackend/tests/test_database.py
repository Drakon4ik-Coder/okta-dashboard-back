from django.test import TestCase
from OktaDashboardBackend.services.database import DatabaseService
import mongoengine
from mongoengine.connection import get_connection
import os

class TestDatabaseConnection(TestCase):
    def setUp(self):
        """Setup test environment"""
        self.original_db_name = os.environ.get('MONGODB_URL')
        os.environ['MONGODB_URL'] = 'mongodb://localhost:27017/test_db' # Use test database
        
        DatabaseService._instance = None
        DatabaseService._is_connected = False
        DatabaseService._connection = None
        
        mongoengine.disconnect_all()

    def test_database_connection(self):
        """Test database connection and basic query"""
        try:
            # Test connection establishment
            db_service = DatabaseService()
            self.assertTrue(db_service.is_connected())
            
            # Test singleton pattern
            second_service = DatabaseService()
            self.assertEqual(id(db_service), id(second_service))
            
            # Test basic query capability
            db = get_connection().get_database()
            # Create a test collection and insert a document
            test_collection = db.get_collection('test_collection')
            test_collection.insert_one({'test': 'data'})
            
            # Query the document
            result = test_collection.find_one({'test': 'data'})
            self.assertIsNotNone(result)
            self.assertEqual(result['test'], 'data')
            
        except Exception as e:
            self.fail(f"Database connection test failed: {str(e)}")

    def tearDown(self):
        try:
            # Clean up test data
            if DatabaseService().is_connected():
                db = get_connection().get_database()
                db.drop_collection('test_collection')
            
            # Disconnect from database
            DatabaseService().disconnect()
            
            # Restore original environment
            if self.original_db_name:
                os.environ['MONGODB_URL'] = self.original_db_name
            else:
                del os.environ['MONGODB_URL']
        except Exception as e:
            print(f"Teardown error: {str(e)}")