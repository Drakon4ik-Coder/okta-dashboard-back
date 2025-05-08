import os
import sys
import django
import datetime

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

print('========== TESTING MONGODB CONNECTION ==========')
try:
    # Reset all MongoDB connections first
    from mongoengine import disconnect_all
    disconnect_all()
    print('Successfully disconnected existing connections')
    
    # Clear mongoengine's internal connection registry
    import mongoengine.connection
    if hasattr(mongoengine.connection, '_connections'):
        mongoengine.connection._connections = {}
    if hasattr(mongoengine.connection, '_connection_settings'):
        mongoengine.connection._connection_settings = {}
    if hasattr(mongoengine.connection, '_dbs'):
        mongoengine.connection._dbs = {}
    print('Cleared mongoengine connection registry')
    
    # Import the DatabaseService class
    from config.services.database import DatabaseService
    
    # Reset the DatabaseService singleton
    print('Resetting DatabaseService...')
    DatabaseService.reset()
    
    # Create a new connection
    print('Initializing new connection...')
    db_service = DatabaseService()
    
    # Test the connection
    if db_service.is_connected():
        print('✅ Successfully connected to MongoDB!')
        
        # Get a list of databases
        dbs = db_service.get_client().list_database_names()
        print(f'Available databases: {dbs}')
        
        # Get a collection and count documents
        test_collection = db_service.get_collection('test_db', 'test_collection')
        test_collection.insert_one({'test': 'connection_test', 'timestamp': datetime.datetime.now()})
        count = test_collection.count_documents({})
        print(f'Inserted test document. Collection has {count} documents')
    else:
        print('❌ Failed to connect to MongoDB')
except Exception as e:
    print(f'❌ Error testing MongoDB connection: {str(e)}')

