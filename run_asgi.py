"""
ASGI Server startup script for the Okta Dashboard.

This script runs the application using uvicorn ASGI server
to properly handle asynchronous views and middleware.
"""
import os
import sys
import argparse

def main():
    """Run the ASGI server."""
    parser = argparse.ArgumentParser(description='Start ASGI server for Okta Dashboard')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port', default=8000, type=int, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    args = parser.parse_args()
    
    # Add the app directory to the path
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, base_dir)
    apps_dir = os.path.join(base_dir, 'apps')
    if os.path.exists(apps_dir):
        sys.path.insert(0, apps_dir)
    
    # Set the Django settings module
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    
    # Import after setting environment variables
    import uvicorn
    
    # Run the ASGI server
    uvicorn.run(
        "config.asgi:application", 
        host=args.host, 
        port=args.port,
        reload=args.debug,
        log_level="info",
    )

if __name__ == '__main__':
    main()
