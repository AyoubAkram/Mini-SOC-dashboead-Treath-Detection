"""
Log Ingestion Module
Handles the collection, storage, and retrieval of security logs using MongoDB
"""

import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import os

# MongoDB connection
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "soc_dashboard")
MONGO_COLLECTION = "logs"

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    # Verify connection
    client.admin.command('ping')
    db = client[MONGO_DB]
    logs_collection = db[MONGO_COLLECTION]
    
    # Create indexes for better query performance
    logs_collection.create_index("INGESTION_TIMESTAMP")
    logs_collection.create_index("_SYSTEMD_UNIT")
    logs_collection.create_index("_COMM")
    
    print(f"✓ Connected to MongoDB: {MONGO_URI}")
except ConnectionFailure as e:
    print(f"✗ Failed to connect to MongoDB: {e}")
    db = None
    logs_collection = None


def ingest_log(log_entry: str) -> bool:
    """
    Ingest a single log entry into MongoDB
    
    Args:
        log_entry: JSON string of the log from journalctl
        
    Returns:
        bool: True if ingestion was successful, False otherwise
    """
    if not logs_collection:
        print("MongoDB not connected")
        return False
        
    try:
        # Parse JSON log entry
        log_data = json.loads(log_entry)
        
        # Add ingestion timestamp if not present
        if 'INGESTION_TIMESTAMP' not in log_data:
            log_data['INGESTION_TIMESTAMP'] = datetime.utcnow()
        
        # Insert into MongoDB
        result = logs_collection.insert_one(log_data)
        return result.inserted_id is not None
            
    except json.JSONDecodeError:
        print(f"Failed to parse log entry: {log_entry}")
        return False
    except Exception as e:
        print(f"Error ingesting log: {e}")
        return False


def get_logs(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """
    Retrieve logs from MongoDB
    
    Args:
        limit: Maximum number of logs to return
        offset: Number of logs to skip from the beginning
        
    Returns:
        List of log entries
    """
    if not logs_collection:
        return []
        
    try:
        # Get most recent logs first
        logs = list(logs_collection.find().sort("INGESTION_TIMESTAMP", -1).skip(offset).limit(limit))
        
        # Convert ObjectId to string for JSON serialization
        for log in logs:
            log['_id'] = str(log['_id'])
            
        return logs
    except Exception as e:
        print(f"Error retrieving logs: {e}")
        return []


def get_log_count() -> int:
    """Get total number of logs in MongoDB"""
    if not logs_collection:
        return 0
        
    try:
        return logs_collection.count_documents({})
    except Exception as e:
        print(f"Error counting logs: {e}")
        return 0


def filter_logs_by_service(service_name: str, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Filter logs by service/unit name
    
    Args:
        service_name: Name of the service to filter by
        limit: Maximum number of logs to return
        
    Returns:
        List of filtered log entries
    """
    if not logs_collection:
        return []
        
    try:
        query = {"_SYSTEMD_UNIT": f"{service_name}.service"}
        logs = list(logs_collection.find(query).sort("INGESTION_TIMESTAMP", -1).limit(limit))
        
        for log in logs:
            log['_id'] = str(log['_id'])
            
        return logs
    except Exception as e:
        print(f"Error filtering logs by service: {e}")
        return []


def filter_logs_by_command(command: str, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Filter logs by command name
    
    Args:
        command: Command name to filter by (e.g., 'sudo')
        limit: Maximum number of logs to return
        
    Returns:
        List of filtered log entries
    """
    if not logs_collection:
        return []
        
    try:
        query = {"_COMM": command}
        logs = list(logs_collection.find(query).sort("INGESTION_TIMESTAMP", -1).limit(limit))
        
        for log in logs:
            log['_id'] = str(log['_id'])
            
        return logs
    except Exception as e:
        print(f"Error filtering logs by command: {e}")
        return []


def get_security_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Get security-related logs (SSH, sudo)
    
    Args:
        limit: Maximum number of logs to return
        
    Returns:
        List of security logs
    """
    if not logs_collection:
        return []
        
    try:
        query = {
            "$or": [
                {"_SYSTEMD_UNIT": "ssh.service"},
                {"_COMM": "sudo"},
                {"_COMM": {"$regex": "ssh", "$options": "i"}}
            ]
        }
        logs = list(logs_collection.find(query).sort("INGESTION_TIMESTAMP", -1).limit(limit))
        
        for log in logs:
            log['_id'] = str(log['_id'])
            
        return logs
    except Exception as e:
        print(f"Error retrieving security logs: {e}")
        return []


def clear_logs() -> int:
    """Clear all logs from MongoDB"""
    if not logs_collection:
        return 0
        
    try:
        result = logs_collection.delete_many({})
        return result.deleted_count
    except Exception as e:
        print(f"Error clearing logs: {e}")
        return 0
