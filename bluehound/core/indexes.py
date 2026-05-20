"""
BlueHound Neo4j Index Helper

Creates performance indexes on first connection.
"""

import logging

logger = logging.getLogger(__name__)


def create_indexes(session) -> None:
    """
    Create Neo4j indexes for frequently queried properties.
    
    """
    indexes = [
        # User indexes
        "CREATE INDEX user_objectid IF NOT EXISTS FOR (u:User) ON (u.objectid)",
        "CREATE INDEX user_name IF NOT EXISTS FOR (u:User) ON (u.name)",
        "CREATE INDEX user_enabled IF NOT EXISTS FOR (u:User) ON (u.enabled)",
        
        # Computer indexes
        "CREATE INDEX comp_objectid IF NOT EXISTS FOR (c:Computer) ON (c.objectid)",
        "CREATE INDEX comp_name IF NOT EXISTS FOR (c:Computer) ON (c.name)",
        "CREATE INDEX comp_enabled IF NOT EXISTS FOR (c:Computer) ON (c.enabled)",
        
        # Group indexes
        "CREATE INDEX group_objectid IF NOT EXISTS FOR (g:Group) ON (g.objectid)",
        "CREATE INDEX group_name IF NOT EXISTS FOR (g:Group) ON (g.name)",
    ]
    
    for index_query in indexes:
        try:
            session.run(index_query)
        except Exception:
            # Index already exists or other non-critical error
            pass
    
    logger.info("Neo4j indexes verified/created")
