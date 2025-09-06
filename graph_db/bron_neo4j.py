"""
Neo4j integration module for BRON graph database.
Provides parallel functionality to bron_arango.py for Neo4j graph database.
"""

import json
import logging
import os
import sys
import uuid
from typing import Dict, List, Optional, Tuple, Any, Union
import argparse

from neo4j import GraphDatabase
import jsonschema
from tqdm import tqdm

from utils.bron_utils import load_graph_network
from graph_db.neo4j_schema_mapper import Neo4jSchemaMapper


# Neo4j Configuration
DEFAULT_URI = "bolt://localhost:7687"
DEFAULT_USER = "neo4j"
DEFAULT_PASSWORD = "password123"
DEFAULT_DATABASE = "neo4j"

# Schema mapping based on provided Neo4j schema
NODE_TYPES = {
    "technique", "engage_approach", "engage_activity", "tactic", "cwe", 
    "engage_goal", "technique_detection", "software", "technique_mitigation",
    "capec_detection", "cpe", "capec_mitigation", "cwe_detection", 
    "cwe_mitigation", "d3fend_mitigation", "cve", "capec", "group"
}

RELATIONSHIP_TYPES = {
    "IS_ACHIEVED_BY_TECHNIQUE", "DEFENDS_AGAINST_TECHNIQUE", "WEAKNESS_IS_MITIGATED_BY",
    "IS_ACHIEVED_BY_APPROACH", "USED_TECHNIQUE", "IS_PARENT_OF_WEAKNESS", 
    "IS_ADDRESSED_BY_ACTIVITY", "WEAKNESS_IS_DETECTED_BY", "TECHNIQUE_IS_MITIGATED_BY",
    "ATTACK_PATTERN_IS_MITIGATED_BY", "TECHNIQUE_IS_DETECTED_BY", "IS_REFINED_BY_SUB_TECHNIQUE",
    "IS_PARENT_OF_ATTACK_PATTERN", "IS_REPRESENTED_AS_ATTACK_PATTERN", "USED_SOFTWARE",
    "IS_COMPROMISING_PLATFORM", "IS_BEING_EXPLOITED_IN_VULNERABILITY", "IMPLEMENTS_TECHNIQUE",
    "EXPLOITS_WEAKNESS", "IS_IMPLEMENTED_BY_ACTIVITY", "ATTACK_PATTERN_IS_DETECTED_BY"
}


class BronNeo4j:
    """Neo4j database handler for BRON graph data."""
    
    def __init__(self, uri: str = DEFAULT_URI, user: str = DEFAULT_USER, 
                 password: str = DEFAULT_PASSWORD, database: str = DEFAULT_DATABASE):
        """Initialize Neo4j connection."""
        self.uri = uri
        self.user = user  
        self.password = password
        self.database = database
        self.driver = None
        self.schema_mapper = Neo4jSchemaMapper()
        
    def connect(self):
        """Establish connection to Neo4j."""
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            # Test connection
            with self.driver.session(database=self.database) as session:
                result = session.run("RETURN 1 as test")
                result.single()
            logging.info(f"Connected to Neo4j at {self.uri}")
        except Exception as e:
            logging.error(f"Failed to connect to Neo4j: {e}")
            raise
            
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()
            logging.info("Closed Neo4j connection")
            
    def clear_database(self):
        """Clear all nodes and relationships from the database."""
        with self.driver.session(database=self.database) as session:
            # Delete all relationships first
            session.run("MATCH ()-[r]-() DELETE r")
            # Then delete all nodes
            session.run("MATCH (n) DELETE n")
            logging.info("Cleared Neo4j database")
            
    def create_constraints(self):
        """Create unique constraints on node properties."""
        constraints = [
            ("technique", "original_id"),
            ("tactic", "original_id"), 
            ("capec", "original_id"),
            ("cwe", "original_id"),
            ("cve", "original_id"),
            ("cpe", "original_id"),
            ("software", "original_id"),
            ("group", "original_id"),
            ("engage_goal", "original_id"),
            ("engage_approach", "original_id"),
            ("engage_activity", "original_id"),
            ("d3fend_mitigation", "original_id")
        ]
        
        with self.driver.session(database=self.database) as session:
            for node_type, property_name in constraints:
                try:
                    query = f"CREATE CONSTRAINT {node_type}_{property_name}_unique IF NOT EXISTS FOR (n:{node_type}) REQUIRE n.{property_name} IS UNIQUE"
                    session.run(query)
                    logging.debug(f"Created constraint for {node_type}.{property_name}")
                except Exception as e:
                    logging.warning(f"Failed to create constraint for {node_type}.{property_name}: {e}")
                    
    def create_indexes(self):
        """Create indexes for better query performance."""
        indexes = [
            ("technique", "name"),
            ("tactic", "name"),
            ("capec", "name"),
            ("cwe", "name"),
            ("cve", "original_id"),
            ("software", "name"),
            ("group", "name")
        ]
        
        with self.driver.session(database=self.database) as session:
            for node_type, property_name in indexes:
                try:
                    query = f"CREATE INDEX {node_type}_{property_name}_index IF NOT EXISTS FOR (n:{node_type}) ON (n.{property_name})"
                    session.run(query)
                    logging.debug(f"Created index for {node_type}.{property_name}")
                except Exception as e:
                    logging.warning(f"Failed to create index for {node_type}.{property_name}: {e}")

    def batch_create_nodes(self, node_type: str, nodes_data: List[Dict], batch_size: int = 1000):
        """Create nodes in batches for better performance."""
        with self.driver.session(database=self.database) as session:
            for i in tqdm(range(0, len(nodes_data), batch_size), desc=f"Creating {node_type} nodes"):
                batch = nodes_data[i:i + batch_size]
                
                # Build the Cypher query for batch insert
                query = f"""
                UNWIND $nodes AS node
                CREATE (n:{node_type})
                SET n = node
                """
                
                session.run(query, nodes=batch)
                
        logging.info(f"Created {len(nodes_data)} {node_type} nodes")

    def batch_create_relationships(self, rel_type: str, from_label: str, to_label: str, 
                                 relationships_data: List[Dict], batch_size: int = 1000):
        """Create relationships in batches."""
        with self.driver.session(database=self.database) as session:
            for i in tqdm(range(0, len(relationships_data), batch_size), 
                         desc=f"Creating {rel_type} relationships"):
                batch = relationships_data[i:i + batch_size]
                
                query = f"""
                UNWIND $rels AS rel
                MATCH (from:{from_label} {{_id: rel._from}})
                MATCH (to:{to_label} {{_id: rel._to}})
                CREATE (from)-[r:{rel_type}]->(to)
                SET r = rel
                """
                
                session.run(query, rels=batch)
                
        logging.info(f"Created {len(relationships_data)} {rel_type} relationships")

    def import_bron_data(self, bron_json_path: str):
        """Import BRON data from JSON file into Neo4j."""
        logging.info(f"Starting import of BRON data from {bron_json_path}")
        
        if not os.path.exists(bron_json_path):
            raise FileNotFoundError(f"BRON JSON file not found: {bron_json_path}")
            
        with open(bron_json_path, 'r') as f:
            bron_data = json.load(f)
            
        # Use schema mapper to convert data
        nodes_by_type, relationships_by_type = self.schema_mapper.map_bron_data(bron_data)
        
        # Import mapped nodes
        for node_type, nodes in nodes_by_type.items():
            if nodes:
                self.batch_create_nodes(node_type, nodes)
                
        # Import mapped relationships
        for rel_type, relationships in relationships_by_type.items():
            if relationships:
                # Determine node types from relationship
                sample_rel = relationships[0]
                from_type, to_type = self._infer_node_types_from_relationship_data(rel_type, sample_rel)
                self.batch_create_relationships(rel_type, from_type, to_type, relationships)
                
        logging.info("Completed BRON data import to Neo4j")

    def _import_networkx_style(self, bron_data: Dict):
        """Import data from NetworkX JSON format."""
        nodes_by_type = {}
        
        # Group nodes by type
        for node in bron_data['nodes']:
            node_type = self._determine_node_type(node)
            if node_type not in nodes_by_type:
                nodes_by_type[node_type] = []
            nodes_by_type[node_type].append(node)
            
        # Create nodes by type
        for node_type, nodes in nodes_by_type.items():
            if node_type in NODE_TYPES:
                self.batch_create_nodes(node_type, nodes)
                
        # Group relationships by type
        rels_by_type = {}
        for link in bron_data['links']:
            rel_type = self._determine_relationship_type(link)
            if rel_type not in rels_by_type:
                rels_by_type[rel_type] = []
            rels_by_type[rel_type].append(link)
            
        # Create relationships
        for rel_type, rels in rels_by_type.items():
            if rels:
                # Determine source and target node types
                sample_rel = rels[0]
                from_type = self._get_node_type_from_id(sample_rel.get('source'))
                to_type = self._get_node_type_from_id(sample_rel.get('target'))
                self.batch_create_relationships(rel_type, from_type, to_type, rels)

    def _import_direct_style(self, bron_data: Dict):
        """Import data from direct node/relationship format.""" 
        # Import each node type
        for node_type in NODE_TYPES:
            if node_type in bron_data:
                self.batch_create_nodes(node_type, bron_data[node_type])
                
        # Import relationships
        for rel_type in RELATIONSHIP_TYPES:
            if rel_type in bron_data:
                # Determine node types based on relationship name and data
                rels = bron_data[rel_type]
                if rels:
                    from_type, to_type = self._infer_node_types_from_relationship(rel_type, rels[0])
                    self.batch_create_relationships(rel_type, from_type, to_type, rels)

    def _determine_node_type(self, node: Dict) -> str:
        """Determine node type from node data."""
        # Check for explicit type field
        if 'type' in node:
            return node['type']
        
        # Try to infer from original_id pattern
        original_id = node.get('original_id', '')
        if original_id.startswith('T') and ('.' in original_id or original_id[1:].isdigit()):
            return 'technique'
        elif original_id.startswith('TA') and original_id[2:].isdigit():
            return 'tactic'  
        elif original_id.startswith('CAPEC-') or original_id.startswith('CA-'):
            return 'capec'
        elif original_id.startswith('CWE-'):
            return 'cwe'
        elif original_id.startswith('CVE-'):
            return 'cve'
        elif original_id.startswith('cpe:'):
            return 'cpe'
        elif original_id.startswith('S') and original_id[1:].isdigit():
            return 'software'
        elif original_id.startswith('G') and original_id[1:].isdigit():
            return 'group'
            
        # Default fallback
        return 'unknown'

    def _determine_relationship_type(self, link: Dict) -> str:
        """Determine relationship type from link data."""
        # Check for explicit relationship type
        if 'relationship_type' in link:
            return link['relationship_type']
        
        # Try to infer from source/target types
        source_id = link.get('source', '')
        target_id = link.get('target', '')
        
        source_type = self._get_node_type_from_id(source_id)
        target_type = self._get_node_type_from_id(target_id)
        
        # Common relationship patterns
        if source_type == 'tactic' and target_type == 'technique':
            return 'IS_ACHIEVED_BY_TECHNIQUE'
        elif source_type == 'technique' and target_type == 'capec':
            return 'IS_REPRESENTED_AS_ATTACK_PATTERN'
        elif source_type == 'capec' and target_type == 'cwe':
            return 'EXPLOITS_WEAKNESS'
        elif source_type == 'cwe' and target_type == 'cve':
            return 'IS_BEING_EXPLOITED_IN_VULNERABILITY'
        elif source_type == 'cve' and target_type == 'cpe':
            return 'IS_COMPROMISING_PLATFORM'
            
        return 'RELATED_TO'  # Default relationship type

    def _get_node_type_from_id(self, node_id: str) -> str:
        """Get node type from node ID."""
        if not node_id:
            return 'unknown'
            
        if node_id.startswith('T') and ('.' in node_id or node_id[1:].isdigit()):
            return 'technique'
        elif node_id.startswith('TA') and node_id[2:].isdigit():
            return 'tactic'
        elif node_id.startswith('CAPEC-') or node_id.startswith('CA-'):
            return 'capec'
        elif node_id.startswith('CWE-'):
            return 'cwe'
        elif node_id.startswith('CVE-'):
            return 'cve'
        elif node_id.startswith('cpe:'):
            return 'cpe'
        elif node_id.startswith('S') and node_id[1:].isdigit():
            return 'software'
        elif node_id.startswith('G') and node_id[1:].isdigit():
            return 'group'
            
        return 'unknown'

    def _infer_node_types_from_relationship(self, rel_type: str, sample_rel: Dict) -> Tuple[str, str]:
        """Infer source and target node types from relationship type and sample data."""
        # Use the relationship type to determine expected node types
        type_mappings = {
            'IS_ACHIEVED_BY_TECHNIQUE': ('tactic', 'technique'),
            'IS_REPRESENTED_AS_ATTACK_PATTERN': ('technique', 'capec'),
            'EXPLOITS_WEAKNESS': ('capec', 'cwe'),
            'IS_BEING_EXPLOITED_IN_VULNERABILITY': ('cwe', 'cve'),
            'IS_COMPROMISING_PLATFORM': ('cve', 'cpe'),
            'DEFENDS_AGAINST_TECHNIQUE': ('d3fend_mitigation', 'technique'),
            'TECHNIQUE_IS_MITIGATED_BY': ('technique', 'technique_mitigation'),
            'USED_TECHNIQUE': ('group', 'technique'),
            'IMPLEMENTS_TECHNIQUE': ('software', 'technique'),
        }
        
        if rel_type in type_mappings:
            return type_mappings[rel_type]
            
        # Fallback: try to infer from actual IDs
        from_id = sample_rel.get('_from', '')
        to_id = sample_rel.get('_to', '')
        
        from_type = self._get_node_type_from_id(from_id)
        to_type = self._get_node_type_from_id(to_id)
        
        return from_type, to_type
    
    def _infer_node_types_from_relationship_data(self, rel_type: str, sample_rel: Dict) -> Tuple[str, str]:
        """Infer source and target node types from relationship type and sample data."""
        # Use the schema mapper's logic
        return self.schema_mapper._infer_node_types_from_relationship(rel_type, sample_rel)

    def validate_import(self) -> Dict[str, int]:
        """Validate the imported data and return node/relationship counts."""
        counts = {}
        
        with self.driver.session(database=self.database) as session:
            # Count nodes by type
            for node_type in NODE_TYPES:
                result = session.run(f"MATCH (n:{node_type}) RETURN count(n) as count")
                count = result.single()['count']
                counts[f"{node_type}_nodes"] = count
                
            # Count relationships by type  
            for rel_type in RELATIONSHIP_TYPES:
                result = session.run(f"MATCH ()-[r:{rel_type}]-() RETURN count(r) as count")
                count = result.single()['count']
                counts[f"{rel_type}_relationships"] = count
                
        logging.info(f"Validation counts: {counts}")
        return counts


def main(bron_json_path: str, uri: str = DEFAULT_URI, user: str = DEFAULT_USER, 
         password: str = DEFAULT_PASSWORD, database: str = DEFAULT_DATABASE,
         clear_db: bool = False):
    """Main function to import BRON data into Neo4j."""
    
    # Initialize Neo4j connection
    neo4j_db = BronNeo4j(uri, user, password, database)
    
    try:
        neo4j_db.connect()
        
        if clear_db:
            neo4j_db.clear_database()
            
        # Create constraints and indexes
        neo4j_db.create_constraints()
        neo4j_db.create_indexes()
        
        # Import BRON data
        neo4j_db.import_bron_data(bron_json_path)
        
        # Validate import
        counts = neo4j_db.validate_import()
        
        logging.info("Neo4j import completed successfully")
        return counts
        
    finally:
        neo4j_db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Import BRON data into Neo4j")
    parser.add_argument("bron_json", help="Path to BRON JSON file")
    parser.add_argument("--uri", default=DEFAULT_URI, help="Neo4j URI")
    parser.add_argument("--user", default=DEFAULT_USER, help="Neo4j username") 
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="Neo4j password")
    parser.add_argument("--database", default=DEFAULT_DATABASE, help="Neo4j database name")
    parser.add_argument("--clear", action="store_true", help="Clear database before import")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    
    main(args.bron_json, args.uri, args.user, args.password, args.database, args.clear)