"""
Neo4j query module for BRON graph database.
Provides parallel functionality to query_graph_db.py for Neo4j.
"""

import json
import os
import collections
import sys
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Set, Tuple
import argparse
import logging

import pandas as pd
from neo4j import GraphDatabase

from utils.bron_utils import get_csv_data
from offense.build_offensive_BRON import ID_DICT_PATHS


# Neo4j Configuration  
DEFAULT_URI = "bolt://localhost:7687"
DEFAULT_USER = "neo4j" 
DEFAULT_PASSWORD = "password123"
DEFAULT_DATABASE = "neo4j"


@dataclass(eq=True, frozen=True)
class Document:
    """Document representation for query results."""
    datatype: str
    original_id: str
    name: str


class Neo4jQueryEngine:
    """Neo4j query engine for BRON data."""
    
    def __init__(self, uri: str = DEFAULT_URI, user: str = DEFAULT_USER,
                 password: str = DEFAULT_PASSWORD, database: str = DEFAULT_DATABASE):
        """Initialize Neo4j query engine."""
        self.uri = uri
        self.user = user
        self.password = password  
        self.database = database
        self.driver = None
        
    def connect(self):
        """Connect to Neo4j database."""
        self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        logging.info(f"Connected to Neo4j at {self.uri}")
        
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()
            logging.info("Closed Neo4j connection")
            
    def get_technique_id_from_id(self, technique_id: str) -> Optional[str]:
        """Get technique internal ID from original ID."""
        query = """
        MATCH (t:technique {original_id: $technique_id})
        RETURN t._id as id
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query, technique_id=technique_id)
            record = result.single()
            return record['id'] if record else None
            
    def get_connections(self, starting_points: List[str], collection_name: str) -> Dict[str, Set[Document]]:
        """Get connections from starting points in a collection."""
        connections = collections.defaultdict(set)
        
        # Build query to find connections from starting points
        query = f"""
        MATCH (start:{collection_name})
        WHERE start.original_id IN $starting_points
        MATCH (start)-[r]-(connected)
        RETURN start.original_id as starting_point,
               labels(connected) as node_labels,
               connected.original_id as original_id,
               connected.name as name
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query, starting_points=starting_points)
            
            for record in result:
                starting_point = record['starting_point']
                node_labels = record['node_labels']
                original_id = record['original_id'] 
                name = record['name']
                
                # Use first label as datatype
                datatype = node_labels[0] if node_labels else 'unknown'
                
                doc = Document(datatype, original_id or '', name or '')
                connections[starting_point].add(doc)
                
        return connections
        
    def get_connection_counts(self, starting_points: List[str], collection_name: str) -> Dict[str, Dict[str, int]]:
        """Get connection counts by data type from starting points."""
        connections = self.get_connections(starting_points, collection_name)
        connection_counts = {}
        
        for key, values in connections.items():
            connection_counts[key] = collections.defaultdict(int)
            for element in values:
                connection_counts[key][element.datatype] += 1
                
        return connection_counts
        
    def get_graph_traversal(self, starting_points: List[str], collection_name: str,
                           max_depth: int = 3) -> Dict[str, Dict[str, Any]]:
        """Perform graph traversal from starting points."""
        data = {}
        
        for starting_point in starting_points:
            # Find starting node
            start_query = f"""
            MATCH (start:{collection_name})
            WHERE start.original_id = $starting_point OR start.name = $starting_point
            RETURN start._id as start_id, start.original_id as original_id
            """
            
            with self.driver.session(database=self.database) as session:
                result = session.run(start_query, starting_point=starting_point)
                start_record = result.single()
                
                if not start_record:
                    logging.warning(f"Starting point not found: {starting_point}")
                    continue
                    
                start_id = start_record['start_id']
                logging.info(f"{collection_name} {starting_point} {start_id}")
                
                # Perform traversal
                traversal_query = """
                MATCH (start {_id: $start_id})
                CALL apoc.path.subgraphNodes(start, {
                    maxLevel: $max_depth,
                    relationshipFilter: '>',
                    labelFilter: ''
                })
                YIELD node
                RETURN labels(node) as node_labels,
                       node.original_id as original_id,
                       node.name as name,
                       node._id as node_id
                """
                
                try:
                    # Try with APOC first
                    result = session.run(traversal_query, start_id=start_id, max_depth=max_depth)
                    nodes = []
                    for record in result:
                        nodes.append({
                            'labels': record['node_labels'],
                            'original_id': record['original_id'],
                            'name': record['name'],
                            'node_id': record['node_id']
                        })
                    data[starting_point] = self._process_traversal_results(nodes)
                    
                except Exception as e:
                    # Fallback to basic traversal without APOC
                    logging.warning(f"APOC not available, using basic traversal: {e}")
                    fallback_query = f"""
                    MATCH path = (start {{_id: $start_id}})-[*1..{max_depth}]-(node)
                    RETURN labels(node) as node_labels,
                           node.original_id as original_id,
                           node.name as name,
                           node._id as node_id
                    """
                    
                    result = session.run(fallback_query, start_id=start_id)
                    nodes = []
                    for record in result:
                        nodes.append({
                            'labels': record['node_labels'], 
                            'original_id': record['original_id'],
                            'name': record['name'],
                            'node_id': record['node_id']
                        })
                    data[starting_point] = self._process_traversal_results(nodes)
                    
        return data
        
    def _process_traversal_results(self, nodes: List[Dict]) -> Dict[str, Any]:
        """Process traversal results into summary format."""
        node_counts = collections.defaultdict(int)
        unique_nodes = set()
        
        for node in nodes:
            labels = node['labels']
            node_type = labels[0] if labels else 'unknown'
            node_counts[node_type] += 1
            unique_nodes.add(node['node_id'])
            
        return {
            'node_counts': dict(node_counts),
            'total_nodes': len(unique_nodes),
            'node_details': nodes
        }
        
    def find_shortest_paths(self, source_type: str, source_id: str, 
                           target_type: str, target_id: str) -> List[Dict]:
        """Find shortest paths between two nodes."""
        query = f"""
        MATCH (source:{source_type} {{original_id: $source_id}})
        MATCH (target:{target_type} {{original_id: $target_id}})
        MATCH path = shortestPath((source)-[*]-(target))
        RETURN path,
               length(path) as path_length,
               [n in nodes(path) | {{
                   labels: labels(n),
                   original_id: n.original_id,
                   name: n.name
               }}] as path_nodes,
               [r in relationships(path) | type(r)] as relationship_types
        """
        
        paths = []
        with self.driver.session(database=self.database) as session:
            result = session.run(query, source_id=source_id, target_id=target_id)
            
            for record in result:
                paths.append({
                    'length': record['path_length'],
                    'nodes': record['path_nodes'],
                    'relationships': record['relationship_types']
                })
                
        return paths
        
    def get_node_details(self, node_type: str, node_id: str) -> Optional[Dict]:
        """Get detailed information about a specific node."""
        query = f"""
        MATCH (n:{node_type})
        WHERE n.original_id = $node_id OR n._id = $node_id
        RETURN n as node_properties
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query, node_id=node_id)
            record = result.single()
            
            if record:
                return dict(record['node_properties'])
            return None
            
    def get_relationship_details(self, source_id: str, target_id: str) -> List[Dict]:
        """Get relationship details between two nodes."""
        query = """
        MATCH (source {original_id: $source_id})-[r]-(target {original_id: $target_id})
        RETURN type(r) as relationship_type,
               properties(r) as relationship_properties,
               labels(source) as source_labels,
               labels(target) as target_labels
        """
        
        relationships = []
        with self.driver.session(database=self.database) as session:
            result = session.run(query, source_id=source_id, target_id=target_id)
            
            for record in result:
                relationships.append({
                    'type': record['relationship_type'],
                    'properties': record['relationship_properties'],
                    'source_labels': record['source_labels'],
                    'target_labels': record['target_labels']
                })
                
        return relationships


def parse_args(args: List[str]) -> Dict[str, Any]:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Analyse Neo4j network for risk")
    parser.add_argument(
        "--starting_point",
        type=str, 
        required=True,
        help="Path to CSV file with starting point data"
    )
    parser.add_argument(
        "--starting_point_type", 
        type=str,
        required=True,
        help=f"Data source type: {', '.join(ID_DICT_PATHS.keys())}"
    )
    parser.add_argument("--neo4j_uri", type=str, default=DEFAULT_URI, help="Neo4j URI")
    parser.add_argument("--neo4j_user", type=str, default=DEFAULT_USER, help="Neo4j user")
    parser.add_argument("--neo4j_password", type=str, default=DEFAULT_PASSWORD, help="Neo4j password") 
    parser.add_argument("--neo4j_database", type=str, default=DEFAULT_DATABASE, help="Neo4j database")
    parser.add_argument("--max_depth", type=int, default=3, help="Maximum traversal depth")
    
    parsed_args = vars(parser.parse_args(args))
    assert parsed_args["starting_point_type"] in ID_DICT_PATHS.keys()
    return parsed_args


def main(args: List[str] = None):
    """Main function for Neo4j querying."""
    if args is None:
        args = sys.argv[1:]
        
    parsed_args = parse_args(args)
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize query engine
    engine = Neo4jQueryEngine(
        uri=parsed_args["neo4j_uri"],
        user=parsed_args["neo4j_user"],
        password=parsed_args["neo4j_password"],
        database=parsed_args["neo4j_database"]
    )
    
    try:
        engine.connect()
        
        # Load starting points
        starting_points_data = get_csv_data(parsed_args["starting_point"])
        starting_points = [item[0] for item in starting_points_data]
        collection_name = parsed_args["starting_point_type"]
        
        logging.info(f"Analyzing {len(starting_points)} starting points of type {collection_name}")
        
        # Get connection counts
        connection_counts = engine.get_connection_counts(starting_points, collection_name)
        
        print("Connection counts:")
        print(json.dumps(connection_counts, indent=2))
        
        # Optionally perform graph traversal
        if len(starting_points) <= 10:  # Limit traversal for performance
            traversal_results = engine.get_graph_traversal(
                starting_points, collection_name, parsed_args["max_depth"]
            )
            print("\nTraversal results:")
            print(json.dumps(traversal_results, indent=2))
            
    finally:
        engine.close()


if __name__ == "__main__":
    main()