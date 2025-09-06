"""
Test cases for Neo4j graph database integration.
"""

import unittest
import json
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock

from graph_db.bron_neo4j import BronNeo4j
from graph_db.query_neo4j import Neo4jQueryEngine, Document
from graph_db.neo4j_schema_mapper import Neo4jSchemaMapper


class TestBronNeo4j(unittest.TestCase):
    """Test cases for BronNeo4j class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_uri = "bolt://localhost:7687"
        self.test_user = "neo4j"
        self.test_password = "password123" 
        self.test_database = "test"
        
        # Mock Neo4j driver
        self.mock_driver = Mock()
        self.mock_session = Mock()
        self.mock_driver.session.return_value.__enter__.return_value = self.mock_session
        
    @patch('graph_db.bron_neo4j.GraphDatabase.driver')
    def test_connect(self, mock_driver):
        """Test Neo4j connection."""
        mock_driver.return_value = self.mock_driver
        
        bron_neo4j = BronNeo4j(self.test_uri, self.test_user, self.test_password, self.test_database)
        bron_neo4j.connect()
        
        mock_driver.assert_called_once_with(self.test_uri, auth=(self.test_user, self.test_password))
        self.assertEqual(bron_neo4j.driver, self.mock_driver)
        
    def test_close(self):
        """Test closing Neo4j connection."""
        bron_neo4j = BronNeo4j()
        bron_neo4j.driver = self.mock_driver
        
        bron_neo4j.close()
        
        self.mock_driver.close.assert_called_once()
        
    @patch('graph_db.bron_neo4j.GraphDatabase.driver')
    def test_clear_database(self, mock_driver):
        """Test clearing database."""
        mock_driver.return_value = self.mock_driver
        
        bron_neo4j = BronNeo4j()
        bron_neo4j.driver = self.mock_driver
        
        bron_neo4j.clear_database()
        
        # Verify delete queries were called
        expected_calls = 2  # One for relationships, one for nodes
        self.assertEqual(self.mock_session.run.call_count, expected_calls)
        
    @patch('graph_db.bron_neo4j.GraphDatabase.driver')
    def test_create_constraints(self, mock_driver):
        """Test creating constraints."""
        mock_driver.return_value = self.mock_driver
        
        bron_neo4j = BronNeo4j()
        bron_neo4j.driver = self.mock_driver
        
        bron_neo4j.create_constraints()
        
        # Verify constraint creation queries were called
        self.assertTrue(self.mock_session.run.call_count > 0)
        
    @patch('graph_db.bron_neo4j.GraphDatabase.driver') 
    def test_batch_create_nodes(self, mock_driver):
        """Test batch node creation."""
        mock_driver.return_value = self.mock_driver
        
        bron_neo4j = BronNeo4j()
        bron_neo4j.driver = self.mock_driver
        
        test_nodes = [
            {"_id": "test1", "name": "Test Node 1", "original_id": "T1001"},
            {"_id": "test2", "name": "Test Node 2", "original_id": "T1002"}
        ]
        
        bron_neo4j.batch_create_nodes("technique", test_nodes)
        
        # Verify node creation query was called
        self.mock_session.run.assert_called()
        call_args = self.mock_session.run.call_args
        query = call_args[0][0]
        self.assertIn("CREATE", query)
        self.assertIn("technique", query)
        
    def test_determine_node_type(self):
        """Test node type determination."""
        bron_neo4j = BronNeo4j()
        
        # Test technique ID
        technique_node = {"original_id": "T1001", "name": "Test Technique"}
        self.assertEqual(bron_neo4j._determine_node_type(technique_node), "technique")
        
        # Test tactic ID
        tactic_node = {"original_id": "TA0001", "name": "Test Tactic"}
        self.assertEqual(bron_neo4j._determine_node_type(tactic_node), "tactic")
        
        # Test CVE ID
        cve_node = {"original_id": "CVE-2021-1234", "name": "Test CVE"}
        self.assertEqual(bron_neo4j._determine_node_type(cve_node), "cve")
        
    def test_import_bron_data_file_not_found(self):
        """Test import with non-existent file."""
        bron_neo4j = BronNeo4j()
        
        with self.assertRaises(FileNotFoundError):
            bron_neo4j.import_bron_data("/nonexistent/path/file.json")
            
    @patch('graph_db.bron_neo4j.GraphDatabase.driver')
    @patch('builtins.open')
    @patch('os.path.exists')
    def test_import_bron_data_success(self, mock_exists, mock_open, mock_driver):
        """Test successful BRON data import."""
        mock_exists.return_value = True
        mock_driver.return_value = self.mock_driver
        
        # Mock BRON data
        test_bron_data = {
            "nodes": [
                {"original_id": "T1001", "name": "Test Technique", "description": "Test"}
            ],
            "links": [
                {"source": "T1001", "target": "TA0001"}
            ]
        }
        
        mock_file = Mock()
        mock_file.read.return_value = json.dumps(test_bron_data)
        mock_open.return_value.__enter__.return_value = mock_file
        
        bron_neo4j = BronNeo4j()
        bron_neo4j.driver = self.mock_driver
        
        # Mock schema mapper
        bron_neo4j.schema_mapper = Mock()
        bron_neo4j.schema_mapper.map_bron_data.return_value = (
            {"technique": [{"_id": "test1", "name": "Test"}]},
            {"IS_ACHIEVED_BY_TECHNIQUE": [{"_from": "test1", "_to": "test2"}]}
        )
        
        bron_neo4j.import_bron_data("test_file.json")
        
        # Verify schema mapper was called
        bron_neo4j.schema_mapper.map_bron_data.assert_called_once()


class TestNeo4jQueryEngine(unittest.TestCase):
    """Test cases for Neo4jQueryEngine class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_uri = "bolt://localhost:7687"
        self.test_user = "neo4j"
        self.test_password = "password123"
        self.test_database = "test"
        
        # Mock Neo4j driver
        self.mock_driver = Mock()
        self.mock_session = Mock()
        self.mock_driver.session.return_value.__enter__.return_value = self.mock_session
        
    @patch('graph_db.query_neo4j.GraphDatabase.driver')
    def test_connect(self, mock_driver):
        """Test query engine connection."""
        mock_driver.return_value = self.mock_driver
        
        engine = Neo4jQueryEngine(self.test_uri, self.test_user, self.test_password, self.test_database)
        engine.connect()
        
        mock_driver.assert_called_once_with(self.test_uri, auth=(self.test_user, self.test_password))
        self.assertEqual(engine.driver, self.mock_driver)
        
    def test_get_technique_id_from_id(self):
        """Test getting technique ID."""
        engine = Neo4jQueryEngine()
        engine.driver = self.mock_driver
        
        # Mock query result
        mock_result = Mock()
        mock_record = Mock()
        mock_record.__getitem__.return_value = "internal_id_123"
        mock_result.single.return_value = mock_record
        self.mock_session.run.return_value = mock_result
        
        result = engine.get_technique_id_from_id("T1001")
        
        self.assertEqual(result, "internal_id_123")
        self.mock_session.run.assert_called_once()
        
    def test_get_connections(self):
        """Test getting connections from starting points."""
        engine = Neo4jQueryEngine()
        engine.driver = self.mock_driver
        
        # Mock query results
        mock_result = Mock()
        mock_records = [
            {
                'starting_point': 'T1001',
                'node_labels': ['technique'],
                'original_id': 'T1002',
                'name': 'Test Technique 2'
            },
            {
                'starting_point': 'T1001', 
                'node_labels': ['capec'],
                'original_id': 'CAPEC-123',
                'name': 'Test CAPEC'
            }
        ]
        mock_result.__iter__.return_value = iter([Mock(**record) for record in mock_records])
        self.mock_session.run.return_value = mock_result
        
        connections = engine.get_connections(['T1001'], 'technique')
        
        self.assertIn('T1001', connections)
        self.assertEqual(len(connections['T1001']), 2)
        
        # Check document types
        docs = list(connections['T1001'])
        datatypes = {doc.datatype for doc in docs}
        self.assertIn('technique', datatypes)
        self.assertIn('capec', datatypes)
        
    def test_get_connection_counts(self):
        """Test getting connection counts."""
        engine = Neo4jQueryEngine()
        engine.driver = self.mock_driver
        
        # Mock the get_connections method
        engine.get_connections = Mock()
        engine.get_connections.return_value = {
            'T1001': {
                Document('technique', 'T1002', 'Test 2'),
                Document('capec', 'CAPEC-123', 'Test CAPEC'),
                Document('technique', 'T1003', 'Test 3')
            }
        }
        
        counts = engine.get_connection_counts(['T1001'], 'technique')
        
        expected = {
            'T1001': {'technique': 2, 'capec': 1}
        }
        
        self.assertEqual(counts, expected)


class TestNeo4jSchemaMapper(unittest.TestCase):
    """Test cases for Neo4jSchemaMapper class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mapper = Neo4jSchemaMapper()
        
    def test_generate_node_id(self):
        """Test node ID generation."""
        id1 = self.mapper.generate_node_id()
        id2 = self.mapper.generate_node_id()
        
        self.assertNotEqual(id1, id2)
        self.assertTrue(id1.startswith('node_'))
        
    def test_generate_relationship_id(self):
        """Test relationship ID generation."""
        id1 = self.mapper.generate_relationship_id()
        id2 = self.mapper.generate_relationship_id()
        
        self.assertNotEqual(id1, id2)
        self.assertTrue(id1.startswith('rel_'))
        
    def test_map_node_technique(self):
        """Test mapping technique node."""
        node_data = {
            "original_id": "T1001",
            "name": "Test Technique", 
            "description": "Test description"
        }
        
        mapped_node = self.mapper.map_node(node_data, 'technique')
        
        self.assertIn('_id', mapped_node)
        self.assertEqual(mapped_node['original_id'], 'T1001')
        self.assertEqual(mapped_node['name'], 'Test Technique')
        self.assertEqual(mapped_node['description'], 'Test description')
        
    def test_map_relationship(self):
        """Test mapping relationship."""
        rel_data = {
            "description": "Test relationship"
        }
        
        mapped_rel = self.mapper.map_relationship(
            rel_data, 'EXPLOITS_WEAKNESS', 'capec_123', 'cwe_456'
        )
        
        self.assertIn('_id', mapped_rel)
        self.assertEqual(mapped_rel['_from'], 'capec_123')
        self.assertEqual(mapped_rel['_to'], 'cwe_456')
        self.assertEqual(mapped_rel['description'], 'Test relationship')
        
    def test_convert_property_type_string(self):
        """Test string property conversion."""
        result = self.mapper._convert_property_type(123, 'STRING')
        self.assertEqual(result, '123')
        
    def test_convert_property_type_integer(self):
        """Test integer property conversion."""
        result = self.mapper._convert_property_type('123', 'INTEGER')
        self.assertEqual(result, 123)
        
        result = self.mapper._convert_property_type('invalid', 'INTEGER') 
        self.assertEqual(result, 0)
        
    def test_convert_property_type_list(self):
        """Test list property conversion."""
        # From list
        result = self.mapper._convert_property_type(['a', 'b', 'c'], 'LIST')
        self.assertEqual(result, ['a', 'b', 'c'])
        
        # From comma-separated string
        result = self.mapper._convert_property_type('a, b, c', 'LIST')
        self.assertEqual(result, ['a', 'b', 'c'])
        
        # From single value
        result = self.mapper._convert_property_type('single', 'LIST')
        self.assertEqual(result, ['single'])
        
    def test_determine_node_type(self):
        """Test node type determination."""
        # Test technique
        node = {"original_id": "T1001"}
        self.assertEqual(self.mapper._determine_node_type(node), 'technique')
        
        # Test tactic
        node = {"original_id": "TA0001"}
        self.assertEqual(self.mapper._determine_node_type(node), 'tactic')
        
        # Test CAPEC
        node = {"original_id": "CAPEC-123"}
        self.assertEqual(self.mapper._determine_node_type(node), 'capec')
        
        # Test CWE
        node = {"original_id": "CWE-79"}
        self.assertEqual(self.mapper._determine_node_type(node), 'cwe')
        
        # Test CVE
        node = {"original_id": "CVE-2021-1234"}
        self.assertEqual(self.mapper._determine_node_type(node), 'cve')
        
    def test_determine_relationship_type(self):
        """Test relationship type determination."""
        # Test with explicit type
        link = {"relationship_type": "EXPLOITS_WEAKNESS"}
        result = self.mapper._determine_relationship_type(link)
        self.assertEqual(result, "EXPLOITS_WEAKNESS")
        
        # Test inferred from node types
        link = {"source": "CAPEC-123", "target": "CWE-79"}
        result = self.mapper._determine_relationship_type(link)
        self.assertEqual(result, "EXPLOITS_WEAKNESS")


class TestIntegration(unittest.TestCase):
    """Integration tests for Neo4j BRON implementation."""
    
    def test_end_to_end_mock(self):
        """Test end-to-end workflow with mocked components."""
        # Create test BRON data
        test_data = {
            "nodes": [
                {"original_id": "T1001", "name": "Test Technique"},
                {"original_id": "CAPEC-123", "name": "Test CAPEC"}
            ],
            "links": [
                {"source": "T1001", "target": "CAPEC-123"}
            ]
        }
        
        # Test schema mapping
        mapper = Neo4jSchemaMapper()
        nodes_by_type, rels_by_type = mapper.map_bron_data(test_data)
        
        # Verify nodes were mapped
        self.assertIn('technique', nodes_by_type)
        self.assertIn('capec', nodes_by_type) 
        
        # Verify relationships were mapped
        self.assertTrue(len(rels_by_type) > 0)
        
        # Test that mapped data has required fields
        technique_node = nodes_by_type['technique'][0]
        self.assertIn('_id', technique_node)
        self.assertIn('original_id', technique_node)
        self.assertIn('name', technique_node)


if __name__ == '__main__':
    unittest.main()