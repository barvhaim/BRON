"""
Schema mapping utilities for converting BRON data to Neo4j format.
Maps the BRON data model to the specific Neo4j schema provided by the user.
"""

import logging
from typing import Dict, List, Any, Tuple, Optional


# Neo4j Schema Mapping based on provided schema
NEO4J_SCHEMA = {
    "technique": {
        "type": "node",
        "properties": {
            "_id": "STRING",
            "description": "STRING", 
            "original_id": "STRING",
            "name": "STRING"
        },
        "relationships": {
            "IS_REFINED_BY_SUB_TECHNIQUE": {"direction": "out", "target": "technique"},
            "IS_ADDRESSED_BY_ACTIVITY": {"direction": "out", "target": "engage_activity"},
            "IS_ACHIEVED_BY_TECHNIQUE": {"direction": "in", "target": "tactic"},
            "DEFENDS_AGAINST_TECHNIQUE": {"direction": "out", "target": "d3fend_mitigation"},
            "USED_TECHNIQUE": {"direction": "in", "target": "group"},
            "IMPLEMENTS_TECHNIQUE": {"direction": "in", "target": "software"},
            "IS_REPRESENTED_AS_ATTACK_PATTERN": {"direction": "out", "target": "capec"},
            "TECHNIQUE_IS_MITIGATED_BY": {"direction": "out", "target": "technique_mitigation"},
            "TECHNIQUE_IS_DETECTED_BY": {"direction": "out", "target": "technique_detection"}
        }
    },
    "tactic": {
        "type": "node", 
        "properties": {
            "_id": "STRING",
            "description": "STRING",
            "original_id": "STRING",
            "name": "STRING"
        },
        "relationships": {
            "IS_ACHIEVED_BY_TECHNIQUE": {"direction": "out", "target": "technique"}
        }
    },
    "capec": {
        "type": "node",
        "properties": {
            "likelihood_of_attack": "STRING",
            "consequences": "LIST",
            "_id": "STRING", 
            "description": "STRING",
            "original_id": "STRING",
            "name": "STRING",
            "resources_required": "LIST",
            "typical_severity": "STRING",
            "skills_required": "LIST"
        },
        "relationships": {
            "IS_PARENT_OF_ATTACK_PATTERN": {"direction": "out", "target": "capec"},
            "IS_REPRESENTED_AS_ATTACK_PATTERN": {"direction": "in", "target": "technique"},
            "EXPLOITS_WEAKNESS": {"direction": "out", "target": "cwe"},
            "ATTACK_PATTERN_IS_MITIGATED_BY": {"direction": "out", "target": "capec_mitigation"},
            "ATTACK_PATTERN_IS_DETECTED_BY": {"direction": "out", "target": "capec_detection"}
        }
    },
    "cwe": {
        "type": "node",
        "properties": {
            "common_consequences": "LIST",
            "likelihood_of_exploit": "STRING",
            "_id": "STRING",
            "description": "STRING", 
            "original_id": "STRING",
            "name": "STRING",
            "applicable_platforms": "LIST"
        },
        "relationships": {
            "WEAKNESS_IS_MITIGATED_BY": {"direction": "out", "target": "cwe_mitigation"},
            "WEAKNESS_IS_DETECTED_BY": {"direction": "out", "target": "cwe_detection"},
            "IS_PARENT_OF_WEAKNESS": {"direction": "out", "target": "cwe"},
            "IS_BEING_EXPLOITED_IN_VULNERABILITY": {"direction": "out", "target": "cve"},
            "EXPLOITS_WEAKNESS": {"direction": "in", "target": "capec"}
        }
    },
    "cve": {
        "type": "node",
        "properties": {
            "_id": "STRING",
            "description": "STRING",
            "original_id": "STRING", 
            "severity": "INTEGER"
        },
        "relationships": {
            "IS_COMPROMISING_PLATFORM": {"direction": "out", "target": "cpe"},
            "IS_BEING_EXPLOITED_IN_VULNERABILITY": {"direction": "in", "target": "cwe"}
        }
    },
    "cpe": {
        "type": "node",
        "properties": {
            "product": "STRING",
            "_id": "STRING",
            "original_id": "STRING",
            "vendor": "STRING", 
            "version": "STRING"
        },
        "relationships": {
            "IS_COMPROMISING_PLATFORM": {"direction": "in", "target": "cve"}
        }
    },
    "software": {
        "type": "node",
        "properties": {
            "_id": "STRING",
            "description": "STRING",
            "original_id": "STRING",
            "name": "STRING",
            "software_type": "STRING"
        },
        "relationships": {
            "USED_SOFTWARE": {"direction": "in", "target": "group"},
            "IMPLEMENTS_TECHNIQUE": {"direction": "out", "target": "technique"}
        }
    },
    "group": {
        "type": "node", 
        "properties": {
            "_id": "STRING",
            "description": "STRING",
            "original_id": "STRING",
            "name": "STRING",
            "aliases": "LIST"
        },
        "relationships": {
            "USED_SOFTWARE": {"direction": "out", "target": "software"},
            "USED_TECHNIQUE": {"direction": "out", "target": "technique"}
        }
    },
    "engage_goal": {
        "type": "node",
        "properties": {
            "_id": "STRING",
            "original_id": "STRING",
            "name": "STRING"
        },
        "relationships": {
            "IS_ACHIEVED_BY_APPROACH": {"direction": "out", "target": "engage_approach"}
        }
    },
    "engage_approach": {
        "type": "node",
        "properties": {
            "_id": "STRING",
            "original_id": "STRING", 
            "name": "STRING"
        },
        "relationships": {
            "IS_IMPLEMENTED_BY_ACTIVITY": {"direction": "out", "target": "engage_activity"},
            "IS_ACHIEVED_BY_APPROACH": {"direction": "in", "target": "engage_goal"}
        }
    },
    "engage_activity": {
        "type": "node",
        "properties": {
            "_id": "STRING",
            "original_id": "STRING",
            "name": "STRING"
        },
        "relationships": {
            "IS_IMPLEMENTED_BY_ACTIVITY": {"direction": "in", "target": "engage_approach"},
            "IS_ADDRESSED_BY_ACTIVITY": {"direction": "in", "target": "technique"}
        }
    },
    "d3fend_mitigation": {
        "type": "node",
        "properties": {
            "_id": "STRING",
            "description": "STRING",
            "original_id": "STRING",
            "name": "STRING"
        },
        "relationships": {
            "DEFENDS_AGAINST_TECHNIQUE": {"direction": "in", "target": "technique"}
        }
    },
    "technique_mitigation": {
        "type": "node",
        "properties": {
            "_id": "STRING",
            "description": "STRING",
            "original_id": "STRING", 
            "name": "STRING"
        },
        "relationships": {
            "TECHNIQUE_IS_MITIGATED_BY": {"direction": "in", "target": "technique"}
        }
    },
    "technique_detection": {
        "type": "node",
        "properties": {
            "_id": "STRING",
            "description": "STRING",
            "original_id": "STRING",
            "name": "STRING"
        },
        "relationships": {
            "TECHNIQUE_IS_DETECTED_BY": {"direction": "in", "target": "technique"}
        }
    },
    "capec_mitigation": {
        "type": "node",
        "properties": {
            "_id": "STRING",
            "description": "STRING",
            "name": "STRING",
            "capec_id": "STRING"
        },
        "relationships": {
            "ATTACK_PATTERN_IS_MITIGATED_BY": {"direction": "in", "target": "capec"}
        }
    },
    "capec_detection": {
        "type": "node",
        "properties": {
            "_id": "STRING",
            "description": "STRING", 
            "name": "STRING",
            "capec_id": "STRING"
        },
        "relationships": {
            "ATTACK_PATTERN_IS_DETECTED_BY": {"direction": "in", "target": "capec"}
        }
    },
    "cwe_mitigation": {
        "type": "node",
        "properties": {
            "cwe_id": "STRING",
            "_id": "STRING",
            "description": "STRING",
            "name": "STRING",
            "phase": "STRING"
        },
        "relationships": {
            "WEAKNESS_IS_MITIGATED_BY": {"direction": "in", "target": "cwe"}
        }
    },
    "cwe_detection": {
        "type": "node",
        "properties": {
            "cwe_id": "STRING",
            "_id": "STRING", 
            "description": "STRING",
            "name": "STRING",
            "method": "STRING"
        },
        "relationships": {
            "WEAKNESS_IS_DETECTED_BY": {"direction": "in", "target": "cwe"}
        }
    }
}


class Neo4jSchemaMapper:
    """Maps BRON data to Neo4j schema format."""
    
    def __init__(self):
        self.node_id_counter = 0
        self.relationship_id_counter = 0
        
    def generate_node_id(self) -> str:
        """Generate unique node ID."""
        self.node_id_counter += 1
        return f"node_{self.node_id_counter}"
        
    def generate_relationship_id(self) -> str:
        """Generate unique relationship ID."""
        self.relationship_id_counter += 1
        return f"rel_{self.relationship_id_counter}"
        
    def map_node(self, node_data: Dict, node_type: str) -> Dict:
        """Map a single node to Neo4j schema format."""
        if node_type not in NEO4J_SCHEMA:
            logging.warning(f"Unknown node type: {node_type}")
            return None
            
        schema = NEO4J_SCHEMA[node_type]
        mapped_node = {}
        
        # Set node ID
        if "_id" not in node_data:
            mapped_node["_id"] = self.generate_node_id()
        else:
            mapped_node["_id"] = node_data["_id"]
            
        # Map properties according to schema
        for prop_name, prop_type in schema["properties"].items():
            if prop_name in node_data:
                value = node_data[prop_name]
                mapped_node[prop_name] = self._convert_property_type(value, prop_type)
            elif prop_name == "_id":
                continue  # Already handled
            else:
                # Set default values for missing properties
                mapped_node[prop_name] = self._get_default_value(prop_type)
                
        return mapped_node
        
    def map_relationship(self, rel_data: Dict, rel_type: str, 
                        from_node_id: str, to_node_id: str) -> Dict:
        """Map a single relationship to Neo4j schema format."""
        mapped_rel = {
            "_id": rel_data.get("_id", self.generate_relationship_id()),
            "_from": from_node_id,
            "_to": to_node_id
        }
        
        # Copy additional relationship properties
        for key, value in rel_data.items():
            if key not in ["_id", "_from", "_to", "source", "target"]:
                mapped_rel[key] = value
                
        return mapped_rel
        
    def _convert_property_type(self, value: Any, target_type: str) -> Any:
        """Convert property to target type."""
        if value is None:
            return self._get_default_value(target_type)
            
        if target_type == "STRING":
            # Handle complex objects by converting to JSON string
            if isinstance(value, (dict, list)):
                import json
                return json.dumps(value)
            return str(value)
        elif target_type == "INTEGER":
            try:
                return int(float(value))
            except (ValueError, TypeError):
                return 0
        elif target_type == "LIST":
            if isinstance(value, list):
                # Ensure all list items are primitive types
                return [self._flatten_value(item) for item in value]
            elif isinstance(value, str):
                # Try to parse comma-separated string
                return [item.strip() for item in value.split(",") if item.strip()]
            else:
                return [str(value)]
        else:
            return self._flatten_value(value)
            
    def _flatten_value(self, value: Any) -> Any:
        """Flatten complex values to Neo4j-compatible types."""
        if isinstance(value, dict):
            # Convert dict to JSON string
            import json
            return json.dumps(value)
        elif isinstance(value, list):
            # Convert list of complex objects to list of strings
            return [self._flatten_value(item) for item in value]
        else:
            return str(value) if value is not None else ""
            
    def _get_default_value(self, prop_type: str) -> Any:
        """Get default value for property type."""
        defaults = {
            "STRING": "",
            "INTEGER": 0,
            "LIST": []
        }
        return defaults.get(prop_type, "")
        
    def map_bron_data(self, bron_data: Dict) -> Tuple[Dict[str, List[Dict]], Dict[str, List[Dict]]]:
        """Map complete BRON data structure to Neo4j format.
        
        Returns:
            Tuple of (nodes_by_type, relationships_by_type)
        """
        nodes_by_type = {}
        relationships_by_type = {}
        
        # Process NetworkX-style data
        if 'nodes' in bron_data and 'links' in bron_data:
            nodes_by_type, relationships_by_type = self._map_networkx_data(bron_data)
        elif 'nodes' in bron_data and 'edges' in bron_data:
            # Process BRON-specific format with edges instead of links
            nodes_by_type, relationships_by_type = self._map_bron_format(bron_data)
        else:
            # Process direct node/relationship format
            nodes_by_type, relationships_by_type = self._map_direct_data(bron_data)
            
        return nodes_by_type, relationships_by_type
        
    def _map_bron_format(self, bron_data: Dict) -> Tuple[Dict[str, List[Dict]], Dict[str, List[Dict]]]:
        """Map BRON-specific format with nodes as tuples and edges."""
        nodes_by_type = {}
        relationships_by_type = {}
        
        # Map nodes - format is [node_id, node_data]
        node_id_map = {}
        for node_entry in bron_data['nodes']:
            if isinstance(node_entry, list) and len(node_entry) == 2:
                node_id, node_data = node_entry
                
                # Flatten node data
                flattened_node = {
                    'original_id': node_data.get('original_id', node_id),
                    '_id': node_id
                }
                
                # Add basic properties
                if 'name' in node_data:
                    flattened_node['name'] = node_data['name']
                if 'datatype' in node_data:
                    flattened_node['datatype'] = node_data['datatype']
                    
                # Add metadata properties
                if 'metadata' in node_data:
                    metadata = node_data['metadata']
                    if isinstance(metadata, dict):
                        for key, value in metadata.items():
                            if key not in flattened_node:  # Don't overwrite existing properties
                                flattened_node[key] = value
                
                # Determine node type
                node_type = node_data.get('datatype', self._determine_node_type(flattened_node))
                
                if node_type in NEO4J_SCHEMA:
                    mapped_node = self.map_node(flattened_node, node_type)
                    if mapped_node:
                        if node_type not in nodes_by_type:
                            nodes_by_type[node_type] = []
                        nodes_by_type[node_type].append(mapped_node)
                        
                        # Track node ID mapping for relationships
                        node_id_map[node_id] = mapped_node['_id']
                        
        # Map edges - format is [source_id, target_id, edge_data] 
        for edge_entry in bron_data['edges']:
            if isinstance(edge_entry, list) and len(edge_entry) >= 2:
                source_id = edge_entry[0]
                target_id = edge_entry[1]
                edge_data = edge_entry[2] if len(edge_entry) > 2 else {}
                
                # Determine relationship type
                rel_type = self._determine_relationship_type_from_nodes(source_id, target_id)
                
                # Create relationship
                mapped_rel = self.map_relationship(
                    edge_data, rel_type,
                    node_id_map.get(source_id, source_id),
                    node_id_map.get(target_id, target_id)
                )
                
                if rel_type not in relationships_by_type:
                    relationships_by_type[rel_type] = []
                relationships_by_type[rel_type].append(mapped_rel)
                
        return nodes_by_type, relationships_by_type
        
    def _determine_relationship_type_from_nodes(self, source_id: str, target_id: str) -> str:
        """Determine relationship type from source and target node IDs."""
        source_type = self._get_node_type_from_id(source_id)
        target_type = self._get_node_type_from_id(target_id)
        
        # Map common relationship patterns
        type_to_relationship = {
            ('tactic', 'technique'): 'IS_ACHIEVED_BY_TECHNIQUE',
            ('technique', 'capec'): 'IS_REPRESENTED_AS_ATTACK_PATTERN',
            ('capec', 'cwe'): 'EXPLOITS_WEAKNESS',
            ('cwe', 'cve'): 'IS_BEING_EXPLOITED_IN_VULNERABILITY',
            ('cve', 'cpe'): 'IS_COMPROMISING_PLATFORM',
            ('group', 'technique'): 'USED_TECHNIQUE',
            ('software', 'technique'): 'IMPLEMENTS_TECHNIQUE',
            ('group', 'software'): 'USED_SOFTWARE',
            ('technique', 'technique'): 'IS_REFINED_BY_SUB_TECHNIQUE',
            ('capec', 'capec'): 'IS_PARENT_OF_ATTACK_PATTERN',
            ('cwe', 'cwe'): 'IS_PARENT_OF_WEAKNESS',
        }
        
        return type_to_relationship.get((source_type, target_type), 'RELATED_TO')
        
    def _map_networkx_data(self, bron_data: Dict) -> Tuple[Dict[str, List[Dict]], Dict[str, List[Dict]]]:
        """Map NetworkX-style BRON data."""
        nodes_by_type = {}
        relationships_by_type = {}
        
        # Map nodes
        for node in bron_data['nodes']:
            node_type = self._determine_node_type(node)
            if node_type in NEO4J_SCHEMA:
                mapped_node = self.map_node(node, node_type)
                if mapped_node:
                    if node_type not in nodes_by_type:
                        nodes_by_type[node_type] = []
                    nodes_by_type[node_type].append(mapped_node)
                    
        # Create node ID mapping for relationships
        node_id_map = {}
        for node_type, nodes in nodes_by_type.items():
            for node in nodes:
                original_id = node.get("original_id", node.get("_id"))
                if original_id:
                    node_id_map[original_id] = node["_id"]
                    
        # Map relationships
        for link in bron_data['links']:
            rel_type = self._determine_relationship_type(link)
            source_id = link.get('source')
            target_id = link.get('target')
            
            if source_id in node_id_map and target_id in node_id_map:
                mapped_rel = self.map_relationship(
                    link, rel_type, 
                    node_id_map[source_id], 
                    node_id_map[target_id]
                )
                
                if rel_type not in relationships_by_type:
                    relationships_by_type[rel_type] = []
                relationships_by_type[rel_type].append(mapped_rel)
                
        return nodes_by_type, relationships_by_type
        
    def _map_direct_data(self, bron_data: Dict) -> Tuple[Dict[str, List[Dict]], Dict[str, List[Dict]]]:
        """Map direct node/relationship format BRON data."""
        nodes_by_type = {}
        relationships_by_type = {}
        
        # Map nodes
        for node_type in NEO4J_SCHEMA:
            if node_type in bron_data:
                mapped_nodes = []
                for node in bron_data[node_type]:
                    mapped_node = self.map_node(node, node_type)
                    if mapped_node:
                        mapped_nodes.append(mapped_node)
                if mapped_nodes:
                    nodes_by_type[node_type] = mapped_nodes
                    
        # Map relationships (would need relationship data in input)
        # This depends on how relationships are structured in the input data
        
        return nodes_by_type, relationships_by_type
        
    def _determine_node_type(self, node: Dict) -> str:
        """Determine node type from node data."""
        if 'type' in node:
            return node['type']
            
        original_id = node.get('original_id', '')
        if not original_id:
            original_id = node.get('id', '')
            
        # Pattern matching for node types
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
            
        # Check for engagement types
        if 'engage' in node.get('name', '').lower():
            if 'goal' in node.get('name', '').lower():
                return 'engage_goal'
            elif 'approach' in node.get('name', '').lower():
                return 'engage_approach'
            elif 'activity' in node.get('name', '').lower():
                return 'engage_activity'
                
        # Check for mitigation types
        if 'mitigation' in node.get('name', '').lower():
            if 'technique' in node.get('name', '').lower():
                return 'technique_mitigation'
            elif 'capec' in node.get('name', '').lower():
                return 'capec_mitigation'
            elif 'cwe' in node.get('name', '').lower():
                return 'cwe_mitigation'
            elif 'd3fend' in node.get('name', '').lower():
                return 'd3fend_mitigation'
                
        # Check for detection types  
        if 'detection' in node.get('name', '').lower():
            if 'technique' in node.get('name', '').lower():
                return 'technique_detection'
            elif 'capec' in node.get('name', '').lower():
                return 'capec_detection'
            elif 'cwe' in node.get('name', '').lower():
                return 'cwe_detection'
                
        return 'unknown'
        
    def _determine_relationship_type(self, link: Dict) -> str:
        """Determine relationship type from link data."""
        if 'relationship_type' in link:
            return link['relationship_type']
        if 'type' in link:
            return link['type']
            
        # Try to infer from source/target node types
        source = link.get('source', '')
        target = link.get('target', '')
        
        source_type = self._get_node_type_from_id(source)
        target_type = self._get_node_type_from_id(target)
        
        # Map common relationship patterns
        type_to_relationship = {
            ('tactic', 'technique'): 'IS_ACHIEVED_BY_TECHNIQUE',
            ('technique', 'capec'): 'IS_REPRESENTED_AS_ATTACK_PATTERN',
            ('capec', 'cwe'): 'EXPLOITS_WEAKNESS',
            ('cwe', 'cve'): 'IS_BEING_EXPLOITED_IN_VULNERABILITY',
            ('cve', 'cpe'): 'IS_COMPROMISING_PLATFORM',
            ('group', 'technique'): 'USED_TECHNIQUE',
            ('software', 'technique'): 'IMPLEMENTS_TECHNIQUE',
            ('group', 'software'): 'USED_SOFTWARE',
            ('technique', 'technique_mitigation'): 'TECHNIQUE_IS_MITIGATED_BY',
            ('technique', 'technique_detection'): 'TECHNIQUE_IS_DETECTED_BY',
            ('capec', 'capec_mitigation'): 'ATTACK_PATTERN_IS_MITIGATED_BY',
            ('capec', 'capec_detection'): 'ATTACK_PATTERN_IS_DETECTED_BY',
            ('cwe', 'cwe_mitigation'): 'WEAKNESS_IS_MITIGATED_BY',
            ('cwe', 'cwe_detection'): 'WEAKNESS_IS_DETECTED_BY',
            ('d3fend_mitigation', 'technique'): 'DEFENDS_AGAINST_TECHNIQUE',
            ('engage_goal', 'engage_approach'): 'IS_ACHIEVED_BY_APPROACH',
            ('engage_approach', 'engage_activity'): 'IS_IMPLEMENTED_BY_ACTIVITY',
            ('technique', 'engage_activity'): 'IS_ADDRESSED_BY_ACTIVITY'
        }
        
        return type_to_relationship.get((source_type, target_type), 'RELATED_TO')
        
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
            'USED_SOFTWARE': ('group', 'software'),
            'IS_REFINED_BY_SUB_TECHNIQUE': ('technique', 'technique'),
            'IS_PARENT_OF_WEAKNESS': ('cwe', 'cwe'),
            'IS_PARENT_OF_ATTACK_PATTERN': ('capec', 'capec'),
            'WEAKNESS_IS_MITIGATED_BY': ('cwe', 'cwe_mitigation'),
            'WEAKNESS_IS_DETECTED_BY': ('cwe', 'cwe_detection'),
            'TECHNIQUE_IS_DETECTED_BY': ('technique', 'technique_detection'),
            'ATTACK_PATTERN_IS_MITIGATED_BY': ('capec', 'capec_mitigation'),
            'ATTACK_PATTERN_IS_DETECTED_BY': ('capec', 'capec_detection'),
            'IS_ACHIEVED_BY_APPROACH': ('engage_goal', 'engage_approach'),
            'IS_IMPLEMENTED_BY_ACTIVITY': ('engage_approach', 'engage_activity'),
            'IS_ADDRESSED_BY_ACTIVITY': ('technique', 'engage_activity'),
        }
        
        if rel_type in type_mappings:
            return type_mappings[rel_type]
            
        # Fallback: try to infer from actual IDs
        from_id = sample_rel.get('_from', '') or sample_rel.get('source', '')
        to_id = sample_rel.get('_to', '') or sample_rel.get('target', '')
        
        from_type = self._get_node_type_from_id(from_id)
        to_type = self._get_node_type_from_id(to_id)
        
        return from_type, to_type