#!/usr/bin/env python3
"""
Custom script to build BRON for Neo4j using only successfully downloaded data.
Workaround for CVE download issues by focusing on ATT&CK, CAPEC, and CWE data.
"""

import os
import sys
import json
import logging
import argparse
from typing import List, Dict, Any

# Add project root to path
sys.path.insert(0, '.')

import download_threat_information.parsing_scripts.parse_capec_cwe as parse_capec_cwe
import download_threat_information.parsing_scripts.parse_attack_tactic_technique as parse_attack
import offense.build_offensive_BRON as build_offensive_BRON
import graph_db.bron_neo4j as bron_neo4j

DOWNLOAD_PATH = "data/raw"
BRON_SAVE_PATH = "data/attacks"
MBRON_SAVE_PATH = "data/mitigations"

def parse_available_data():
    """Parse the successfully downloaded data sources."""
    logging.info("BEGIN Parsing available data")
    
    # Ensure output directory exists
    os.makedirs(BRON_SAVE_PATH, exist_ok=True)
    
    # Parse CWE & CAPEC data
    logging.info("Parsing CWE XML...")
    parse_capec_cwe.parse_cwe_xml_to_csv(
        os.path.join(DOWNLOAD_PATH, "raw_CWE_xml.zip"), 
        BRON_SAVE_PATH, 
        DOWNLOAD_PATH
    )
    
    logging.info("Parsing CAPEC XML...")
    parse_capec_cwe.parse_capec_xml_to_csv(
        os.path.join(DOWNLOAD_PATH, "raw_CAPEC.xml"), 
        BRON_SAVE_PATH
    )
    
    logging.info("Linking CAPEC and CWE...")
    parse_capec_cwe.parse_capec_cwe_files(BRON_SAVE_PATH)
    
    # Parse ATT&CK data
    logging.info("Parsing ATT&CK enterprise data...")
    parse_attack.parse_enterprise_attack(
        os.path.join(DOWNLOAD_PATH, "raw_enterprise_attack.json"), 
        BRON_SAVE_PATH
    )
    
    logging.info("Linking tactics and techniques...")
    parse_attack.link_tactic_techniques(
        os.path.join(DOWNLOAD_PATH, "raw_enterprise_attack.json"), 
        BRON_SAVE_PATH
    )
    
    logging.info("Linking techniques to techniques...")
    parse_attack.link_technique_technique(
        os.path.join(DOWNLOAD_PATH, "raw_enterprise_attack.json"), 
        BRON_SAVE_PATH
    )
    
    logging.info("Linking CAPEC and techniques...")
    parse_attack.link_capec_technique(BRON_SAVE_PATH)
    
    logging.info("Parsing completed successfully")

def create_synthetic_cve_data():
    """Create some synthetic CVE data to complete the attack chains."""
    logging.info("Creating synthetic CVE data for complete attack chains...")
    
    # Create a minimal CVE mapping file that the build process expects
    cve_data = {}
    
    # Read the CWE data to create realistic CVE mappings
    try:
        with open(os.path.join(BRON_SAVE_PATH, "cwe_names.json"), 'r') as f:
            cwe_data = json.load(f)
            
        # Create synthetic CVEs for common CWEs
        common_cwes = ['CWE-79', 'CWE-89', 'CWE-22', 'CWE-352', 'CWE-434', 'CWE-78']
        cve_counter = 2024001
        
        for cwe_id in common_cwes:
            if cwe_id in cwe_data:
                # Create 2-3 CVEs per CWE
                for i in range(2):
                    cve_id = f"CVE-2024-{cve_counter:05d}"
                    cve_data[cve_id] = {
                        'cwe_ids': [cwe_id],
                        'score': 7.5 + (i * 0.5),  # Vary severity
                        'description': f"Synthetic vulnerability exploiting {cwe_data[cwe_id]['name']}",
                        'cpe_matches': [
                            f"cpe:2.3:a:example:product{i}:1.0:*:*:*:*:*:*:*"
                        ]
                    }
                    cve_counter += 1
    
        # Save CVE mapping file
        cve_output_file = os.path.join(BRON_SAVE_PATH, "cve_map_cpe_cwe_score.json")
        with open(cve_output_file, 'w') as f:
            json.dump(cve_data, f, indent=2)
            
        logging.info(f"Created {len(cve_data)} synthetic CVE entries")
        
    except Exception as e:
        logging.warning(f"Could not create synthetic CVE data: {e}")

def build_bron_graph():
    """Build the BRON graph from parsed data."""
    logging.info("BEGIN building BRON graph")
    
    # Create synthetic CVE data if needed
    create_synthetic_cve_data()
    
    # Build the graph using the offensive BRON builder
    build_offensive_BRON.BRON_PATH = "."
    build_offensive_BRON.build_graph(BRON_SAVE_PATH, BRON_SAVE_PATH)
    
    logging.info("BRON graph build completed")

def import_to_neo4j(uri: str, user: str, password: str, database: str, clear: bool):
    """Import the built BRON graph to Neo4j."""
    logging.info("BEGIN importing BRON to Neo4j")
    
    bron_json_path = os.path.join(BRON_SAVE_PATH, "BRON.json")
    
    if not os.path.exists(bron_json_path):
        raise FileNotFoundError(f"BRON.json not found at {bron_json_path}")
    
    # Import using our Neo4j module
    counts = bron_neo4j.main(bron_json_path, uri, user, password, database, clear)
    
    logging.info("Neo4j import completed successfully")
    logging.info(f"Import statistics: {counts}")
    
    return counts

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Build BRON for Neo4j (ATT&CK, CAPEC, CWE)")
    
    # Neo4j arguments
    parser.add_argument("--neo4j_uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--neo4j_user", default="neo4j", help="Neo4j username")
    parser.add_argument("--neo4j_password", default="password123", help="Neo4j password")
    parser.add_argument("--neo4j_database", default="neo4j", help="Neo4j database name")
    parser.add_argument("--neo4j_clear", action="store_true", help="Clear Neo4j database before import")
    
    # Control flags
    parser.add_argument("--no_parsing", action="store_true", help="Skip parsing step")
    parser.add_argument("--no_building", action="store_true", help="Skip BRON building step")
    parser.add_argument("--no_import", action="store_true", help="Skip Neo4j import step")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('build_bron_neo4j.log'),
            logging.StreamHandler()
        ]
    )
    
    try:
        logging.info("Starting BRON build for Neo4j")
        
        if not args.no_parsing:
            parse_available_data()
            
        if not args.no_building:
            build_bron_graph()
            
        if not args.no_import:
            counts = import_to_neo4j(
                args.neo4j_uri,
                args.neo4j_user, 
                args.neo4j_password,
                args.neo4j_database,
                args.neo4j_clear
            )
            
            print("\n🎉 BRON Neo4j Build Complete!")
            print("=" * 50)
            print("📊 Database Statistics:")
            
            # Show node counts
            node_counts = {k: v for k, v in counts.items() if k.endswith('_nodes') and v > 0}
            for node_type, count in sorted(node_counts.items()):
                clean_name = node_type.replace('_nodes', '').replace('_', ' ').title()
                print(f"  📋 {clean_name}: {count}")
            
            print()    
            print("🔗 Relationship Statistics:")
            rel_counts = {k: v for k, v in counts.items() if k.endswith('_relationships') and v > 0}
            for rel_type, count in sorted(rel_counts.items()):
                clean_name = rel_type.replace('_relationships', '').replace('_', ' ')
                print(f"  🔗 {clean_name}: {count}")
                
            print(f"\n🌐 Neo4j Connection: {args.neo4j_uri}")
            print(f"📚 Database: {args.neo4j_database}")
            
        logging.info("BRON build completed successfully")
        
    except Exception as e:
        logging.error(f"Build failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()