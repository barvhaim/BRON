# BRON - Building Relevant Ontology for cybersecurity

[![BRON February 2023](docs/figures/BRON_drawing.png)](docs/figures/BRON_drawing.png)

BRON (Building Relevant Ontology for cybersecurity) is a Python-based cybersecurity knowledge graph that links threat data from multiple sources:
- [MITRE ATT&CK](https://attack.mitre.org/) (tactics, techniques)  
- [CAPEC](https://capec.mitre.org/) (attack patterns)
- [CWE](https://cwe.mitre.org/) (weakness enumeration)
- [CVE](https://nvd.nist.gov) (vulnerabilities) 
- [MITRE Engage](https://engage.mitre.org/), [D3FEND](https://d3fend.mitre.org/) (defensive mitigations)
- [CPE](https://nvd.nist.gov/products/cpe) (platform configurations)
- [ExploitDB](https://exploit-db.com/) data

The graph can be stored in either **ArangoDB** or **Neo4j** with bidirectional edges connecting related cybersecurity concepts. Orange nodes represent "offensive" information, while blue nodes represent "defensive" information.

## Deployment

BRON supports both ArangoDB and Neo4j as backend databases. You can use either one independently or both simultaneously.

See [graph_db](graph_db) for implementation details. A public ArangoDB instance is available at [bron.alfa.csail.mit.edu](http://bron.alfa.csail.mit.edu:8529).

### Ubuntu Setup

#### Python Environment
```bash
# Python 
sudo apt install python3 python3-venv python3-dev

# Python venv
python3 -m venv ~/.venvs/BRON-dev
# Activate venv
source ~/.venvs/BRON-dev/bin/activate
# Install dependencies
pip install -r requirements.txt
# Pythonpath
export PYTHONPATH=.

# BRON environment variables
export BRON_PWD={Your database password}
export BRON_SERVER_IP=127.0.0.1
```

#### Database Installation (Choose One or Both)

**ArangoDB:**
```bash
curl -OL https://download.arangodb.com/arangodb310/DEBIAN/Release.key
sudo apt-key add - < Release.key
echo 'deb https://download.arangodb.com/arangodb310/DEBIAN/ /' | sudo tee /etc/apt/sources.list.d/arangodb.list
sudo apt-get install apt-transport-https
sudo apt-get update
sudo apt-get install arangodb3=3.10.2-1
```

**Neo4j:**
```bash
# Install Java (required for Neo4j)
sudo apt install openjdk-11-jdk

# Add Neo4j repository
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable 4.4' | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt-get update
sudo apt-get install neo4j

# Start Neo4j service
sudo systemctl enable neo4j
sudo systemctl start neo4j
```

#### Build BRON

**With ArangoDB:**
```bash
python tutorials/build_bron.py --username root --password ${BRON_PWD} --ip ${BRON_SERVER_IP}
```

**With Neo4j:**
```bash
python tutorials/build_bron.py --username root --password dummy --ip 127.0.0.1 --no_arangodb --neo4j --neo4j_uri bolt://localhost:7687 --neo4j_user neo4j --neo4j_password password123 --neo4j_clear
```

**With Both Databases:**
```bash
python tutorials/build_bron.py --username root --password ${BRON_PWD} --ip ${BRON_SERVER_IP} --neo4j --neo4j_uri bolt://localhost:7687 --neo4j_user neo4j --neo4j_password password123
```

#### Testing
```bash
# Test ArangoDB implementation
python -m unittest tests.test_bron_graph_db

# Test Neo4j implementation
python -m unittest tests.test_neo4j_graph_db

# Run all tests
python -m unittest tests.test_schema tests.test_mitigations
```

### Docker
Pre-requisites:
- Docker ([installing Docker](https://docs.docker.com/engine/install/))
- Docker Compose ([installing Compose](https://docs.docker.com/compose/install/))

To deploy BRON on top of ArangoDB, clone this repository and run:
```
docker-compose up -d
```

The deployment starts two containers:
- `brondb`: an ArangoDB server hosting the BRON graph and collections
- `bootstrap`: an ephemeral container that builds BRON and loads it into the graph database

It may take a few minutes for the bootstrap to conclude. It will download and analyze the required datasets, build BRON, and import it into the database. You can check its completion by monitoring the `bootstrap` container logs.
```
docker logs -f bootstrap
```
To access the graph database console, point your browser to `http://localhost:8529`, login, and select BRON as database. 

> Note: this deployment uses docker secrets for setting the database password; its value can be changed in `./graph_db/arango_root_password`.

## Programmatic APIs Installation

Python version > = 3.8

### Pip
- Create a `pip` environment
```
python3 -m venv bron_venv
source ./bron_venv/bin/activate
pip install -r requirements.txt
```

## Getting Started 

### Quick Start with Docker (Recommended)
```bash
docker-compose up -d
docker logs -f bootstrap  # Monitor build progress
```

### Manual Installation
Choose your preferred database backend:

**ArangoDB:**
```bash
python tutorials/build_bron.py --username root --password $(cat arango_root_password) --ip 127.0.0.1
tail -n 1 build_bron.log
```

**Neo4j Only:**
```bash
python tutorials/build_bron.py --username root --password dummy --ip 127.0.0.1 --no_arangodb --neo4j --neo4j_clear
```

This should produce a `build_bron.log` file that ends with `END building BRON`.

## Querying BRON

### ArangoDB Queries
```bash
python graph_db/query_graph_db.py --starting_point_type capec --starting_point graph_db/example_data/example_input_data/starting_point_capec.csv
```

### Neo4j Queries
```bash
python graph_db/query_neo4j.py --starting_point_type capec --starting_point graph_db/example_data/example_input_data/starting_point_capec.csv --neo4j_uri bolt://localhost:7687 --neo4j_user neo4j --neo4j_password password123
```

## Tutorials
Tutorials are available in the `tutorials` folder:
- Using BRON in ArangoDB: `tutorials/using_bron_graphdb.py`
- Building BRON: `tutorials/build_bron.py`


## Command Line Usage

### Build BRON with Multiple Database Support

```bash
usage: build_bron.py [-h] --username USERNAME --password PASSWORD --ip IP 
                     [--clean] [--clean_local_files] [--delete_mitigations] 
                     [--no_download] [--no_parsing] [--no_building] [--no_arangodb]
                     [--no_mitigations] [--no_validation]
                     [--neo4j] [--neo4j_uri NEO4J_URI] [--neo4j_user NEO4J_USER] 
                     [--neo4j_password NEO4J_PASSWORD] [--neo4j_database NEO4J_DATABASE] 
                     [--neo4j_clear]

Build BRON in ArangoDB and/or Neo4j

Database Options:
  --username USERNAME   ArangoDB username
  --password PASSWORD   ArangoDB password  
  --ip IP               ArangoDB IP address
  --no_arangodb         Skip ArangoDB import
  --neo4j               Enable Neo4j support
  --neo4j_uri NEO4J_URI Neo4j connection URI (default: bolt://localhost:7687)
  --neo4j_user NEO4J_USER Neo4j username (default: neo4j)
  --neo4j_password NEO4J_PASSWORD Neo4j password (default: password123)
  --neo4j_database NEO4J_DATABASE Neo4j database name (default: neo4j)
  --neo4j_clear         Clear Neo4j database before import

Build Options:
  --clean               Clean all files and databases
  --clean_local_files   Clean all local files
  --delete_mitigations  Clean all mitigation collections
  --no_download         Do not download data
  --no_parsing          Do not parse data
  --no_building         Do not build BRON
  --no_mitigations      Do not create and import mitigations
  --no_validation       Do not validate entries imported to the database
```

### Import Existing BRON Data to Neo4j
```bash
python graph_db/bron_neo4j.py data/attacks/BRON.json --uri bolt://localhost:7687 --user neo4j --password password123 --clear
```

## Architecture

### Core Modules

- **`download_threat_information/`** - Downloads and parses raw threat data from various sources (MITRE, CVE, etc.)
- **`offense/`** - Builds offensive BRON components, linking attack techniques to vulnerabilities
- **`mitigations/`** - Processes defensive data from D3FEND, Engage, and mitigation frameworks
- **`graph_db/`** - Graph database integration (ArangoDB/Neo4j), schema management, and graph operations
- **`utils/`** - Shared utilities for data processing and BRON operations
- **`tutorials/`** - Entry point scripts and usage examples

### Database Support

BRON now supports both ArangoDB and Neo4j as backend databases:

- **ArangoDB**: Multi-model database with native graph capabilities
- **Neo4j**: Native graph database with Cypher query language
- **Parallel Support**: Use both databases simultaneously or independently
- **Schema Mapping**: Automatic conversion between database formats
- **Performance Optimizations**: Batched imports and proper indexing

### Graph Schema
The graph schema is defined in `graph_db/schema.json` with:
- **Vertex collections**: Individual data types (technique, cve, cwe, etc.)
- **Edge collections**: Relationships between data types (TechniqueCapec, CapecCwe, etc.)
- **Unique constraints**: Prevent duplicate entries based on original_id and name

See `graph_db/schemas` for detailed schema definitions.

## Bibliography

arXiv report: [https://arxiv.org/abs/2010.00533](https://arxiv.org/abs/2010.00533)

```
@misc{hemberg2021linking,
      title={Linking Threat Tactics, Techniques, and Patterns with Defensive Weaknesses, Vulnerabilities and Affected Platform Configurations for Cyber Hunting}, 
      author={Erik Hemberg and Jonathan Kelly and Michal Shlapentokh-Rothman and Bryn Reinstadler and Katherine Xu and Nick Rutar and Una-May O'Reilly},
      year={2021},
      eprint={2010.00533},
      archivePrefix={arXiv},
      primaryClass={cs.CR}
}
```
