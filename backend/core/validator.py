# core/validator.py
import re

HOST_REGEX = re.compile(r"^[a-zA-Z0-9\.\-_]+$")

class ValidationError(Exception):
    def __init__(self, message, error_code="VALIDATION_ERROR"):
        super().__init__(message)
        self.error_code = error_code

def validate_proto(proto):
    """
    Validates the raw ProtoJSON data structure.
    Checks required fields, node schemas, port ranges, and hosts.
    """
    if not proto:
        raise ValidationError("ProtoJSON is empty or invalid JSON", "ERR_EMPTY_PAYLOAD")

    if "pentest_id" not in proto or not str(proto["pentest_id"]).strip():
        raise ValidationError("proto: missing or empty 'pentest_id'", "ERR_MISSING_PENTEST_ID")

    if "nodes" not in proto or not isinstance(proto["nodes"], list):
        raise ValidationError("proto: 'nodes' must be a non-empty array", "ERR_MISSING_NODES")

    if len(proto["nodes"]) == 0:
        raise ValidationError("proto: 'nodes' array cannot be empty", "ERR_EMPTY_NODES_LIST")

    seen_node_ids = set()

    for idx, node in enumerate(proto["nodes"]):
        # Check node_id presence
        if "node_id" not in node or not str(node["node_id"]).strip():
            raise ValidationError(f"proto: node at index {idx} is missing 'node_id'", "ERR_MISSING_NODE_ID")
        
        node_id = node["node_id"]
        if node_id in seen_node_ids:
            raise ValidationError(f"proto: duplicate node_id '{node_id}' found", "ERR_DUPLICATE_NODE_ID")
        seen_node_ids.add(node_id)

        # Check required VAPT attributes
        required_fields = ["type", "host", "port", "timestamp", "severity"]
        for field in required_fields:
            if field not in node or node[field] is None:
                raise ValidationError(f"proto: node '{node_id}' is missing required field '{field}'", f"ERR_MISSING_FIELD_{field.upper()}")

        # Port validation
        port = node["port"]
        try:
            port_val = int(port)
            if port_val < 1 or port_val > 65535:
                raise ValueError()
        except (ValueError, TypeError):
            raise ValidationError(f"proto: node '{node_id}' has invalid port value '{port}' (must be 1-65535)", "ERR_INVALID_PORT")

        # Host validation (basic syntax check)
        host = str(node["host"])
        if not HOST_REGEX.match(host):
            raise ValidationError(f"proto: node '{node_id}' has invalid host syntax '{host}'", "ERR_INVALID_HOST")

        # Severity validation
        valid_severities = {"info", "low", "medium", "high", "critical", "confirmed"}
        severity = str(node["severity"]).lower()
        if severity not in valid_severities:
            raise ValidationError(f"proto: node '{node_id}' has invalid severity '{severity}' (must be one of {valid_severities})", "ERR_INVALID_SEVERITY")


def validate_graph(graph):
    """
    Validates that the Graph structure emitted by the Brain module aligns with contracts.
    """
    if "nodes" not in graph or not isinstance(graph["nodes"], list):
        raise ValidationError("graph: missing or invalid 'nodes' array", "ERR_GRAPH_NODES")

    if "edges" not in graph or not isinstance(graph["edges"], list):
        raise ValidationError("graph: missing or invalid 'edges' array", "ERR_GRAPH_EDGES")

    if "chains" not in graph or not isinstance(graph["chains"], list):
        raise ValidationError("graph: missing or invalid 'chains' array", "ERR_GRAPH_CHAINS")

    graph_node_ids = {node["id"] for node in graph["nodes"] if "id" in node}

    # Verify edge connectivity references existing nodes
    for idx, edge in enumerate(graph["edges"]):
        for field in ["from", "to"]:
            if field not in edge:
                raise ValidationError(f"graph: edge at index {idx} missing '{field}' field", "ERR_INVALID_EDGE_STRUCT")
            
            node_ref = edge[field]
            if node_ref not in graph_node_ids:
                raise ValidationError(f"graph: edge references non-existent node '{node_ref}'", "ERR_INVALID_NODE_REFERENCE")

    # Verify chain node associations
    for chain in graph["chains"]:
        if "chain_id" not in chain:
            raise ValidationError("graph: chain missing 'chain_id'", "ERR_INVALID_CHAIN_STRUCT")
        if "node_ids" not in chain or not isinstance(chain["node_ids"], list):
            raise ValidationError(f"graph: chain '{chain.get('chain_id')}' missing or invalid 'node_ids'", "ERR_INVALID_CHAIN_NODES")
        
        for nid in chain["node_ids"]:
            if nid not in graph_node_ids:
                raise ValidationError(f"graph: chain '{chain['chain_id']}' contains unknown node reference '{nid}'", "ERR_CHAIN_UNKNOWN_NODE")


def validate_enrichment(graph, enriched):
    """
    Validates that the Enrichment output maps to all computed attack chains.
    """
    if "chain_briefs" not in enriched or not isinstance(enriched["chain_briefs"], list):
        raise ValidationError("enrichment: missing or invalid 'chain_briefs' array", "ERR_ENRICHMENT_BRIEFS")

    graph_chain_ids = {c["chain_id"] for c in graph["chains"]}
    brief_ids = {b["chain_id"] for b in enriched["chain_briefs"]}

    missing_briefs = graph_chain_ids - brief_ids
    if missing_briefs:
        raise ValidationError(f"enrichment: missing briefings for attack chains: {list(missing_briefs)}", "ERR_ENRICHMENT_MISMATCH")
