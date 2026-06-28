# core/merger.py

def merge(proto, graph, enriched):
    """
    Consolidates data from all pipeline phases into a single frontend-ready JSON.
    Resolves node IDs into full ProtoJSON objects, filters edges, and binds briefs.
    """
    # 1. Map node_id → full node object (from raw ProtoJSON)
    proto_node_map = {
        node["node_id"]: node
        for node in proto.get("nodes", [])
    }

    # 2. Map chain_id → brief metadata (from Enrichment Engine)
    brief_map = {
        brief["chain_id"]: brief
        for brief in enriched.get("chain_briefs", [])
    }

    final_chains = []

    # 3. Assemble each chain
    for chain in graph.get("chains", []):
        chain_id = chain["chain_id"]
        node_ids = chain["node_ids"]

        # Resolve full node details
        nodes = []
        for nid in node_ids:
            if nid not in proto_node_map:
                raise Exception(f"Merger Error: Node reference '{nid}' in chain '{chain_id}' not found in original ProtoJSON.")
            nodes.append(proto_node_map[nid])

        # Filter edges corresponding strictly to nodes in this chain
        edges = []
        for edge in graph.get("edges", []):
            if edge.get("from") in node_ids and edge.get("to") in node_ids:
                edges.append(edge)

        # Retrieve and bind briefing details
        if chain_id not in brief_map:
            raise Exception(f"Merger Error: Missing enrichment brief for chain '{chain_id}'")
        brief = brief_map[chain_id]

        final_chain = {
            "chain_id": chain_id,
            "nodes": nodes,
            "edges": edges,
            "brief": brief
        }
        final_chains.append(final_chain)

    # 4. Compile final package
    final_output = {
        "pentest_id": proto.get("pentest_id"),
        "target": proto.get("target", "unknown_target"),
        "chains": final_chains
    }

    return final_output
