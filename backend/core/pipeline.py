# core/pipeline.py
import logging

from engines.brain import run_brain
from engines.enrichment import run_enrichment

from core.validator import (
    validate_proto,
    validate_graph,
    validate_enrichment
)
from core.merger import merge

# Setup backend logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PipelineController")

def run_pipeline(proto):
    """
    Executes the ingestion, analysis, enrichment, and consolidation pipeline.
    """
    logger.info("Initializing pipeline execution...")

    # Step 1: Validate Input ProtoJSON
    logger.info("Step 1: Validating raw ProtoJSON schema...")
    validate_proto(proto)
    logger.info("ProtoJSON validation successful.")

    # Step 2: Establish attack graph (Brain Engine)
    logger.info("Step 2: Computing graph nodes and correlation edges...")
    graph = run_brain(proto)
    logger.info(f"Graph computed with {len(graph.get('nodes', []))} nodes, {len(graph.get('edges', []))} edges.")

    # Step 3: Validate Graph Structure
    logger.info("Step 3: Validating graph and attack path links...")
    validate_graph(graph)
    logger.info("Graph structural validation successful.")

    # Step 4: Enrich attack paths (Enrichment Engine)
    logger.info("Step 4: Executing threat enrichment & remediation plan generation...")
    enriched = run_enrichment(graph, proto)
    logger.info(f"Enrichment generated for {len(enriched.get('chain_briefs', []))} briefs.")

    # Step 5: Validate Enrichment contracts
    logger.info("Step 5: Validating enrichment compliance...")
    validate_enrichment(graph, enriched)
    logger.info("Enrichment validation successful.")

    # Step 6: Consolidate elements
    logger.info("Step 6: Running consolidation merger...")
    final_output = merge(proto, graph, enriched)
    logger.info("Pipeline executed and merged successfully.")

    return final_output
