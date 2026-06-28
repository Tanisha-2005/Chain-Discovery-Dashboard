# main.py
import os
import sys
import json
import argparse
from core.pipeline import run_pipeline

def run_cli_pipeline():
    """
    Executes the offline pipeline just like Sprint 1.
    Loads data/protojson.json, runs the pipeline, and saves to data/dashboard_data.json.
    """
    input_path = "data/protojson.json"
    output_path = "data/dashboard_data.json"

    # Ensure files exist relative to execution directory
    if not os.path.exists(input_path):
        print(f"Error: Input file '{input_path}' not found.")
        sys.exit(1)

    print(f"Loading raw security audit from {input_path}...")
    with open(input_path, "r") as f:
        proto = json.load(f)

    print("Executing Chain Discovery Ingestion & Enrichment Pipeline...")
    try:
        result = run_pipeline(proto)
        
        # Ensure data folder exists
        os.makedirs("data", exist_ok=True)
        
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)
            
        print(f"Success: {output_path} generated successfully.")
    except Exception as e:
        print(f"Pipeline Execution Failed: {str(e)}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="VAPT & SOC Chain Discovery Engine")
    parser.add_argument(
        "--server", 
        action="store_true", 
        help="Launch the interactive FastAPI Server for the Web Dashboard"
    )
    parser.add_argument(
        "--port", 
        type=int, 
        default=8000, 
        help="Port to run the API server on (default: 8000)"
    )
    
    args = parser.parse_args()

    if args.server:
        # Lazy import of uvicorn and server to prevent load errors in CLI mode
        import uvicorn
        print(f"Starting Chain Discovery Dashboard API Server on port {args.port}...")
        uvicorn.run("server:app", host="0.0.0.0", port=args.port, reload=True)
    else:
        run_cli_pipeline()

if __name__ == "__main__":
    main()
