#!/usr/bin/env python3
"""
ADR Policy Store Context Provider

Provides enterprise policy data for reasoning-based compliance analysis.
Generic design focused on policy violations and governance.
"""
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Any

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create MCP server instance
mcp = FastMCP('policy_store_server')

# Load policy data
def load_policy_data() -> Dict[str, Any]:
    """Load enterprise policy data from YAML file"""
    policy_file = Path(__file__).parent / "data" / "policy_store.yaml"

    try:
        if policy_file.exists():
            with open(policy_file, 'r') as f:
                data = yaml.safe_load(f) or {"policies":[]}
                logger.info(f"Loaded policy data from {policy_file}")
                return data
        else:
            logger.warning(f"Policy file not found: {policy_file}")
            return {"policies": []}
    except Exception as e:
        logger.error(f"Failed to load policies: {e}")
        return {"policies": []}

policy_data = load_policy_data()

@mcp.tool()
def get_policies(categories: List[str] = None) -> Dict[str, Any]:
    """Get enterprise policies for compliance analysis"""
    policies = policy_data.get("policies", [])

    if categories:
        filtered_policies = [p for p in policies if p.get("category") in categories]
    else:
        filtered_policies = policies

    return {
        "policies": filtered_policies,
        "total_policies": len(filtered_policies)
    }

@mcp.tool()
def search_policies(keywords: List[str]) -> Dict[str, Any]:
    """Search policies by keywords for relevant compliance rules"""
    policies = policy_data.get("policies", [])
    matching_policies = []

    for policy in policies:
        # Search in policy text fields
        policy_text = f"{policy.get('name', '')} {policy.get('description', '')}"
        if policy.get('requirements'):
            policy_text += " " + " ".join(policy.get('requirements', []))

        # Check if any keyword matches
        for keyword in keywords:
            if keyword.lower() in policy_text.lower():
                matching_policies.append(policy)
                break  # Only add once per policy

    return {
        "matching_policies": matching_policies,
        "search_keywords": keywords,
        "total_matches": len(matching_policies)
    }

@mcp.tool()
def get_policy_categories() -> Dict[str, Any]:
    """Get available policy categories and risk areas"""
    # Extract categories dynamically from policies
    policies = policy_data.get("policies", [])
    categories = sorted(list(set(p.get("category", "") for p in policies if p.get("category"))))

    # Extract risk areas dynamically from policies
    risk_areas = set()
    for policy in policies:
        risk_areas.update(policy.get("risk_areas", []))
    risk_areas = sorted(list(risk_areas))

    return {
        "policy_categories": categories,
        "risk_categories": risk_areas,
        "total_categories": len(categories),
        "total_risk_areas": len(risk_areas)
    }

@mcp.tool()
def assess_policy_violations(operation_description: str) -> Dict[str, Any]:
    """Assess if operations violate policies"""
    policies = policy_data.get("policies", [])

    return {
        "operation": operation_description,
        "policies": policies
    }

@mcp.tool()
def get_risk_areas() -> Dict[str, Any]:
    """Get all risk areas across policies"""
    policies = policy_data.get("policies", [])

    risk_map = {}
    for policy in policies:
        category = policy.get("category", "uncategorized")
        entry = {
            "policy_name": policy.get("name"),
            "risk_areas": policy.get("risk_areas", [])
        }
        if category in risk_map:
            risk_map[category].append(entry)
        else:
            risk_map[category] = [entry]

    return risk_map

if __name__ == "__main__":
    mcp.run()
