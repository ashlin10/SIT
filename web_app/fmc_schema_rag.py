"""
FMC OpenAPI Schema RAG Pipeline.
Indexes merged_oas3.json into searchable chunks for AI-assisted FMC configuration generation.
"""
import json
import os
import logging
import re
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# Schema names relevant to device configuration (mapped to config YAML keys)
FMC_CONFIG_SCHEMA_MAP = {
    # Interfaces
    "loopback_interfaces": ["LoopbackInterface"],
    "physical_interfaces": ["PhysicalInterface"],
    "etherchannel_interfaces": ["EtherChannelInterface"],
    "subinterfaces": ["SubInterface"],
    "vti_interfaces": ["VTIInterface"],
    "inline_sets": ["InlineSet"],
    "bridge_group_interfaces": ["BridgeGroupInterface"],
    # Routing
    "bgp_general_settings": ["BGPGeneralSettingModel"],
    "bgp_policies": ["BGPIPvAddressFamilyModel", "IBGPAddressFamilyModel"],
    "bfd_policies": ["BFDPolicyModel", "VrfBFDPolicyModel"],
    "ospfv2_policies": ["OspfPolicyModel", "Ospfv2PolicyModel"],
    "ospfv2_interfaces": ["OspfInterfaceModel", "Ospfv2InterfaceModel"],
    "ospfv3_policies": ["Ospfv3PolicyModel"],
    "ospfv3_interfaces": ["Ospfv3InterfaceModel"],
    "eigrp_policies": ["EigrpPolicyModel"],
    "pbr_policies": ["PBRPolicyModel"],
    "ipv4_static_routes": ["IPv4StaticRouteModel"],
    "ipv6_static_routes": ["IPv6StaticRouteModel"],
    "ecmp_zones": ["ECMPZoneModel"],
    "vrfs": ["VRFPolicyEntry"],
    # Objects
    "security_zones": ["SecurityZoneObject"],
    "network_objects": ["NetworkObject"],
    "host_objects": ["HostObject"],
    "range_objects": ["RangeObject"],
    "fqdn_objects": ["FQDNObject"],
    "network_groups": ["NetworkGroup"],
    "port_objects": ["ProtocolPortObject", "ICMPv4Object", "ICMPv6Object", "AnyProtocolPortObject"],
    "port_groups": ["PortObjectGroup"],
    "bfd_templates": ["BFDTemplate"],
    "as_path_lists": ["AsPathList"],
    "key_chains": ["KeyChainObject"],
    "sla_monitors": ["SLAMonitorObjectModel"],
    "community_lists_standard": ["CommunityList"],
    "community_lists_extended": ["ExtendedCommunityList", "ExpandedCommunityList"],
    "ipv4_prefix_lists": ["IPv4PrefixList"],
    "ipv6_prefix_lists": ["IPv6PrefixList"],
    "access_lists_standard": ["StandardAccessListModel"],
    "access_lists_extended": ["ExtendedAccessListModel"],
    "route_maps": ["RouteMap"],
    "ipv4_address_pools": ["IPv4AddressPool"],
    "ipv6_address_pools": ["IPv6AddressPool"],
    "mac_address_pools": ["MACAddressPool"],
}

# Fields that represent secrets/auth and should never be generated
AUTH_FIELDS = {
    "authKey", "md5Key", "password", "secret", "neighborSecret",
    "encryptionKey", "authenticationKey", "preSharedKey", "keyString",
}


class FMCSchemaChunk:
    """A single searchable chunk of FMC schema information."""
    def __init__(self, chunk_id: str, content: str, schema_name: str,
                 config_type: str, keywords: List[str]):
        self.chunk_id = chunk_id
        self.content = content
        self.schema_name = schema_name
        self.config_type = config_type
        self.keywords = keywords


class FMCSchemaRAG:
    """RAG pipeline for FMC OpenAPI schema."""

    def __init__(self, schema_path: str = None):
        self.schema_path = schema_path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "utils", "merged_oas3.json"
        )
        self.chunks: List[FMCSchemaChunk] = []
        self.schemas: Dict[str, Any] = {}
        self.paths: Dict[str, Any] = {}
        self._loaded = False

    def load(self):
        """Load and index the OpenAPI schema."""
        if self._loaded:
            return
        try:
            with open(self.schema_path, "r") as f:
                data = json.load(f)
            self.schemas = data.get("components", {}).get("schemas", {})
            self.paths = data.get("paths", {})
            self._index_schemas()
            self._loaded = True
            logger.info(f"FMC Schema RAG: indexed {len(self.chunks)} chunks from {len(self.schemas)} schemas")
        except Exception as e:
            logger.error(f"Failed to load FMC schema: {e}")

    def _resolve_ref(self, ref: str) -> Optional[Dict]:
        """Resolve a $ref to its schema definition."""
        if not ref or not ref.startswith("#/components/schemas/"):
            return None
        name = ref.split("/")[-1]
        return self.schemas.get(name)

    def _flatten_schema(self, schema: Dict, depth: int = 0, max_depth: int = 3) -> Dict:
        """Flatten a schema by resolving $ref references up to max_depth."""
        if depth >= max_depth:
            return schema
        result = dict(schema)

        # Resolve allOf
        if "allOf" in result:
            merged = {}
            for part in result["allOf"]:
                if "$ref" in part:
                    resolved = self._resolve_ref(part["$ref"])
                    if resolved:
                        flat = self._flatten_schema(resolved, depth + 1, max_depth)
                        for k, v in flat.get("properties", {}).items():
                            merged[k] = v
                elif "properties" in part:
                    merged.update(part["properties"])
            result["properties"] = merged
            del result["allOf"]

        # Resolve property $refs
        if "properties" in result:
            new_props = {}
            for prop_name, prop_val in result["properties"].items():
                if "$ref" in prop_val:
                    resolved = self._resolve_ref(prop_val["$ref"])
                    if resolved and depth < max_depth - 1:
                        flat = self._flatten_schema(resolved, depth + 1, max_depth)
                        new_props[prop_name] = flat
                    else:
                        ref_name = prop_val["$ref"].split("/")[-1]
                        new_props[prop_name] = {"type": "object", "$ref_name": ref_name}
                elif "items" in prop_val and "$ref" in prop_val.get("items", {}):
                    ref_name = prop_val["items"]["$ref"].split("/")[-1]
                    new_props[prop_name] = {
                        "type": "array",
                        "items": {"type": "object", "$ref_name": ref_name}
                    }
                else:
                    new_props[prop_name] = prop_val
            result["properties"] = new_props

        return result

    def _schema_to_text(self, name: str, schema: Dict, config_type: str) -> str:
        """Convert a schema to human-readable text for the chunk."""
        flat = self._flatten_schema(schema, depth=0, max_depth=2)
        lines = [f"FMC API Schema: {name}"]
        lines.append(f"Config type: {config_type}")

        if "description" in flat:
            lines.append(f"Description: {flat['description']}")

        if flat.get("type"):
            lines.append(f"Type: {flat['type']}")

        required = set(flat.get("required", []))

        if "properties" in flat:
            lines.append("Properties:")
            for prop_name, prop_def in sorted(flat["properties"].items()):
                req_marker = " (REQUIRED)" if prop_name in required else ""
                is_auth = prop_name in AUTH_FIELDS
                auth_marker = " [AUTH/SECRET - must be provided by user]" if is_auth else ""

                prop_type = prop_def.get("type", "")
                if "$ref_name" in prop_def:
                    prop_type = f"object ({prop_def['$ref_name']})"
                elif prop_type == "array" and "items" in prop_def:
                    items = prop_def["items"]
                    item_type = items.get("$ref_name", items.get("type", ""))
                    prop_type = f"array of {item_type}"

                desc = prop_def.get("description", "")
                enum_vals = prop_def.get("enum", [])
                enum_str = f" enum={enum_vals}" if enum_vals else ""
                default = prop_def.get("default")
                default_str = f" default={default}" if default is not None else ""

                line = f"  - {prop_name}: {prop_type}{req_marker}{auth_marker}{enum_str}{default_str}"
                if desc:
                    line += f" — {desc[:120]}"
                lines.append(line)

        if "enum" in flat:
            lines.append(f"Allowed values: {flat['enum']}")

        return "\n".join(lines)

    def _extract_keywords(self, name: str, schema: Dict, config_type: str) -> List[str]:
        """Extract search keywords from a schema."""
        kws = [name.lower(), config_type.lower()]
        # Add property names as keywords
        for prop in schema.get("properties", {}):
            kws.append(prop.lower())
        # Split camelCase
        for word in re.findall(r'[A-Z][a-z]+|[a-z]+', name):
            kws.append(word.lower())
        return list(set(kws))

    def _index_schemas(self):
        """Index all relevant schemas into chunks."""
        self.chunks = []
        indexed_schemas = set()

        # Index schemas mapped to config types
        for config_type, schema_names in FMC_CONFIG_SCHEMA_MAP.items():
            for schema_name in schema_names:
                # Try exact match first
                schema = self.schemas.get(schema_name)
                if not schema:
                    # Try case-insensitive search
                    for k, v in self.schemas.items():
                        if k.lower() == schema_name.lower():
                            schema_name = k
                            schema = v
                            break
                if schema and schema_name not in indexed_schemas:
                    text = self._schema_to_text(schema_name, schema, config_type)
                    keywords = self._extract_keywords(schema_name, schema, config_type)
                    chunk = FMCSchemaChunk(
                        chunk_id=f"schema_{schema_name}",
                        content=text,
                        schema_name=schema_name,
                        config_type=config_type,
                        keywords=keywords
                    )
                    self.chunks.append(chunk)
                    indexed_schemas.add(schema_name)

        # Also index related sub-schemas (I-prefixed interfaces like IOspfArea, IBGPGSBestPath, etc.)
        for schema_name, schema in self.schemas.items():
            if schema_name in indexed_schemas:
                continue
            lower = schema_name.lower()
            # Index schemas that match device config concepts
            relevance_map = {
                "interface": "interfaces",
                "ospf": "ospf",
                "bgp": "bgp",
                "eigrp": "eigrp",
                "bfd": "bfd",
                "vrf": "vrf",
                "ecmp": "ecmp",
                "staticroute": "static_routes",
                "pbr": "pbr",
                "securityzone": "security_zones",
                "routemap": "route_maps",
                "prefixlist": "prefix_lists",
                "communitylist": "community_lists",
                "accesslist": "access_lists",
                "addresspool": "address_pools",
                "aspath": "as_path",
                "keychain": "key_chains",
                "slamonitor": "sla_monitors",
            }
            matched_type = None
            for keyword, ctype in relevance_map.items():
                if keyword in lower.replace("_", ""):
                    matched_type = ctype
                    break

            if matched_type and "listcontainer" not in lower and "metadata" not in lower:
                text = self._schema_to_text(schema_name, schema, matched_type)
                keywords = self._extract_keywords(schema_name, schema, matched_type)
                chunk = FMCSchemaChunk(
                    chunk_id=f"schema_{schema_name}",
                    content=text,
                    schema_name=schema_name,
                    config_type=matched_type,
                    keywords=keywords
                )
                self.chunks.append(chunk)
                indexed_schemas.add(schema_name)

    def search(self, query: str, top_k: int = 8) -> List[str]:
        """Search for relevant schema chunks based on query."""
        if not self._loaded:
            self.load()

        query_lower = query.lower()
        query_words = set(re.findall(r'\w+', query_lower))

        scored: List[Tuple[float, FMCSchemaChunk]] = []
        for chunk in self.chunks:
            score = 0.0

            # Direct config type match (highest weight)
            for config_type in FMC_CONFIG_SCHEMA_MAP:
                type_words = set(config_type.replace("_", " ").split())
                if type_words & query_words:
                    score += 10.0

            # Keyword overlap
            chunk_kw_set = set(chunk.keywords)
            overlap = query_words & chunk_kw_set
            score += len(overlap) * 3.0

            # Schema name fuzzy match
            schema_lower = chunk.schema_name.lower()
            for word in query_words:
                if len(word) >= 3 and word in schema_lower:
                    score += 5.0

            # Content substring match for specific terms
            content_lower = chunk.content.lower()
            for word in query_words:
                if len(word) >= 4 and word in content_lower:
                    score += 1.0

            if score > 0:
                scored.append((score, chunk))

        scored.sort(key=lambda x: x[0], reverse=True)
        results = []
        for score, chunk in scored[:top_k]:
            results.append(chunk.content)

        return results

    def get_schema_for_config_type(self, config_type: str) -> List[str]:
        """Get all schema chunks for a specific config type."""
        if not self._loaded:
            self.load()
        results = []
        for chunk in self.chunks:
            if chunk.config_type == config_type or config_type in chunk.config_type:
                results.append(chunk.content)
        return results

    def get_schema_json(self, schema_name: str) -> Optional[Dict]:
        """Get the raw JSON schema for a named schema."""
        if not self._loaded:
            self.load()
        schema = self.schemas.get(schema_name)
        if schema:
            return self._flatten_schema(schema, depth=0, max_depth=2)
        return None

    def get_context_for_query(self, query: str) -> str:
        """Get formatted context string for a query."""
        results = self.search(query, top_k=6)
        if not results:
            return ""
        context = "=== FMC API Schema Reference ===\n\n"
        context += "\n\n---\n\n".join(results)
        return context


# Singleton instance
_fmc_schema_rag: Optional[FMCSchemaRAG] = None

def get_fmc_schema_rag() -> FMCSchemaRAG:
    """Get or create the singleton FMC Schema RAG instance."""
    global _fmc_schema_rag
    if _fmc_schema_rag is None:
        _fmc_schema_rag = FMCSchemaRAG()
        _fmc_schema_rag.load()
    return _fmc_schema_rag
