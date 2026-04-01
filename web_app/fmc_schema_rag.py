"""
FMC OpenAPI Examples RAG Pipeline.
Indexes merged_oas3_examples_rag.jsonl into searchable chunks for AI-assisted FMC configuration generation.
Sole authoritative source: utils/merged_oas3_examples_rag.jsonl
"""
import json
import os
import glob
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
    """RAG pipeline for FMC OpenAPI examples and related schema entries."""

    def __init__(self, jsonl_dir: str = None):
        self.jsonl_dir = jsonl_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "utils"
        )
        self.chunks: List[FMCSchemaChunk] = []
        self.schemas: Dict[str, Any] = {}          # schema_name -> raw JSON
        self.operations: Dict[str, Any] = {}        # operationId -> raw JSON
        self.examples: List[Dict[str, Any]] = []    # example entries from merged JSONL
        self._loaded = False

    def _get_jsonl_files(self) -> List[str]:
        """Get the merged examples JSONL file, if present."""
        pattern = os.path.join(self.jsonl_dir, "merged_oas3_examples_rag.jsonl")
        files = sorted(glob.glob(pattern))
        return files

    def load(self):
        """Load and index the merged JSONL RAG source file."""
        if self._loaded:
            return
        try:
            schema_entries = []
            operation_entries = []
            example_entries = []
            self.chunks = []
            jsonl_files = self._get_jsonl_files()
            if not jsonl_files:
                logger.error(f"No merged JSONL file found in {self.jsonl_dir}")
                return

            for jsonl_path in jsonl_files:
                with open(jsonl_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        entry = json.loads(line)
                        entry_type = entry.get("type")
                        if entry_type == "component_schema":
                            name = entry.get("metadata", {}).get("name", "")
                            if name and entry.get("json"):
                                self.schemas[name] = entry["json"]
                                schema_entries.append(entry)
                        elif entry_type == "operation":
                            op_id = entry.get("metadata", {}).get("operationId", "")
                            if op_id and entry.get("json"):
                                self.operations[op_id] = entry["json"]
                                operation_entries.append(entry)
                        elif entry.get("path") and entry.get("method"):
                            example_entries.append(entry)

            if schema_entries:
                self._index_schemas()
            if operation_entries:
                self._index_operations(operation_entries)
            if example_entries:
                self.examples = example_entries
                self._index_examples(example_entries)
            self._loaded = True
            logger.info(
                f"FMC RAG: indexed {len(self.chunks)} chunks "
                f"({len(self.schemas)} schemas, {len(self.operations)} operations, "
                f"{len(example_entries)} example entries) from {len(jsonl_files)} file(s)"
            )
        except Exception as e:
            logger.error(f"Failed to load FMC RAG JSONL: {e}")

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

    def _normalize_chunk_id(self, value: str) -> str:
        """Normalize a string to a safe chunk id segment."""
        cleaned = re.sub(r"[^a-zA-Z0-9]+", "_", value or "").strip("_")
        return cleaned.lower() or "unknown"

    def _is_chassis_chunk(self, chunk: FMCSchemaChunk) -> bool:
        """Return True if chunk content refers to chassis operations."""
        haystack = f"{chunk.schema_name}\n{chunk.content}".lower()
        return "/chassis/fmcmanagedchassis" in haystack or "fmcmanagedchassis" in haystack

    def _example_to_text(self, path: str, method: str, example: Dict) -> str:
        """Convert an example entry to human-readable text for the chunk."""
        lines = [f"FMC API Example: {method} {path}"]
        if example:
            name = example.get("name") or "Example"
            source_pointer = example.get("source_pointer")
            kind = example.get("kind")
            lines.append(f"Example: {name}")
            if kind:
                lines.append(f"Kind: {kind}")
            if source_pointer:
                lines.append(f"Source: {source_pointer}")
            data = example.get("data")
            if data is not None:
                payload = json.dumps(data, indent=2, ensure_ascii=False)
                if len(payload) > 2000:
                    payload = f"{payload[:2000]}... (truncated)"
                lines.append(payload)
        return "\n".join(lines)

    def _extract_example_keywords(self, path: str, method: str, example: Dict) -> List[str]:
        """Extract search keywords from an example entry."""
        kws = {method.lower()}
        for segment in (path or "").split("/"):
            if segment and not segment.startswith("{"):
                kws.add(segment.lower())

        if example:
            name_words = re.findall(r"[A-Za-z0-9]+", example.get("name", ""))
            for word in name_words:
                kws.add(word.lower())
            source_pointer = example.get("source_pointer", "")
            if "request" in source_pointer.lower():
                kws.add("request")
            if "response" in source_pointer.lower():
                kws.add("response")
            data = example.get("data")
            if isinstance(data, dict):
                for key in data.keys():
                    kws.add(str(key).lower())
                value = data.get("value")
                if isinstance(value, dict):
                    for key in value.keys():
                        kws.add(str(key).lower())

        return list(kws)

    def _index_examples(self, example_entries: List[Dict]):
        """Index API examples into chunks for retrieval."""
        for entry in example_entries:
            path = entry.get("path", "")
            method = entry.get("method", "").upper()
            examples = entry.get("examples") or []
            op_key = f"{method} {path}".strip()

            if not examples:
                chunk = FMCSchemaChunk(
                    chunk_id=f"example_{self._normalize_chunk_id(op_key)}_1",
                    content=self._example_to_text(path, method, {}),
                    schema_name=op_key,
                    config_type="example",
                    keywords=self._extract_example_keywords(path, method, {})
                )
                self.chunks.append(chunk)
                continue

            for idx, example in enumerate(examples, start=1):
                chunk = FMCSchemaChunk(
                    chunk_id=(
                        f"example_{self._normalize_chunk_id(method)}_"
                        f"{self._normalize_chunk_id(path)}_{idx}"
                    ),
                    content=self._example_to_text(path, method, example),
                    schema_name=op_key,
                    config_type="example",
                    keywords=self._extract_example_keywords(path, method, example)
                )
                self.chunks.append(chunk)

    def _index_operations(self, operation_entries: List[Dict]):
        """Index API operations into chunks for endpoint context."""
        for entry in operation_entries:
            meta = entry.get("metadata", {})
            op_id = meta.get("operationId", "")
            path = meta.get("path", "")
            method = meta.get("method", "").upper()
            title = entry.get("title", "")
            content = entry.get("content", "")

            # Build keywords from path segments and operationId
            kws = [op_id.lower(), method.lower()]
            for segment in path.split("/"):
                if segment and not segment.startswith("{"):
                    kws.append(segment.lower())
            for word in re.findall(r'[A-Z][a-z]+|[a-z]+', op_id):
                kws.append(word.lower())

            text = f"FMC API Operation: {method} {path}\n"
            text += f"operationId: {op_id}\n"
            text += content[:800] if content else ""

            chunk = FMCSchemaChunk(
                chunk_id=f"op_{op_id}",
                content=text,
                schema_name=op_id,
                config_type="operation",
                keywords=list(set(kws))
            )
            self.chunks.append(chunk)

    def search(self, query: str, top_k: int = 8) -> List[str]:
        """Search for relevant schema chunks based on query."""
        if not self._loaded:
            self.load()

        query_lower = query.lower()
        query_words = set(re.findall(r'\w+', query_lower))
        allow_chassis = "chassis" in query_words or "fmcmanagedchassis" in query_lower

        scored: List[Tuple[float, FMCSchemaChunk]] = []
        for chunk in self.chunks:
            if not allow_chassis and self._is_chassis_chunk(chunk):
                continue
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
        context = "=== FMC API Examples Reference ===\n\n"
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
