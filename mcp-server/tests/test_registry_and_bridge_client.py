import sys
import types
import unittest
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_DIR))

if "mcp.types" not in sys.modules:
    mcp_module = types.ModuleType("mcp")
    mcp_types_module = types.ModuleType("mcp.types")

    class Tool:
        def __init__(self, name, description, inputSchema):
            self.name = name
            self.description = description
            self.inputSchema = inputSchema

    mcp_types_module.Tool = Tool
    sys.modules["mcp"] = mcp_module
    sys.modules["mcp.types"] = mcp_types_module

for module_name in ("win32file", "win32pipe"):
    sys.modules.setdefault(module_name, types.ModuleType(module_name))

pywintypes_module = types.ModuleType("pywintypes")
pywintypes_module.error = OSError
sys.modules.setdefault("pywintypes", pywintypes_module)

from bridge_client import _convert_addrs, _normalize_response
from tool_registry import TOOL_DEFINITIONS, TOOL_TO_CMD, get_tools, mcp_to_bridge_command


class ToolRegistryTests(unittest.TestCase):
    def test_tool_names_are_unique(self):
        names = [spec["name"] for spec in TOOL_DEFINITIONS]
        self.assertEqual(len(names), len(set(names)))

    def test_command_mapping_only_references_public_tools(self):
        names = {spec["name"] for spec in TOOL_DEFINITIONS}
        self.assertLessEqual(set(TOOL_TO_CMD), names)

    def test_tools_are_constructed_from_metadata(self):
        tools = get_tools()
        self.assertEqual(len(tools), len(TOOL_DEFINITIONS))
        self.assertEqual(mcp_to_bridge_command("memory_read"), "read_memory")
        self.assertEqual(mcp_to_bridge_command("unknown_tool"), "unknown_tool")

    def test_breakpoint_filter_accepts_single_or_multiple_conditions(self):
        spec = next(item for item in TOOL_DEFINITIONS if item["name"] == "set_bp_filter")
        schema = spec["inputSchema"]
        self.assertEqual(schema["required"], ["addr"])
        self.assertIn("condition", schema["properties"])
        self.assertIn("conditions", schema["properties"])
        self.assertIn("op", schema["properties"])
        self.assertNotIn("filename", schema["properties"])

    def test_breakpoint_set_does_not_accept_condition(self):
        spec = next(item for item in TOOL_DEFINITIONS if item["name"] == "breakpoint_set")
        schema = spec["inputSchema"]
        self.assertNotIn("condition", schema["properties"])


class BridgeClientNormalizationTests(unittest.TestCase):
    def test_convert_address_integers_to_hex_strings(self):
        converted = _convert_addrs({"addr": 0x401000, "count": 3})
        self.assertEqual(converted["addr"], "0x401000")
        self.assertEqual(converted["count"], 3)

    def test_normalize_success_response(self):
        response = _normalize_response({"id": "7", "result": {"state": "paused"}})
        self.assertTrue(response["ok"])
        self.assertEqual(response["bridge_id"], "7")
        self.assertEqual(response["data"]["state"], "paused")
        self.assertIsNone(response["error"])

    def test_normalize_bridge_error_response(self):
        response = _normalize_response({"id": "8", "error": "unknown method"})
        self.assertFalse(response["ok"])
        self.assertEqual(response["bridge_id"], "8")
        self.assertEqual(response["error"]["code"], "BRIDGE_ERROR")

    def test_normalize_command_failed_payload(self):
        response = _normalize_response({"id": "9", "result": {"ok": False, "error": "command failed"}})
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "COMMAND_FAILED")
        self.assertEqual(response["data"]["error"], "command failed")


if __name__ == "__main__":
    unittest.main()
