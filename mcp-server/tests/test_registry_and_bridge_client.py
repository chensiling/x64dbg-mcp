import sys
import tempfile
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

from bridge_client import _convert_addrs, _normalize_base_url, _normalize_response, discover_instances
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

    def test_breakpoint_condition_lifecycle_tools_are_registered(self):
        expected = {
            "breakpoint_condition_get": "get_breakpoint_condition",
            "breakpoint_condition_set": "set_breakpoint_condition",
            "breakpoint_condition_append": "append_breakpoint_condition",
            "breakpoint_condition_clear": "clear_breakpoint_condition",
            "set_bp_filter": "set_breakpoint_condition",
        }
        for tool_name, command in expected.items():
            with self.subTest(tool_name=tool_name):
                spec = next(item for item in TOOL_DEFINITIONS if item["name"] == tool_name)
                schema = spec["inputSchema"]
                self.assertEqual(mcp_to_bridge_command(tool_name), command)
                self.assertEqual(schema["required"], ["addr"])
                self.assertIn("addr", schema["properties"])
                self.assertNotIn("filename", schema["properties"])

        append_schema = next(item for item in TOOL_DEFINITIONS if item["name"] == "breakpoint_condition_append")["inputSchema"]
        self.assertIn("condition", append_schema["properties"])
        self.assertIn("conditions", append_schema["properties"])
        self.assertIn("op", append_schema["properties"])


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

    def test_normalize_base_url_accepts_port_or_url(self):
        self.assertEqual(_normalize_base_url("21464"), "http://127.0.0.1:21464")
        self.assertEqual(_normalize_base_url("http://127.0.0.1:21464/"), "http://127.0.0.1:21464")

    def test_discover_instances_reads_http_instance_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance_dir = Path(tmp)
            (instance_dir / "123.json").write_text('{"port":21464,"pid":123}', encoding="utf-8")
            instances = discover_instances(instance_dir)
        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0]["url"], "http://127.0.0.1:21464")
        self.assertEqual(instances[0]["pid"], 123)

    def test_discover_instances_deduplicates_same_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance_dir = Path(tmp)
            old_file = instance_dir / "old.json"
            new_file = instance_dir / "new.json"
            old_file.write_text('{"port":21464,"pid":1}', encoding="utf-8")
            new_file.write_text('{"port":21464,"pid":2}', encoding="utf-8")
            old_time = 1000
            new_time = 2000
            import os
            os.utime(old_file, (old_time, old_time))
            os.utime(new_file, (new_time, new_time))
            instances = discover_instances(instance_dir)
        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0]["pid"], 2)


if __name__ == "__main__":
    unittest.main()
