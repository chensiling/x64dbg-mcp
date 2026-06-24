cmake_minimum_required(VERSION 3.15)
project(x64dbg_mcp_bridge LANGUAGES CXX)

get_filename_component(REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(PLUGINSDK_DIR "${REPO_ROOT}/pluginsdk")
set(DIST_DIR "${REPO_ROOT}/build")
set(PACKAGE_DIR "${DIST_DIR}/x64dbg-mcp")
set(MCP_SERVER_DIR "${REPO_ROOT}/mcp-server")
set(INTERMEDIATE_DIR "${CMAKE_BINARY_DIR}/intermediate")

add_library(mcp_bridge SHARED
    bridge_plugin.cpp
)

set_target_properties(mcp_bridge PROPERTIES
    OUTPUT_NAME "mcp_bridge"
    SUFFIX ".dp64"
    RUNTIME_OUTPUT_DIRECTORY "${DIST_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${DIST_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY "${INTERMEDIATE_DIR}"
    PDB_OUTPUT_DIRECTORY "${INTERMEDIATE_DIR}"
)

foreach(CONFIG DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    string(TOUPPER "${CONFIG}" CONFIG_UPPER)
    set_target_properties(mcp_bridge PROPERTIES
        "RUNTIME_OUTPUT_DIRECTORY_${CONFIG_UPPER}" "${DIST_DIR}"
        "LIBRARY_OUTPUT_DIRECTORY_${CONFIG_UPPER}" "${DIST_DIR}"
        "ARCHIVE_OUTPUT_DIRECTORY_${CONFIG_UPPER}" "${INTERMEDIATE_DIR}"
        "PDB_OUTPUT_DIRECTORY_${CONFIG_UPPER}" "${INTERMEDIATE_DIR}"
    )
endforeach()

target_include_directories(mcp_bridge PRIVATE
    ${PLUGINSDK_DIR}
    ${PLUGINSDK_DIR}/jansson
    ${PLUGINSDK_DIR}/lz4
    ${PLUGINSDK_DIR}/XEDParse
)

target_compile_definitions(mcp_bridge PRIVATE
    BUILD_BRIDGE
    _CRT_SECURE_NO_WARNINGS
)

target_link_libraries(mcp_bridge
    ${PLUGINSDK_DIR}/x64dbg.lib
    ${PLUGINSDK_DIR}/x64bridge.lib
    ${PLUGINSDK_DIR}/jansson/jansson_x64.lib
    Ws2_32.lib
    User32.lib
)

add_custom_command(TARGET mcp_bridge POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${PACKAGE_DIR}/web"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${MCP_SERVER_DIR}/server.py" "${PACKAGE_DIR}/server.py"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${MCP_SERVER_DIR}/bridge_client.py" "${PACKAGE_DIR}/bridge_client.py"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${MCP_SERVER_DIR}/tool_registry.py" "${PACKAGE_DIR}/tool_registry.py"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${MCP_SERVER_DIR}/requirements.txt" "${PACKAGE_DIR}/requirements.txt"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${MCP_SERVER_DIR}/config.json" "${PACKAGE_DIR}/config.json"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${MCP_SERVER_DIR}/web/health.html" "${PACKAGE_DIR}/web/health.html"
    COMMENT "Assembling x64dbg-mcp package in ${PACKAGE_DIR}"
)
