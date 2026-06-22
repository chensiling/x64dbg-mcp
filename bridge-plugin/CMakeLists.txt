cmake_minimum_required(VERSION 3.15)
project(x64dbg_mcp_bridge LANGUAGES CXX)

set(PLUGINSDK_DIR "${CMAKE_SOURCE_DIR}/../pluginsdk")

add_library(mcp_bridge SHARED
    bridge_plugin.cpp
)

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
)

# Copy output to x64dbg plugins directory (adjust path as needed)
# add_custom_command(TARGET mcp_bridge POST_BUILD
#     COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:mcp_bridge>
#         "C:/path/to/x64dbg/release/x64/plugins/mcp_bridge.dp64"
# )
