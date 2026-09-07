# CodeQL Audit Results: Server / Tool / Vulnerability

## Awesome-MCP-Server
- `read_wikipedia_article`: SSRF
- `summarize_wikipedia_article`: SSRF

## DesktopCommanderMCP
- `<unknown>`: Arbitrary File Content Write, ReDoS
- `call_tool_request`: Arbitrary File Content Write
- `create_directory`: Arbitrary Path Write via mkdir
- `edit_block`: Arbitrary File Content Write, Arbitrary File Read
- `read_file`: Arbitrary File Read, SSRF
- `start_search`: Arbitrary File Read, ReDoS
- `write_file`: Arbitrary File Content Write, Arbitrary File Read

## Jij-MCP-Server
- `jm_check`: RCE

## NetForensicMCP
- `analyze_pcap`: Command Injection
- `check_threats`: Command Injection
- `extract_credentials`: Command Injection
- `extract_stream_chunks`: Command Injection
- `extract_stream_content`: Command Injection
- `get_conversations`: Command Injection
- `get_stream_info`: Command Injection
- `get_summary_stats`: Command Injection
- `get_top_ips`: Command Injection

## PromptShopMCP
- `generate_image_from_url`: SSRF
- `remove_background`: SSRF

## aerostack-mcp
- `discover_feed`: SSRF
- `get_container_logs`: Command Injection

## blender-mcp
- `execute_blender_code`: RCE
- `generate_hunyuan3d_model`: Arbitrary File Read, SSRF
- `generate_hyper3d_model_via_images`: Arbitrary File Read
- `import_generated_asset_hunyuan`: SSRF

## code-index-mcp
- `get_symbol_body`: Arbitrary File Read
- `search_code_advanced`: ReDoS

## facebook-ads-mcp-server
- `fetch_pagination_url`: SSRF

## fm-mcp-servers
- `get_smadex_report_id`: SSRF

## genesis-mcp
- `run_simulation`: RCE

## graphlit-mcp-server
- `ingestFile`: Arbitrary File Read
- `retrieveImages`: SSRF

## mcp-dominican-layer
- `parse-csv`: SSRF
- `parse-pdf`: SSRF
- `parse-xlsx`: SSRF

## mcp-florence2
- `caption`: SSRF
- `ocr`: SSRF
- `process`: SSRF

## mcp-rdf-explorer
- `explore_url`: SSRF

## pptr-mcp
- `execute`: RCE

## swagger-testcase-mcp
- `fetch_swagger`: SSRF
