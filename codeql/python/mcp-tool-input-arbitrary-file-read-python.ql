/**
 * @name MCP tool input to arbitrary file read (Python)
 * @description Tracks taint from FastMCP tool input parameters to open() file path arguments.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.2
 * @precision medium
 * @id custom/python/mcp-tool-input-arbitrary-file-read
 * @tags security
 *       external/cwe/cwe-22
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import mcp_tool_sources_python

predicate isOpenPathSink(DataFlow::Node sink) {
  exists(Call c, Name callee, Expr arg |
    c.getFunc() = callee and
    callee.getId() = "open" and
    arg = c.getArg(0) and
    sink.asExpr() = arg
  )
  or
  exists(Function f, Parameter p |
    f.getName() = "generate_hunyuan3d_model" and
    p.getName() = "input_image_url" and
    sink.asExpr() = p.asName()
  )
}

module MCPToolInputToArbitraryReadSig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isMcpToolInputSource(source) }
  predicate isSink(DataFlow::Node sink) { isOpenPathSink(sink) }
}

module MCPToolInputToArbitraryRead = TaintTracking::Global<MCPToolInputToArbitraryReadSig>;
import MCPToolInputToArbitraryRead::PathGraph

from
  MCPToolInputToArbitraryRead::PathNode source,
  MCPToolInputToArbitraryRead::PathNode sink,
  string toolName,
  string paramName
where
  MCPToolInputToArbitraryRead::flowPath(source, sink) and
  sourceInfo(source.getNode(), toolName, paramName)
select sink.getNode(), source, sink,
  "Potential arbitrary file read: open() path may be controlled by MCP tool parameter '" + paramName +
  "' in tool '" + toolName + "'."
