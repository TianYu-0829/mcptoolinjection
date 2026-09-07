/**
 * @name MCP tool input to ReDoS regex compilation (Python)
 * @description Tracks taint from FastMCP tool input parameters to re.compile pattern arguments.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id custom/python/mcp-tool-input-redos
 * @tags security
 *       external/cwe/cwe-1333
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import mcp_tool_sources_python

predicate isReCompileSink(DataFlow::Node sink) {
  exists(Call c, Attribute callee, Name base, Expr arg |
    c.getFunc() = callee and
    callee.getName() = "compile" and
    base = callee.getObject() and
    base.getId() = "re" and
    arg = c.getArg(0) and
    sink.asExpr() = arg
  )
}

module MCPToolInputToReDosSig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isMcpToolInputSource(source) }
  predicate isSink(DataFlow::Node sink) { isReCompileSink(sink) }
}

module MCPToolInputToReDos = TaintTracking::Global<MCPToolInputToReDosSig>;
import MCPToolInputToReDos::PathGraph

from
  MCPToolInputToReDos::PathNode source,
  MCPToolInputToReDos::PathNode sink,
  string toolName,
  string paramName
where
  MCPToolInputToReDos::flowPath(source, sink) and
  sourceInfo(source.getNode(), toolName, paramName)
select sink.getNode(), source, sink,
  "Potential ReDoS: re.compile pattern may be controlled by MCP tool parameter '" + paramName +
  "' in tool '" + toolName + "'."
