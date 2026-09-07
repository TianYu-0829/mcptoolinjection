/**
 * @name MCP tool input to command injection (Python)
 * @description Tracks taint from FastMCP tool input parameters to os.system command arguments.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision medium
 * @id custom/python/mcp-tool-input-command-injection
 * @tags security
 *       external/cwe/cwe-78
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import mcp_tool_sources_python

predicate isOsSystemSink(DataFlow::Node sink) {
  exists(Call c, Attribute callee, Name base, Expr arg |
    c.getFunc() = callee and
    callee.getName() = "system" and
    base = callee.getObject() and
    base.getId() = "os" and
    arg = c.getArg(0) and
    sink.asExpr() = arg
  )
}

module MCPToolInputToCmdiSig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isMcpToolInputSource(source) }
  predicate isSink(DataFlow::Node sink) { isOsSystemSink(sink) }
}

module MCPToolInputToCmdi = TaintTracking::Global<MCPToolInputToCmdiSig>;
import MCPToolInputToCmdi::PathGraph

from
  MCPToolInputToCmdi::PathNode source,
  MCPToolInputToCmdi::PathNode sink,
  string toolName,
  string paramName
where
  MCPToolInputToCmdi::flowPath(source, sink) and
  sourceInfo(source.getNode(), toolName, paramName)
select sink.getNode(), source, sink,
  "Potential command injection: os.system argument may be controlled by MCP tool parameter '" +
  paramName + "' in tool '" + toolName + "'."
