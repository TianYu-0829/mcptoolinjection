/**
 * @name MCP tool input to code execution (Python)
 * @description Tracks taint from FastMCP tool input parameters to exec/eval code execution sinks.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision medium
 * @id custom/python/mcp-tool-input-rce
 * @tags security
 *       external/cwe/cwe-94
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import mcp_tool_sources_python

predicate isExecOrEvalSink(DataFlow::Node sink) {
  exists(Call c, Name callee, Expr arg |
    c.getFunc() = callee and
    (callee.getId() = "exec" or callee.getId() = "eval") and
    arg = c.getArg(0) and
    sink.asExpr() = arg
  )
  or
  exists(Function f, Parameter p |
    f.getName() = "execute_blender_code" and
    p.getName() = "code" and
    sink.asExpr() = p.asName()
  )
}

module MCPToolInputToRCESig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isMcpToolInputSource(source) }
  predicate isSink(DataFlow::Node sink) { isExecOrEvalSink(sink) }
}

module MCPToolInputToRCE = TaintTracking::Global<MCPToolInputToRCESig>;
import MCPToolInputToRCE::PathGraph

from
  MCPToolInputToRCE::PathNode source,
  MCPToolInputToRCE::PathNode sink,
  string toolName,
  string paramName
where
  MCPToolInputToRCE::flowPath(source, sink) and
  sourceInfo(source.getNode(), toolName, paramName)
select sink.getNode(), source, sink,
  "Potential RCE: exec/eval argument may be controlled by MCP tool parameter '" + paramName +
  "' in tool '" + toolName + "'."
