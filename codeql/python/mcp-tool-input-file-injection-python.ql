/**
 * @name MCP tool input to file injection sinks (Python)
 * @description Tracks taint from FastMCP tool input parameters to mkdir path arguments and Path.write_* content arguments.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id custom/python/mcp-tool-input-file-injection
 * @tags security
 *       external/cwe/cwe-73
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import mcp_tool_sources_python

predicate isMkdirPathSink(DataFlow::Node sink) {
  exists(Call c, Attribute callee, Name base, Expr arg |
    c.getFunc() = callee and
    callee.getName() = "makedirs" and
    base = callee.getObject() and
    base.getId() = "os" and
    arg = c.getArg(0) and
    sink.asExpr() = arg
  )
  or
  exists(Call c, Attribute callee, Name base, Expr arg |
    c.getFunc() = callee and
    callee.getName() = "mkdir" and
    base = callee.getObject() and
    base.getId() = "os" and
    arg = c.getArg(0) and
    sink.asExpr() = arg
  )
  or
  exists(Call methodCall, Attribute method, Call pathCtor, Name ctor, Expr pathArg |
    methodCall.getFunc() = method and
    method.getName() = "mkdir" and
    pathCtor = method.getObject() and
    pathCtor.getFunc() = ctor and
    ctor.getId() = "Path" and
    pathArg = pathCtor.getArg(0) and
    sink.asExpr() = pathArg
  )
}

predicate isPathWriteContentSink(DataFlow::Node sink) {
  exists(Call methodCall, Attribute method, Call pathCtor, Name ctor, Expr contentArg |
    methodCall.getFunc() = method and
    (method.getName() = "write_text" or method.getName() = "write_bytes") and
    pathCtor = method.getObject() and
    pathCtor.getFunc() = ctor and
    ctor.getId() = "Path" and
    contentArg = methodCall.getArg(0) and
    sink.asExpr() = contentArg
  )
}

predicate sinkKind(DataFlow::Node sink, string kind) {
  kind = "path_write" and isMkdirPathSink(sink)
  or
  kind = "content_write" and isPathWriteContentSink(sink)
}

module MCPToolInputToFileInjectionSig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isMcpToolInputSource(source) }
  predicate isSink(DataFlow::Node sink) { sinkKind(sink, _) }
}

module MCPToolInputToFileInjection = TaintTracking::Global<MCPToolInputToFileInjectionSig>;
import MCPToolInputToFileInjection::PathGraph

from
  MCPToolInputToFileInjection::PathNode source,
  MCPToolInputToFileInjection::PathNode sink,
  string toolName,
  string paramName,
  string kind,
  string message
where
  MCPToolInputToFileInjection::flowPath(source, sink) and
  sinkKind(sink.getNode(), kind) and
  sourceInfo(source.getNode(), toolName, paramName) and
  (
    kind = "path_write" and
    message = "Potential file injection: MCP tool input may control mkdir path."
    or
    kind = "content_write" and
    message = "Potential file injection: MCP tool input may control Path.write_* content."
  )
select sink.getNode(), source, sink, message
