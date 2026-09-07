/**
 * @name MCP request arguments to dangerous sinks (JavaScript)
 * @description Tracks taint from request.params.arguments to dangerous sinks: RCE, command injection, ReDoS, arbitrary file read, and file injection. Full SSRF is in mcp-tool-input-ssrf-javascript.ql.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @id custom/js/mcp-request-arguments-to-dangerous-sinks
 * @tags security
 *       external/cwe/cwe-94
 *       external/cwe/cwe-78
 *       external/cwe/cwe-1333
 *       external/cwe/cwe-22
 *       external/cwe/cwe-73
 */

import javascript
import semmle.javascript.dataflow.DataFlow
import semmle.javascript.dataflow.TaintTracking
import mcp_request_arguments_sources_javascript

predicate sinkKind(DataFlow::Node sink, string kind) {
  exists(CallExpr c, PropAccess callee, Expr arg0 |
    c.getCallee() = callee and
    callee.getPropertyName() = "runInContext" and
    arg0 = c.getArgument(0) and
    sink.asExpr() = arg0 and
    kind = "rce"
  )
  or
  exists(NewExpr n, PropAccess ctor, VarAccess base, Expr codeArg |
    n.getCallee() = ctor and
    ctor.getPropertyName() = "Script" and
    base = ctor.getBase() and
    base.getName() = "vm" and
    codeArg = n.getArgument(0) and
    sink.asExpr() = codeArg and
    kind = "rce"
  )
  or
  exists(CallExpr c, VarAccess callee, Expr arg0 |
    c.getCallee() = callee and
    callee.getName() = "eval" and
    arg0 = c.getArgument(0) and
    sink.asExpr() = arg0 and
    kind = "rce"
  )
  or
  exists(CallExpr c, VarAccess callee, Expr arg0 |
    c.getCallee() = callee and
    (callee.getName() = "exec" or callee.getName() = "execSync" or callee.getName() = "execAsync") and
    arg0 = c.getArgument(0) and
    sink.asExpr() = arg0 and
    kind = "cmdi"
  )
  or
  exists(CallExpr c, PropAccess callee, Expr arg0 |
    c.getCallee() = callee and
    (callee.getPropertyName() = "exec" or callee.getPropertyName() = "execSync" or callee.getPropertyName() = "execAsync") and
    arg0 = c.getArgument(0) and
    sink.asExpr() = arg0 and
    kind = "cmdi"
  )
  or
  exists(NewExpr n, VarAccess ctor, Expr pattern |
    n.getCallee() = ctor and
    ctor.getName() = "RegExp" and
    pattern = n.getArgument(0) and
    sink.asExpr() = pattern and
    kind = "redos"
  )
  or
  exists(NewExpr n, PropAccess ctor, Expr pattern |
    n.getCallee() = ctor and
    ctor.getPropertyName() = "RegExp" and
    pattern = n.getArgument(0) and
    sink.asExpr() = pattern and
    kind = "redos"
  )
  or
  exists(CallExpr c, PropAccess callee, Expr pathArg |
    c.getCallee() = callee and
    (
      callee.getPropertyName() = "readFile" or
      callee.getPropertyName() = "readFileSync" or
      callee.getPropertyName() = "createReadStream"
    ) and
    pathArg = c.getArgument(0) and
    sink.asExpr() = pathArg and
    kind = "arbitrary_read"
  )
  or
  exists(CallExpr c, PropAccess callee, Expr pathArg |
    c.getCallee() = callee and
    (
      callee.getPropertyName() = "mkdir" or
      callee.getPropertyName() = "mkdirSync"
    ) and
    pathArg = c.getArgument(0) and
    sink.asExpr() = pathArg and
    kind = "path_write"
  )
  or
  exists(CallExpr c, PropAccess callee, Expr contentArg |
    c.getCallee() = callee and
    (
      callee.getPropertyName() = "writeFile" or
      callee.getPropertyName() = "writeFileSync" or
      callee.getPropertyName() = "appendFile" or
      callee.getPropertyName() = "appendFileSync"
    ) and
    contentArg = c.getArgument(1) and
    sink.asExpr() = contentArg and
    kind = "content_write"
  )
}

module MCPArgsToDangerousSinksSig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isMcpRequestArgumentsSource(source) }
  predicate isSink(DataFlow::Node sink) { sinkKind(sink, _) }
}

module MCPArgsToDangerousSinks = TaintTracking::Global<MCPArgsToDangerousSinksSig>;
import MCPArgsToDangerousSinks::PathGraph

predicate sinkMessage(string kind, string message) {
  kind = "rce" and
  message = "Potential RCE: request.params.arguments may reach vm.runInContext code argument."
  or
  kind = "cmdi" and
  message = "Potential command injection: request.params.arguments may reach exec-like command argument."
  or
  kind = "redos" and
  message = "Potential ReDoS: request.params.arguments may control RegExp pattern."
  or
  kind = "arbitrary_read" and
  message = "Potential arbitrary file read: request.params.arguments may control filesystem read path."
  or
  kind = "path_write" and
  message = "Potential file injection: request.params.arguments may control mkdir path."
  or
  kind = "content_write" and
  message = "Potential file injection: request.params.arguments may control write content."
}

from
  MCPArgsToDangerousSinks::PathNode source,
  MCPArgsToDangerousSinks::PathNode sink,
  string kind,
  string message
where
  MCPArgsToDangerousSinks::flowPath(source, sink) and
  sinkKind(sink.getNode(), kind) and
  sinkMessage(kind, message)
select sink.getNode(), source, sink, message
