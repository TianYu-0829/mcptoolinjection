/**
 * @name MCP tool input to full SSRF (JavaScript)
 * @description Tracks taint from MCP tool arguments to outbound request URLs
 *              where the attacker can control the hostname (full SSRF).
 *              Concatenating a constant `https://host/...` prefix only yields
 *              path/query control and is treated as a sanitizer, matching
 *              CodeQL's hostnameSanitizingPrefixEdge.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id custom/js/mcp-tool-input-ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import javascript
import semmle.javascript.dataflow.DataFlow
import semmle.javascript.dataflow.TaintTracking
import semmle.javascript.security.dataflow.UrlConcatenation
import mcp_request_arguments_sources_javascript

/**
 * A string that, when used as a URL prefix, forces the rest of the value into
 * the path. A lone "/" is included so `` `/${id}` `` is treated as a path, not
 * a hostname. Protocol-relative prefixes like "//evil" are excluded.
 */
predicate isRelativeUrlPrefix(DataFlow::Node nd) {
  nd.getStringValue().regexpMatch("/([^/].*)?")
  or
  isRelativeUrlPrefix(StringConcatenation::getAnOperand(nd))
  or
  isRelativeUrlPrefix(nd.getAPredecessor())
}

/**
 * Taint flowing from `source` into concatenation `sink` cannot change the
 * hostname of the resulting URL.
 */
predicate hostLockedPrefixEdge(DataFlow::Node source, DataFlow::Node sink) {
  hostnameSanitizingPrefixEdge(source, sink)
  or
  exists(DataFlow::Node operator, int n |
    StringConcatenation::taintStep(source, sink, operator, n) and
    isRelativeUrlPrefix(StringConcatenation::getOperand(operator, [0 .. n - 1]))
  )
}

predicate isOutboundUrlSink(DataFlow::Node sink) {
  exists(CallExpr c, VarAccess callee, Expr urlArg |
    c.getCallee() = callee and
    callee.getName() = "fetch" and
    urlArg = c.getArgument(0) and
    sink.asExpr() = urlArg
  )
  or
  exists(CallExpr c, PropAccess callee, Expr urlArg |
    c.getCallee() = callee and
    (callee.getPropertyName() = "get" or callee.getPropertyName() = "post") and
    exists(VarAccess base |
      base = callee.getBase() and
      (base.getName() = "axios" or base.getName() = "http")
    ) and
    urlArg = c.getArgument(0) and
    sink.asExpr() = urlArg
  )
}

/**
 * Full-SSRF configuration. Two complementary hostname locks:
 * - isBarrier: the concatenation *result* already has a locked host, so it
 *   must not be treated as a user-controlled URL.
 * - isBarrierOut: taint that is appended after a host-locking prefix must
 *   not continue (covers `path.startsWith('http') ? path : base+path`
 *   helpers whose relative-path call sites cannot change the host).
 */
module MCPToolInputToFullSsrfSig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isMcpRequestArgumentsSource(source) }

  predicate isSink(DataFlow::Node sink) { isOutboundUrlSink(sink) }

  predicate isBarrier(DataFlow::Node node) { hostLockedPrefixEdge(_, node) }

  predicate isBarrierOut(DataFlow::Node node) { hostLockedPrefixEdge(node, _) }
}

module MCPToolInputToFullSsrf = TaintTracking::Global<MCPToolInputToFullSsrfSig>;
import MCPToolInputToFullSsrf::PathGraph

from MCPToolInputToFullSsrf::PathNode source, MCPToolInputToFullSsrf::PathNode sink
where MCPToolInputToFullSsrf::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential SSRF: request.params.arguments may control outbound request URL hostname."
