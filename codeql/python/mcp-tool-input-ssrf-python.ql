/**
 * @name MCP tool input to full SSRF (Python)
 * @description Tracks taint from FastMCP tool input parameters to outbound HTTP
 *              request URLs where the attacker can control the hostname.
 *              Constant host prefixes (`https://api.example.com/{id}`) are
 *              treated as FullUrlControlSanitizer, matching CodeQL's official
 *              py/full-ssrf modeling.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id custom/python/mcp-tool-input-ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.ServerSideRequestForgeryCustomizations
import mcp_tool_sources_python

predicate isOutboundUrlSink(DataFlow::Node sink) {
  exists(Call c, Attribute callee, Name base, Expr urlArg |
    c.getFunc() = callee and
    base = callee.getObject() and
    (base.getId() = "requests" or base.getId() = "httpx") and
    (
      callee.getName() = "get" or
      callee.getName() = "post" or
      callee.getName() = "put" or
      callee.getName() = "patch" or
      callee.getName() = "delete" or
      callee.getName() = "head" or
      callee.getName() = "request"
    ) and
    urlArg = c.getArg(0) and
    sink.asExpr() = urlArg
  )
  or
  exists(Call c, Attribute callee, Attribute reqAttr, Name urllibName, Expr urlArg |
    c.getFunc() = callee and
    callee.getName() = "urlopen" and
    reqAttr = callee.getObject().(Attribute) and
    reqAttr.getName() = "request" and
    urllibName = reqAttr.getObject().(Name) and
    urllibName.getId() = "urllib" and
    urlArg = c.getArg(0) and
    sink.asExpr() = urlArg
  )
  or
  exists(Function f, Parameter p |
    (
      (f.getName() = "generate_hunyuan3d_model" and p.getName() = "input_image_url")
      or
      (f.getName() = "import_generated_asset_hunyuan" and p.getName() = "zip_file_url")
    ) and
    sink.asExpr() = p.asName()
  )
}

module MCPToolInputToSSRFSig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isMcpToolInputSource(source) }

  predicate isSink(DataFlow::Node sink) { isOutboundUrlSink(sink) }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof ServerSideRequestForgery::FullUrlControlSanitizer
  }
}

module MCPToolInputToSSRF = TaintTracking::Global<MCPToolInputToSSRFSig>;
import MCPToolInputToSSRF::PathGraph

from
  MCPToolInputToSSRF::PathNode source,
  MCPToolInputToSSRF::PathNode sink,
  string toolName,
  string paramName
where
  MCPToolInputToSSRF::flowPath(source, sink) and
  sourceInfo(source.getNode(), toolName, paramName)
select sink.getNode(), source, sink,
  "Potential SSRF: request URL may be controlled by MCP tool parameter '" + paramName +
  "' in tool '" + toolName + "'."
