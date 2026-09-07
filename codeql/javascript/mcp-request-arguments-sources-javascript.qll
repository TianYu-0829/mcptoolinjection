/**
 * Shared source predicates for JavaScript MCP queries.
 */

import javascript
import semmle.javascript.dataflow.DataFlow

predicate isRequestParamsArgumentsExpr(Expr e) {
  exists(PropAccess argsProp, PropAccess paramsProp, VarAccess req |
    e = argsProp and
    argsProp.getPropertyName() = "arguments" and
    paramsProp = argsProp.getBase() and
    paramsProp.getPropertyName() = "params" and
    req = paramsProp.getBase() and
    req.getName() = "request"
  )
}

predicate isMcpRequestArgumentsSource(DataFlow::Node source) {
  exists(Expr e |
    isRequestParamsArgumentsExpr(e) and
    source.asExpr() = e
  )
}
