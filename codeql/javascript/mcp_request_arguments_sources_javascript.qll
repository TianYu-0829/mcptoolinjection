/**
 * Shared source predicates for JavaScript MCP queries.
 */

import javascript
import semmle.javascript.dataflow.DataFlow

predicate isRequestParamsArgumentsExpr(Expr e) {
  exists(PropAccess argsProp, PropAccess paramsProp |
    e = argsProp and
    argsProp.getPropertyName() = "arguments" and
    paramsProp = argsProp.getBase() and
    paramsProp.getPropertyName() = "params"
  )
  or
  exists(PropAccess argsProp, VarAccess base |
    e = argsProp and
    argsProp.getPropertyName() = "arguments" and
    base = argsProp.getBase() and
    base.getName() = "params"
  )
}

predicate isToolRegistrationCallback(Function f) {
  exists(CallExpr c, PropAccess callee |
    c.getCallee() = callee and
    (callee.getPropertyName() = "tool" or callee.getPropertyName() = "registerTool") and
    f = c.getArgument(c.getNumArgument() - 1).(Function)
  )
}

predicate isCallToolHandlerCallback(Function f) {
  exists(CallExpr c, PropAccess callee |
    c.getCallee() = callee and
    callee.getPropertyName() = "setRequestHandler" and
    f = c.getArgument(c.getNumArgument() - 1).(Function)
  )
}

predicate isMcpRequestArgumentsSource(DataFlow::Node source) {
  exists(Expr e |
    isRequestParamsArgumentsExpr(e) and
    source.asExpr() = e
  )
  or
  exists(PropAccess p, VarAccess base |
    base = p.getBase() and
    base.getName() = "parsed" and
    source.asExpr() = p
  )
  or
  exists(Function f, Parameter p |
    (isToolRegistrationCallback(f) or isCallToolHandlerCallback(f)) and
    p = f.getAParameter() and
    source = DataFlow::parameterNode(p)
  )
}
