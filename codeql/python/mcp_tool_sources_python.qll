/**
 * Shared source predicates for Python MCP tool queries.
 */

import python
import semmle.python.dataflow.new.DataFlow

predicate isFastMcpCtor(Expr e) {
  exists(Name n |
    e = n and
    (n.getId() = "FastMCP" or n.getId() = "MCPServer")
  )
  or
  exists(Attribute a |
    e = a and
    (a.getName() = "FastMCP" or a.getName() = "MCPServer")
  )
}

predicate isFastMcpInstanceVar(Variable v) {
  exists(Assign a, Name lhs, Call ctorCall, Expr callee |
    lhs = a.getATarget().(Name) and
    lhs.getVariable() = v and
    ctorCall = a.getValue() and
    callee = ctorCall.getFunc() and
    isFastMcpCtor(callee)
  )
}

predicate isMcpToolDecorator(Expr dec) {
  exists(Attribute attr, Name inst, Variable v |
    dec = attr and
    attr.getName() = "tool" and
    inst = attr.getObject() and
    v = inst.getVariable() and
    isFastMcpInstanceVar(v)
  )
  or
  exists(Call callDec, Attribute attr, Name inst, Variable v |
    dec = callDec and
    attr = callDec.getFunc() and
    attr.getName() = "tool" and
    inst = attr.getObject() and
    v = inst.getVariable() and
    isFastMcpInstanceVar(v)
  )
}

predicate isFastMcpToolFunction(Function f) {
  exists(Expr dec |
    dec = f.getADecorator() and
    isMcpToolDecorator(dec)
  )
}

predicate requiredToolInputParam(Function f, Parameter p) {
  isFastMcpToolFunction(f) and
  (p = f.getAnArg() or p = f.getAKeywordOnlyArg()) and
  not p.isSelf() and
  not p.isVarargs() and
  not p.isKwargs()
}

predicate isRequestParamsArgumentsExpr(Expr e) {
  exists(Attribute argsAttr, Attribute paramsAttr |
    e = argsAttr and
    argsAttr.getName() = "arguments" and
    paramsAttr = argsAttr.getObject().(Attribute) and
    paramsAttr.getName() = "params"
  )
}

predicate isMcpToolInputSource(DataFlow::Node source) {
  exists(Function f, Parameter p |
    requiredToolInputParam(f, p) and
    source.asExpr() = p.asName()
  )
  or
  exists(Expr e |
    isRequestParamsArgumentsExpr(e) and
    source.asExpr() = e
  )
}

predicate sourceInfo(DataFlow::Node src, string toolName, string paramName) {
  exists(Function f, Parameter p |
    requiredToolInputParam(f, p) and
    src.asExpr() = p.asName() and
    toolName = f.getName() and
    paramName = p.getName()
  )
  or
  exists(Expr e |
    isRequestParamsArgumentsExpr(e) and
    src.asExpr() = e and
    toolName = "<rpc-handler>" and
    paramName = "request.params.arguments"
  )
}
