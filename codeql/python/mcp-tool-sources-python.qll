/**
 * Shared source predicates for Python MCP tool queries.
 */

import python
import semmle.python.dataflow.new.DataFlow

predicate isFastMcpCtor(Expr e) {
  exists(Name n |
    e = n and
    n.getId() = "FastMCP"
  )
  or
  exists(Attribute a |
    e = a and
    a.getName() = "FastMCP"
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
  not p.isKwargs() and
  not exists(p.getDefault())
}

predicate isMcpToolInputSource(DataFlow::Node source) {
  exists(Function f, Parameter p |
    requiredToolInputParam(f, p) and
    source.asExpr() = p.asName()
  )
}

predicate sourceInfo(DataFlow::Node src, string toolName, string paramName) {
  exists(Function f, Parameter p |
    requiredToolInputParam(f, p) and
    src.asExpr() = p.asName() and
    toolName = f.getName() and
    paramName = p.getName()
  )
}
