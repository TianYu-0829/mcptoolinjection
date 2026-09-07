/**
 * @name List MCP required tool parameters (Python, generic)
 * @description Finds MCP tools in Python (dictionary schema style and FastMCP decorator style) and extracts required runtime parameters.
 * @kind table
 * @id custom/python/list-mcp-tools-required-params-generic
 * @tags maintainability
 */

import python

predicate dictStringKeyValue(Dict d, string key, Expr value) {
  exists(KeyValuePair kv, StringLiteral k |
    kv = d.getAnItem() and
    k = kv.getKey() and
    k.getText() = key and
    value = kv.getValue()
  )
}

predicate exprResolvesToDict(Expr e, Dict d) {
  d = e
  or
  exists(Name useName, Variable v, Assign a, Name lhs |
    e = useName and
    v = useName.getVariable() and
    lhs = a.getATarget().(Name) and
    lhs.getVariable() = v and
    d = a.getValue().(Dict)
  )
}

predicate exprResolvesToList(Expr e, List l) {
  l = e
  or
  exists(Name useName, Variable v, Assign a, Name lhs |
    e = useName and
    v = useName.getVariable() and
    lhs = a.getATarget().(Name) and
    lhs.getVariable() = v and
    l = a.getValue().(List)
  )
}

predicate isToolLikeDict(Dict d) {
  exists(Expr nameExpr | dictStringKeyValue(d, "name", nameExpr)) and
  exists(Expr schemaExpr | dictStringKeyValue(d, "inputSchema", schemaExpr))
}

predicate fileLooksLikeMcpRpc(File f) {
  exists(StringLiteral s |
    s.getLocation().getFile() = f and
    (s.getText() = "tools/list" or s.getText() = "tools/call")
  )
}

predicate isInToolsPayload(Dict toolDict) {
  exists(Dict payload, Expr toolsExpr, List toolsList |
    dictStringKeyValue(payload, "tools", toolsExpr) and
    exprResolvesToList(toolsExpr, toolsList) and
    toolDict = toolsList.getAnElt().(Dict)
  )
}

predicate toolSchemaDict(Dict toolDict, Dict schemaDict) {
  exists(Expr schemaExpr |
    dictStringKeyValue(toolDict, "inputSchema", schemaExpr) and
    exprResolvesToDict(schemaExpr, schemaDict)
  )
}

predicate parameterOfTool(Dict toolDict, string paramName) {
  exists(Dict schemaDict, Expr propsExpr, Dict propsDict, KeyValuePair paramKv, StringLiteral paramKey |
    toolSchemaDict(toolDict, schemaDict) and
    dictStringKeyValue(schemaDict, "properties", propsExpr) and
    exprResolvesToDict(propsExpr, propsDict) and
    paramKv = propsDict.getAnItem() and
    paramKey = paramKv.getKey() and
    paramName = paramKey.getText()
  )
}

predicate requiredParam(Dict toolDict, string paramName) {
  exists(Dict schemaDict, Expr requiredExpr, List requiredList, StringLiteral requiredName |
    toolSchemaDict(toolDict, schemaDict) and
    dictStringKeyValue(schemaDict, "required", requiredExpr) and
    exprResolvesToList(requiredExpr, requiredList) and
    requiredName = requiredList.getAnElt() and
    paramName = requiredName.getText()
  )
}

predicate hasNoRequiredParameters(Dict toolDict) {
  not exists(string paramName |
    parameterOfTool(toolDict, paramName) and
    requiredParam(toolDict, paramName)
  )
}

predicate toolNameOf(Dict toolDict, string toolName) {
  exists(StringLiteral nameLit, Expr nameExpr |
    dictStringKeyValue(toolDict, "name", nameExpr) and
    nameLit = nameExpr and
    toolName = nameLit.getText()
  )
}

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

predicate requiredDecoratorParam(Function f, Parameter p, string paramName) {
  (p = f.getAnArg() or p = f.getAKeywordOnlyArg()) and
  not p.isSelf() and
  not p.isVarargs() and
  not p.isKwargs() and
  not exists(p.getDefault()) and
  paramName = p.getName()
}

predicate hasNoRequiredDecoratorParams(Function f) {
  not exists(Parameter p, string paramName |
    requiredDecoratorParam(f, p, paramName)
  )
}

predicate toolRequiredParam(string toolName, string paramName, File f) {
  exists(Dict toolDict |
    isToolLikeDict(toolDict) and
    isInToolsPayload(toolDict) and
    toolNameOf(toolDict, toolName) and
    f = toolDict.getLocation().getFile() and
    fileLooksLikeMcpRpc(f) and
    (
      exists(string p |
        parameterOfTool(toolDict, p) and
        requiredParam(toolDict, p) and
        paramName = p
      )
      or
      hasNoRequiredParameters(toolDict) and
      paramName = "<none>"
    )
  )
  or
  exists(Function ftool, Parameter p |
    isFastMcpToolFunction(ftool) and
    toolName = ftool.getName() and
    f = ftool.getLocation().getFile() and
    requiredDecoratorParam(ftool, p, paramName)
  )
  or
  exists(Function ftool |
    isFastMcpToolFunction(ftool) and
    toolName = ftool.getName() and
    f = ftool.getLocation().getFile() and
    hasNoRequiredDecoratorParams(ftool) and
    paramName = "<none>"
  )
}

from string toolName, string paramName, File f
where toolRequiredParam(toolName, paramName, f)
select "MCP tool: " + toolName + " | required param: " + paramName +
  " (file: " + f.getRelativePath() + ")"
