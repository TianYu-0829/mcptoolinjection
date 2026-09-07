/**
 * @name List MCP required tool parameters (JavaScript, generic)
 * @description Finds MCP tool-like objects and extracts required top-level inputSchema parameters in JavaScript/TypeScript.
 * @kind table
 * @id custom/js/list-mcp-tools-required-params-generic
 * @tags maintainability
 */

import javascript

predicate isToolLikeObject(ObjectExpr obj) {
  exists(Property p | p = obj.getAProperty() and p.getName() = "name") and
  exists(Property p | p = obj.getAProperty() and p.getName() = "inputSchema")
}

predicate fileLooksLikeMcpRpc(File f) {
  exists(StringLiteral s |
    s.getTopLevel().getFile() = f and
    (s.getValue() = "tools/list" or s.getValue() = "tools/call")
  )
}

predicate exprResolvesToObject(Expr e, ObjectExpr obj) {
  obj = e or
  exists(VarAccess va, Variable v |
    e = va and
    v = va.getVariable() and
    obj = v.getAnAssignedExpr().(ObjectExpr)
  )
}

predicate exprResolvesToArray(Expr e, ArrayExpr arr) {
  arr = e or
  exists(VarAccess va, Variable v |
    e = va and
    v = va.getVariable() and
    arr = v.getAnAssignedExpr().(ArrayExpr)
  )
}

predicate isInToolsPayload(ObjectExpr toolObj) {
  exists(ObjectExpr payload, Property toolsProp, Expr toolsExpr, ArrayExpr arr |
    toolsProp = payload.getAProperty() and
    toolsProp.getName() = "tools" and
    toolsExpr = toolsProp.getInit() and
    (
      arr = toolsExpr and
      toolObj = arr.getAnElement().(ObjectExpr)
      or
      exists(VarAccess va, Variable v |
        toolsExpr = va and
        v = va.getVariable() and
        arr = v.getAnAssignedExpr() and
        toolObj = arr.getAnElement().(ObjectExpr)
      )
    )
  )
}

predicate toolSchemaObject(ObjectExpr toolObj, ObjectExpr schemaObj) {
  exists(Property schemaProp, Expr schemaExpr |
    schemaProp = toolObj.getAProperty() and
    schemaProp.getName() = "inputSchema" and
    schemaExpr = schemaProp.getInit() and
    exprResolvesToObject(schemaExpr, schemaObj)
  )
}

predicate parameterOfTool(ObjectExpr toolObj, string paramName) {
  exists(ObjectExpr schemaObj, Property propsProp, Expr propsExpr, ObjectExpr propsObj, Property paramProp |
    toolSchemaObject(toolObj, schemaObj) and
    propsProp = schemaObj.getAProperty() and
    propsProp.getName() = "properties" and
    propsExpr = propsProp.getInit() and
    exprResolvesToObject(propsExpr, propsObj) and
    paramProp = propsObj.getAProperty() and
    paramName = paramProp.getName()
  )
}

predicate requiredParam(ObjectExpr toolObj, string paramName) {
  exists(
    ObjectExpr schemaObj, Property requiredProp, Expr requiredExpr, ArrayExpr requiredArr, Expr el |
    toolSchemaObject(toolObj, schemaObj) and
    requiredProp = schemaObj.getAProperty() and
    requiredProp.getName() = "required" and
    requiredExpr = requiredProp.getInit() and
    exprResolvesToArray(requiredExpr, requiredArr) and
    el = requiredArr.getAnElement() and
    el.getStringValue() = paramName
  )
}

predicate hasNoRequiredParameters(ObjectExpr toolObj) {
  not exists(string paramName |
    parameterOfTool(toolObj, paramName) and
    requiredParam(toolObj, paramName)
  )
}

from
  ObjectExpr toolObj,
  Property nameProp,
  string toolName,
  string paramName,
  File f
where
  isToolLikeObject(toolObj) and
  isInToolsPayload(toolObj) and
  nameProp = toolObj.getAProperty() and
  nameProp.getName() = "name" and
  toolName = nameProp.getInit().getStringValue() and
  f = toolObj.getTopLevel().getFile() and
  fileLooksLikeMcpRpc(f) and
  (
    exists(string p |
      parameterOfTool(toolObj, p) and
      requiredParam(toolObj, p) and
      paramName = p
    )
    or
    hasNoRequiredParameters(toolObj) and
    paramName = "<none>"
  )
select "MCP tool: " + toolName + " | required param: " + paramName +
  " (file: " + f.getRelativePath() + ")"
