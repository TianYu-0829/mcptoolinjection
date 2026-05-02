# attacktool
## Scan one project
```bash
./attacktool/start_attacktool.sh "/path/to/your/project"
```
Example:

```bash
./attacktool/start_attacktool.sh "/path/mcpproject"
```
## Scan all projects under one directory

```bash
./attacktool/start_attacktool.sh "/path/database"/*/
```
## Read the output
The terminal prints two sections:
- `[SUMMARY]`: overall counts
- `[DETAIL]`: vulnerability type and triggered tools per server
