#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces CONCAT() function calls with pipe (||) concatenation operator

    Requirement:
        * Oracle
        * PostgreSQL
        * SQLite
        * Firebird
        * H2

    Notes:
        * Useful to bypass WAFs that block CONCAT() function calls
        * Does not work with MySQL (use CONCAT or + instead)

    >>> tamper("CONCAT('foo','bar')")
    "('foo'||'bar')"
    >>> tamper("CONCAT(CONCAT('a','b'),'c')")
    "(('a'||'b')||'c')"
    """

    retVal = payload

    if payload and "CONCAT(" in payload.upper():
        while True:
            match = re.search(r'CONCAT\s*\(', retVal, re.I)
            if not match:
                break

            index = match.start()
            start = match.end()
            depth = 1
            commas = []
            end = None

            for i in range(start, len(retVal)):
                if retVal[i] == '(':
                    depth += 1
                elif retVal[i] == ')':
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
                elif retVal[i] == ',' and depth == 1:
                    commas.append(i)

            if end and len(commas) >= 1:
                # Extract arguments
                args = []
                prev = start
                for c in commas:
                    args.append(retVal[prev:c].strip())
                    prev = c + 1
                args.append(retVal[prev:end].strip())

                # Build pipe concatenation
                replacement = "(" + "||".join(args) + ")"
                retVal = retVal[:index] + replacement + retVal[end + 1:]
            else:
                break

    return retVal
