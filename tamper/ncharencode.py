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
    Replaces string literals with NCHAR() concatenation for SQL Server

    Requirement:
        * Microsoft SQL Server

    Notes:
        * Useful to bypass WAFs that block common SQL keywords in string
          literals (e.g. 'admin' becomes NCHAR(97)+NCHAR(100)+NCHAR(109)+...)
        * Reference: https://learn.microsoft.com/en-us/sql/t-sql/functions/nchar-transact-sql

    >>> tamper("SELECT 'admin'")
    "SELECT NCHAR(97)+NCHAR(100)+NCHAR(109)+NCHAR(105)+NCHAR(110)"
    """

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        while i < len(payload):
            if payload[i] == '\'' and i + 1 < len(payload):
                # Find the closing quote
                j = payload.index('\'', i + 1) if '\'' in payload[i + 1:] else -1
                if j > i:
                    string_content = payload[i + 1:j]
                    if string_content:
                        nchar_parts = [("NCHAR(%d)" % ord(c)) for c in string_content]
                        retVal += "+".join(nchar_parts)
                    else:
                        retVal += "''"
                    i = j + 1
                    continue
                else:
                    retVal += payload[i]
            else:
                retVal += payload[i]

            i += 1

    return retVal
