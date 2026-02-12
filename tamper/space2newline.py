#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import random

from lib.core.compat import xrange
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces (MySQL) instances of space character (' ') with a random
    combination of newline and tab characters

    Requirement:
        * MySQL
        * PostgreSQL
        * Microsoft SQL Server

    Notes:
        * Useful for bypassing WAFs that don't account for alternate
          whitespace characters in SQL keyword tokenization
        * Many cloud WAFs (AWS WAF, Cloudflare) split on spaces but
          not on other whitespace

    >>> random.seed(0)
    >>> tamper('SELECT id FROM users')  # doctest: +SKIP
    'SELECT\\nid\\tFROM\\nusers'
    """

    WHITESPACE_ALTERNATIVES = ('\n', '\r', '\t', '\n\r', '\r\n')

    retVal = payload

    if payload:
        retVal = ""
        quote, doublequote, firstspace = False, False, False

        for i in xrange(len(payload)):
            if not firstspace:
                if payload[i].isspace():
                    firstspace = True
                    retVal += random.choice(WHITESPACE_ALTERNATIVES)
                    continue

            elif payload[i] == '\'':
                quote = not quote

            elif payload[i] == '"':
                doublequote = not doublequote

            elif payload[i] == ' ' and not quote and not doublequote:
                retVal += random.choice(WHITESPACE_ALTERNATIVES)
                continue

            retVal += payload[i]

    return retVal
