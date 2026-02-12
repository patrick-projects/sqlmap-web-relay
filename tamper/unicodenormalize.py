#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHEST

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Replaces ASCII alpha characters with their fullwidth Unicode counterparts
    (e.g. SELECT -> \uff33\uff25\uff2c\uff25\uff23\uff34)

    Notes:
        * Useful to bypass cloud-based WAFs (Cloudflare, AWS WAF, Azure WAF)
          that match against ASCII SQL keywords but don't normalize Unicode
        * Works when the backend database or application normalizes fullwidth
          Unicode characters to their ASCII equivalents
        * Reference: https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/

    >>> tamper('SELECT 1')
    '\\uff33\\uff25\\uff2c\\uff25\\uff23\\uff34 1'
    """

    retVal = payload

    if payload:
        retVal = ""

        for char in payload:
            if char.isalpha():
                # Convert A-Z (0x41-0x5A) to fullwidth A-Z (0xFF21-0xFF3A)
                # Convert a-z (0x61-0x7A) to fullwidth a-z (0xFF41-0xFF5A)
                code = ord(char)
                if 0x41 <= code <= 0x5A:
                    retVal += chr(0xFF21 + (code - 0x41))
                elif 0x61 <= code <= 0x7A:
                    retVal += chr(0xFF41 + (code - 0x61))
                else:
                    retVal += char
            else:
                retVal += char

    return retVal
