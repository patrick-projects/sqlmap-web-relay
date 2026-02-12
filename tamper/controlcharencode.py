#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import random

from lib.core.compat import xrange
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Inserts zero-width and control characters between SQL keywords to
    bypass pattern-matching WAFs

    Notes:
        * Useful for bypassing cloud WAFs (AWS WAF, Cloudflare) that
          use regex-based keyword matching without Unicode-aware
          tokenization
        * Uses Unicode zero-width characters (U+200B zero-width space,
          U+200C zero-width non-joiner, U+200D zero-width joiner,
          U+FEFF zero-width no-break space) that many SQL parsers ignore
        * Reference: https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf

    >>> len(tamper('SELECT')) > len('SELECT')
    True
    """

    ZERO_WIDTH_CHARS = (
        '\u200b',  # Zero-width space
        '\u200c',  # Zero-width non-joiner
        '\u200d',  # Zero-width joiner
        '\ufeff',  # Zero-width no-break space
    )

    SQL_KEYWORDS = (
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'UNION', 'FROM',
        'WHERE', 'AND', 'OR', 'ORDER', 'GROUP', 'HAVING', 'LIMIT',
        'CONCAT', 'SUBSTRING', 'CAST', 'CONVERT', 'CHAR', 'ASCII',
        'SLEEP', 'BENCHMARK', 'WAITFOR', 'DELAY', 'EXEC', 'EXECUTE',
        'DROP', 'ALTER', 'CREATE', 'TABLE', 'INTO', 'VALUES',
        'INFORMATION_SCHEMA', 'EXTRACTVALUE', 'UPDATEXML',
    )

    retVal = payload

    if payload:
        for keyword in SQL_KEYWORDS:
            # Case-insensitive search for the keyword
            upper = payload.upper()
            idx = 0
            new_payload = ""
            last = 0

            while idx <= len(upper) - len(keyword):
                if upper[idx:idx + len(keyword)] == keyword:
                    # Check it's a whole word
                    before_ok = (idx == 0 or not upper[idx - 1].isalnum())
                    after_ok = (idx + len(keyword) >= len(upper) or not upper[idx + len(keyword)].isalnum())

                    if before_ok and after_ok:
                        new_payload += retVal[last:idx]
                        # Insert zero-width char after first character of keyword
                        original_word = retVal[idx:idx + len(keyword)]
                        insert_pos = random.randint(1, len(keyword) - 1) if len(keyword) > 1 else 0
                        zwc = random.choice(ZERO_WIDTH_CHARS)
                        modified_word = original_word[:insert_pos] + zwc + original_word[insert_pos:]
                        new_payload += modified_word
                        last = idx + len(keyword)
                        idx = last
                        continue

                idx += 1

            new_payload += retVal[last:]
            retVal = new_payload

    return retVal
