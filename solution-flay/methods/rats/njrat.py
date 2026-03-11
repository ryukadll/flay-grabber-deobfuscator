"""
NjRAT / Bladabindi detector

NjRAT (also known as Bladabindi) is a VB.NET RAT originally created around
2012-2013. It remains one of the most widely distributed RATs globally due
to its simplicity and many publicly available builders.
"""

import struct


# Score +3: unique NjRAT protocol markers
_HIGH = [
    "|'|'|".encode("utf-16-le"),   
    "[endof]".encode("utf-16-le"), 
]

# Score +2: strongly NjRAT-specific
_MEDIUM_ASCII = [
    b"Fransesco",            
    b"CsAntiProcess",        
    b"LORDDecrypt",          
]
_MEDIUM_UTF16 = [s.encode("utf-16-le") for s in [
    "SoftwareMicrosoftWindowsCurrentVersionRun",  
    "SGFjS2Vk",              
    "EnviarPermisaoGerenciador",  
]]

# Score +1: present in NjRAT, not unique enough alone
_LOW_ASCII = [
    b"Stub.exe",             
]
_LOW_UTF16 = [s.encode("utf-16-le") for s in [
    "fransesco",            
    "ctraik",             
    "rss",               
    "kl",                    
    "vn",                    
    "[k]",                  
    "[i]",               
]]

_THRESHOLD = 4


def is_njrat(data: bytes) -> bool:
    if b"BSJB" not in data:
        return False

    score = 0

    for fp in _HIGH:
        if fp in data:
            score += 3
            if score >= _THRESHOLD:
                return True

    for fp in _MEDIUM_ASCII:
        if fp in data:
            score += 2
            if score >= _THRESHOLD:
                return True

    for fp in _MEDIUM_UTF16:
        if fp in data:
            score += 2
            if score >= _THRESHOLD:
                return True

    for fp in _LOW_ASCII:
        if fp in data:
            score += 1

    for fp in _LOW_UTF16:
        if fp in data:
            score += 1


    return score >= _THRESHOLD

