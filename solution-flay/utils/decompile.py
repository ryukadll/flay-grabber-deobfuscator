import subprocess, sys, zipfile, re
from os import path, makedirs

PYCDC = "pycdc.exe" if sys.platform == 'win32' else "pycdc"
PYCDAS = "pycdas.exe" if sys.platform == 'win32' else "pycdas"
UPX = "upx.exe" if sys.platform == 'win32' else "upx"

dir = path.join(path.dirname(__file__))

def checkUPX(filename):
    res = subprocess.run([path.join(dir, "bin", UPX), "-l", filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if "not packed" not in res.stderr.decode():
        res = subprocess.run([path.join(dir, "bin", UPX), "-d", filename], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if "Unpacked" in res.stdout.decode():
            return True
        else:
            print("[!] UPX was detected but failed to decompress")
    return False

def decompilePyc(filename):
    res = subprocess.run([path.join(dir, "bin", PYCDC), filename], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return res.stdout.decode()


def disassemblePyc(filename):
    res = subprocess.run([path.join(dir, "bin", PYCDAS), filename], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return res.stdout.decode()


def unzipJava(filename):
    if ".jar" not in filename:
        raise ValueError("Not a jar file")
    outdir = path.join(dir, "..", "temp", filename.split(path.sep)[len(filename.split(path.sep)) - 1].split(".")[0])
    if not path.exists(outdir):
        makedirs(outdir)
    with zipfile.ZipFile(filename) as f:
        f.extractall(outdir)
    return outdir


def strings(bytestring: bytes) -> str:
    """
    Extract printable strings from raw bytes.
    Splits on non-printable bytes so adjacent strings don't bleed together.
    Each chunk is joined with a space so regexes see clean boundaries.
    """
    chunks = re.findall(rb"[\x20-\x7e]{4,}", bytestring)
    return " ".join(c.decode(errors="ignore") for c in chunks)


def consts_from_pyc(filepath: str) -> list:
    """
    Load a .pyc file and recursively extract all string constants from
    co_consts. This is the cleanest way to get token/webhook strings
    without any surrounding marshal type-code bytes bleeding in.
    Returns a flat list of strings.
    """
    import marshal as _marshal

    def _walk(code_obj):
        results = []
        for c in code_obj.co_consts:
            if isinstance(c, str) and len(c) > 8:
                results.append(c)
            elif hasattr(c, "co_consts"):
                results.extend(_walk(c))
        return results

    try:
        with open(filepath, "rb") as f:
            data = f.read()
        # skip the pyc header (16 bytes for Python 3.8+)
        for offset in (16, 12, 8):
            try:
                code = _marshal.loads(data[offset:])
                return _walk(code)
            except Exception:
                continue
    except Exception:
        pass
    return []