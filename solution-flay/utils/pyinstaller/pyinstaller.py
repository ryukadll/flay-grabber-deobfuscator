from utils.pyinstaller.pyinstallerExceptions import ExtractionError


def ExtractPYInstaller(filename: str):
    from utils.pyinstaller.extractors.pyinstxtractor import PyInstArchive

    arch = None

    # -- Try the standard extractor first (no external crypto dependency) -----
    try:
        arch = PyInstArchive(filename)
        if arch.open() and arch.checkFile() and arch.getCArchiveInfo():
            arch.parseTOC()
            arch.extractFiles()
            arch.close()
            return arch
        arch.close()
    except Exception:
        if arch:
            try: arch.close()
            except Exception: pass

    # -- Fall back to the NG extractor (requires pycryptodome) ----------------
    try:
        from utils.pyinstaller.extractors.pyinstxtractorng import PyInstArchive as PyInstArchiveNG
        arch = PyInstArchiveNG(filename)
        if arch.open() and arch.checkFile() and arch.getCArchiveInfo():
            arch.parseTOC()
            arch.extractFiles()
            arch.close()
            return arch
        arch.close()
    except ImportError:
        pass  # pycryptodome not installed — skip NG extractor
    except Exception:
        if arch:
            try: arch.close()
            except Exception: pass

    raise ExtractionError("Not a PyInstaller archive or extraction failed.")
