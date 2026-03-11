import base64, os, zlib, zipfile, re, io

from utils.pyaes import AESModeOfOperationGCM
from utils.deobfuscation import BlankStage3, BlankStage4


class BlankVariantDetected(Exception):
    """
    Raised when blank.aes is present (confirming this is a Blank grabber variant)
    but the webhook could not be extracted — e.g. unknown key format or modified stub.
    flay.py catches this to log the grabber type without aborting.
    """
    pass


class AuthTag:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv


class BlankDeobf:
    def __init__(self, blankdir, entries):
        self.extractiondir = blankdir
        for entry in entries:
            if 'pyi' not in entry:
                self.entry = entry
        self.tempdir = os.path.join(self.extractiondir, "..", "..", "temp")

    @staticmethod
    def getKeysFromPycFile(filename):
        f = open(filename, "rb")
        data = f.read()
        f.close()
        data = data.split(b"stub-oz,")[-1].split(b"\x63\x03")[0].split(b"\x10")
        key = base64.b64decode(data[0].split(b"\xDA")[0].decode())
        iv = base64.b64decode(data[-1].decode())
        return AuthTag(key, iv)

    @staticmethod
    def _blank_aes_present(directory):
        return os.path.exists(os.path.join(directory, "blank.aes"))

    def Deobfuscate(self):
        stub = None
        blank_aes_found = self._blank_aes_present(self.extractiondir)

        if not self.entry == "main-o.pyc" and not self.entry == "stub-o.pyc":
            stub = "stub-o.pyc"
            filename = None
            try:
                if os.path.exists(os.path.join(self.extractiondir, "loader-o.pyc")):
                    filename = "loader-o.pyc"
                else:
                    for files in os.listdir(self.extractiondir):
                        if re.match(r"([a-f0-9]{8}-[a-f0-9]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[a-f0-9]{12}\.pyc)", files):
                            filename = files
                        if filename:
                            break

                if filename is None:
                    if blank_aes_found:
                        raise BlankVariantDetected("blank.aes found but no loader .pyc — modified Blank variant")
                    raise Exception("No loader file found")

                authtags = BlankDeobf.getKeysFromPycFile(os.path.join(self.extractiondir, filename))
                if len(authtags.key) != 32:
                    if blank_aes_found:
                        raise BlankVariantDetected(f"blank.aes found but AES key length invalid ({len(authtags.key)} bytes)")
                    raise ValueError("Key length is invalid")
                if len(authtags.iv) != 12:
                    if blank_aes_found:
                        raise BlankVariantDetected(f"blank.aes found but IV length invalid ({len(authtags.iv)} bytes)")
                    raise ValueError("IV length is invalid")

                if not blank_aes_found:
                    if blank_aes_found:  # never true but keeps structure clear
                        pass
                    raise Exception("blank.aes not found")

                encryptedfile = open(os.path.join(self.extractiondir, "blank.aes"), "rb").read()
                try:
                    reversedstr = encryptedfile[::-1]
                    encryptedfile = zlib.decompress(reversedstr)
                except zlib.error:
                    pass
                try:
                    decryptedfile = AESModeOfOperationGCM(authtags.key, authtags.iv).decrypt(encryptedfile)
                    with zipfile.ZipFile(io.BytesIO(decryptedfile)) as aeszipe:
                        aeszipe.extractall()
                except (zipfile.BadZipFile, Exception) as e:
                    raise BlankVariantDetected(f"blank.aes found but decryption/extraction failed: {e}")

            except BlankVariantDetected:
                raise  # let flay.py handle it
            except Exception as e:
                if blank_aes_found:
                    raise BlankVariantDetected(f"blank.aes found but extraction failed: {e}")
                raise
        else:
            stub = self.entry

        stub_path = os.path.join(self.extractiondir, stub)
        if not os.path.exists(stub_path):
            if blank_aes_found:
                raise BlankVariantDetected(f"blank.aes found but stub not found: {stub}")
            raise Exception(f"Stub not found: {stub}")

        file = open(stub_path, "rb")
        assembly = file.read()
        file.close()

        try:
            stage3 = BlankStage3(assembly)
            webhook = BlankStage4(stage3)
            if not webhook and blank_aes_found:
                raise BlankVariantDetected("blank.aes found but webhook not recovered from stub")
            return webhook
        except BlankVariantDetected:
            raise
        except Exception as e:
            if blank_aes_found:
                raise BlankVariantDetected(f"blank.aes found but stage3/4 failed: {e}")
            raise
