import os
import tempfile

# Testovi koriste privremenu SQLite bazu i lažne ključeve; pravi API-ji se ne zovu (respx).
_tmp = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["ABUSEIPDB_API_KEY"] = "test-abuse"
os.environ["VIRUSTOTAL_API_KEY"] = "test-vt"
