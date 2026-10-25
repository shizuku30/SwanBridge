import gzip
import hashlib
import json
import sys
import tarfile
from pathlib import Path

archive = Path(sys.argv[1])
expected = {
    "root/swanbridge-build/rootfs/work/signing/private-key.pem",
    "root/swanbridge-deploy/backup/etc/config/network",
    "root/swanbridge-deploy/backup/etc/config/firewall",
    "etc/config/ipsec",
    "etc/apk/keys/swanbridge-25.12.pem",
}
found = set()
members = files = payload_bytes = 0
with tarfile.open(archive, "r|gz") as source:
    for member in source:
        name = member.name.rstrip("/")
        if name.startswith("/") or ".." in name.split("/"):
            raise ValueError("Unsafe archive member path")
        members += 1
        if name in expected:
            found.add(name)
        if member.isfile():
            files += 1
            with source.extractfile(member) as data:
                size = 0
                while chunk := data.read(1024 * 1024):
                    size += len(chunk)
            if size != member.size:
                raise ValueError("Truncated archive member")
            payload_bytes += size
if found != expected or files < 1000:
    raise ValueError("Migration archive is missing required contents")
# Read to the gzip trailer as well; tar readers can stop before its CRC is checked.
with gzip.open(archive, "rb") as data:
    while data.read(4 * 1024 * 1024):
        pass
with archive.open("rb") as data:
    digest = hashlib.file_digest(data, "sha256").hexdigest()
result = {"Verified": True, "Archive": str(archive.resolve()), "SHA256": digest,
          "Members": members, "RegularFiles": files, "PayloadBytes": payload_bytes,
          "RequiredContentsPresent": True}
archive.with_name("verification.json").write_text(json.dumps(result, indent=2), encoding="ascii")
print(json.dumps(result, indent=2))
