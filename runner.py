"""Verified explicit FTPS runner for Nautec; credentials come only from secrets."""
import argparse
import datetime as dt
import ftplib
import hashlib
import io
import json
import os
import re
import ssl
import sys
import urllib.request
from pathlib import Path

MAX_BYTES = 25_000_000

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("receiver_redirect_refused")

def pinned_fingerprint():
    value = os.environ.get("NAUTEC_FTP_CERT_SHA256", "").replace(":", "").strip().lower()
    if value and (len(value) != 64 or any(c not in "0123456789abcdef" for c in value)):
        raise ValueError("invalid_pinned_fingerprint")
    return value or None

def tls_context():
    context = ssl.create_default_context()
    if pinned_fingerprint():
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context

def check_pin(sock):
    pin = pinned_fingerprint()
    if not pin:
        return
    der = sock.getpeercert(binary_form=True)
    if not der or hashlib.sha256(der).hexdigest() != pin:
        raise ssl.SSLCertVerificationError("pinned_certificate_mismatch")

class VerifiedFTP(ftplib.FTP_TLS):
    def connect_verified(self):
        self.connect(os.environ["NAUTEC_FTP_HOST"], int(os.environ.get("NAUTEC_FTP_PORT", "21")))
        self.host = os.environ.get("NAUTEC_FTP_TLS_SERVER_NAME", "web1.palby.dk")
        self.auth()
        check_pin(self.sock)
        self.login(os.environ["NAUTEC_FTP_USER"], os.environ["NAUTEC_FTP_PASSWORD"])
        self.prot_p()
        self.cwd(os.environ.get("NAUTEC_FTP_DIRECTORY", "/"))

    def ntransfercmd(self, cmd, rest=None):
        conn, size = super().ntransfercmd(cmd, rest)
        try:
            check_pin(conn)
        except Exception:
            conn.close()
            raise
        return conn, size

def download(ftp, name, before):
    if "/" in name or "\\" in name or name in (".", ".."):
        raise ValueError("invalid_file_name")
    content = io.BytesIO()
    def write(chunk):
        if content.tell() + len(chunk) > MAX_BYTES:
            raise ValueError("file_too_large")
        content.write(chunk)
    ftp.retrbinary("RETR " + name, write)
    after = dict(ftp.mlsd()).get(name)
    if not after or before.get("size") != after.get("size") or before.get("modify") != after.get("modify"):
        raise ValueError("file_changed_during_download")
    return content.getvalue().decode("utf-8-sig")

def send_batch(batch):
    url = os.environ["NAUTEC_IMPORT_URL"]
    if not url.startswith("https://"):
        raise ValueError("https_required")
    body = json.dumps(batch, ensure_ascii=False).encode()
    if len(body) > 30_000_000:
        raise ValueError("batch_too_large")
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Authorization": "Bearer " + os.environ["NAUTEC_IMPORT_TOKEN"],
        "Content-Type": "application/json",
    })
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=120) as response:
        result = json.load(response)
    if not result.get("ok"):
        raise ValueError("import_not_acknowledged")

def verified_manifest(path):
    config = json.loads(Path(path).read_text())
    if config.get("provider_confirmed") is not True:
        raise ValueError("manifest_not_provider_confirmed")
    for group in config["batches"]:
        stamp = dt.datetime.fromisoformat(group["sourceTimestamp"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("explicit_timezone_required")
        if group["kind"] not in ("catalogue", "stock_full", "stock_delta"):
            raise ValueError("unsupported_feed_price_format_unverified")
        if not group["expectedFiles"] or len(set(group["expectedFiles"])) != len(group["expectedFiles"]):
            raise ValueError("incomplete_manifest")
    return sorted(config["batches"], key=lambda b: (dt.datetime.fromisoformat(b["sourceTimestamp"].replace("Z", "+00:00")), 0 if b["kind"] == "catalogue" else 1))

CATALOGUE_DIR = "/web_cataloginventitem_sv"
CATALOGUE_RE = re.compile(r"^web_cataloginventitems_sv_(\d+)\.xml$")
STOCK_FULL_DIR = "/web_stockstatus_full"
STOCK_FULL_NAME = "web_stockstatus_newitemid.xml"
STOCK_DELTA_DIR = "/web_stockstatus_delta"
STOCK_DELTA_RE = re.compile(r"^web_stockstatus_newitemid_delta_(\d{14})\.xml$")
CATALOGUE_CHUNK = 2
DELTA_CAP = 200

def mlsd_files(ftp, directory):
    ftp.cwd(directory)
    return {name: facts for name, facts in ftp.mlsd() if facts.get("type") == "file"}

def iso_from_modify(facts):
    stamp = dt.datetime.strptime(facts["modify"], "%Y%m%d%H%M%S").replace(tzinfo=dt.timezone.utc)
    return stamp.isoformat().replace("+00:00", "Z")

def fetch_cursor():
    url = os.environ["NAUTEC_IMPORT_URL"]
    if not url.startswith("https://"):
        raise ValueError("https_required")
    request = urllib.request.Request(url, method="GET", headers={"Authorization": "Bearer " + os.environ["NAUTEC_IMPORT_TOKEN"]})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
        result = json.load(response)
    if not result.get("ok"):
        raise ValueError("cursor_not_acknowledged")
    return result

def send_files(ftp, listing, batch):
    names = batch["expectedFiles"]
    if not all(name in listing for name in names):
        raise ValueError("missing_file")
    payload = {**batch, "files": [{"name": name, "xml": download(ftp, name, listing[name])} for name in names]}
    final_listing = mlsd_files(ftp, STOCK_DELTA_DIR if batch["kind"] == "stock_delta" else (STOCK_FULL_DIR if batch["kind"] == "stock_full" else CATALOGUE_DIR))
    if any(name not in final_listing or any(listing[name].get(k) != final_listing[name].get(k) for k in ("size", "modify")) for name in names):
        raise ValueError("catalogue_snapshot_changed")
    send_batch(payload)
    print("Import acknowledged:", batch["batchKey"])

def auto_catalogue(ftp):
    listing = mlsd_files(ftp, CATALOGUE_DIR)
    names = sorted((n for n in listing if CATALOGUE_RE.match(n)), key=lambda n: int(CATALOGUE_RE.match(n).group(1)))
    if not names:
        raise ValueError("missing_file")
    stamp = max(iso_from_modify(listing[n]) for n in names)
    day = stamp[:10].replace("-", "")
    chunks = [names[i:i + CATALOGUE_CHUNK] for i in range(0, len(names), CATALOGUE_CHUNK)]
    for index, chunk in enumerate(chunks):
        send_files(ftp, listing, {"kind": "catalogue", "sourceTimestamp": stamp, "batchKey": "catalogue-%s-part%d" % (day, index + 1), "expectedFiles": chunk, "partial": index < len(chunks) - 1})

def auto_stock_full(ftp):
    listing = mlsd_files(ftp, STOCK_FULL_DIR)
    if STOCK_FULL_NAME not in listing:
        raise ValueError("missing_file")
    stamp = iso_from_modify(listing[STOCK_FULL_NAME])
    cursor = fetch_cursor().get("stock")
    if cursor and dt.datetime.fromisoformat(stamp.replace("Z", "+00:00")) <= dt.datetime.fromisoformat(cursor.replace("Z", "+00:00")):
        print("Full stock snapshot already covered; keeping newer stock.")
        return cursor
    send_files(ftp, listing, {"kind": "stock_full", "sourceTimestamp": stamp, "batchKey": "stock-full-" + stamp[:10].replace("-", ""), "expectedFiles": [STOCK_FULL_NAME]})
    return stamp

def auto_stock(ftp):
    cursor = fetch_cursor().get("stock")
    if cursor is None:
        cursor = auto_stock_full(ftp)
    cursor_dt = dt.datetime.fromisoformat(cursor.replace("Z", "+00:00"))
    listing = mlsd_files(ftp, STOCK_DELTA_DIR)
    deltas = []
    for name in listing:
        match = STOCK_DELTA_RE.match(name)
        if not match:
            continue
        stamp = dt.datetime.strptime(match.group(1), "%Y%m%d%H%M%S").replace(tzinfo=dt.timezone.utc)
        if stamp > cursor_dt:
            deltas.append((stamp, name))
    deltas.sort()
    for stamp, name in deltas[:DELTA_CAP]:
        send_files(ftp, listing, {"kind": "stock_delta", "sourceTimestamp": stamp.isoformat().replace("+00:00", "Z"), "batchKey": name[:-4], "expectedFiles": [name]})
    if len(deltas) > DELTA_CAP:
        print("More deltas remain; the next run continues.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest")
    parser.add_argument("--discover", action="store_true")
    parser.add_argument("--auto", choices=["catalogue", "stock", "stock_full"])
    args = parser.parse_args()
    with VerifiedFTP(context=tls_context(), timeout=30) as ftp:
        ftp.connect_verified()
        if args.auto == "catalogue":
            auto_catalogue(ftp)
            return
        if args.auto == "stock":
            auto_stock(ftp)
            return
        if args.auto == "stock_full":
            auto_stock_full(ftp)
            return
        listing = {name: facts for name, facts in ftp.mlsd() if facts.get("type") == "file"}
        if args.discover:
            print(json.dumps([{"name": n, "size": f.get("size"), "modifiedUtc": f.get("modify")} for n, f in listing.items()]))
            return
        if not args.manifest:
            raise ValueError("verified_manifest_required")
        for batch in verified_manifest(args.manifest):
            names = batch["expectedFiles"]
            if not all(name in listing for name in names):
                raise ValueError("missing_file")
            payload = {**batch, "files": [{"name": name, "xml": download(ftp, name, listing[name])} for name in names]}
            final_listing = dict(ftp.mlsd())
            if any(name not in final_listing or any(listing[name].get(k) != final_listing[name].get(k) for k in ("size", "modify")) for name in names):
                raise ValueError("catalogue_snapshot_changed")
            send_batch(payload)
            print("Import acknowledged")

if __name__ == "__main__":
    try:
        main()
    except ssl.SSLCertVerificationError:
        print("FTPS certificate verification failed; no insecure fallback used", file=sys.stderr)
        sys.exit(2)
    except Exception:
        print("Sync stopped; verify transport, manifest and receiver status", file=sys.stderr)
        sys.exit(1)
