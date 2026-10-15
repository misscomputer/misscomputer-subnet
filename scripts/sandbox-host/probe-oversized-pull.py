#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Record what the real dedicated dockerd emits for an oversized registry error.

Independent of the backend: serves, on 127.0.0.1, a registry with a valid
manifest whose every blob request answers 418 with a 600 KiB text/plain
body (the same shape as the backend's
TestEnginePullOversizedRegistryErrorOnDisposableHost). It asks the dedicated
daemon for POST /images/create over its unix socket and records the raw
answer: the HTTP status, the total bytes, the number and longest length of
progress lines, whether any line carries the registry body, and how many blob
requests the registry saw. The engine slice's egress table rejects loopback,
so the caller must open a scoped exception first. Runs as root on the
disposable host only.

  probe-oversized-pull.py PROFILE OUT
"""

from __future__ import annotations

import hashlib
import http.client
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import quote


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


CONFIG = b'{"architecture":"amd64","os":"linux"}'
LAYER = b"layer that is never served"
MANIFEST = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(CONFIG),
            "digest": digest(CONFIG),
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(LAYER),
                "digest": digest(LAYER),
            }
        ],
    }
).encode()
BODY = b"unknown: " + b"A" * (600 << 10)


class Registry(BaseHTTPRequestHandler):
    blob_requests = 0

    def log_message(self, *_args: Any) -> None:  # keep the job log readable
        return

    protocol_version = "HTTP/1.1"

    def _answer(self, head: bool) -> None:
        status, headers, body = 404, {}, b""
        if self.path == "/v2/":
            status = 200
        elif self.path.startswith("/v2/lane2/oversized/manifests/"):
            status, body = 200, MANIFEST
            headers = {
                "Content-Type": "application/vnd.docker.distribution.manifest.v2+json",
                "Docker-Content-Digest": digest(MANIFEST),
            }
        elif self.path.startswith("/v2/lane2/oversized/blobs/"):
            Registry.blob_requests += 1
            status, body, headers = 418, BODY, {"Content-Type": "text/plain"}
        self.send_response_only(status)
        self.send_header("Docker-Distribution-API-Version", "registry/2.0")
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        self._answer(head=False)

    def do_HEAD(self) -> None:  # noqa: N802 (http.server API)
        self._answer(head=True)


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str) -> None:
        super().__init__("localhost", timeout=300)
        self.unix_path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(300)
        self.sock.connect(self.unix_path)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as handle:
        profile = json.load(handle)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Registry)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    repository = f"127.0.0.1:{server.server_address[1]}/lane2/oversized"
    connection = UnixConnection(profile["docker_host"].removeprefix("unix://"))
    query = f"fromImage={quote(repository, safe='')}&tag={quote(digest(MANIFEST), safe='')}"
    path = "/images/create?" + query
    connection.request("POST", path, headers={"Content-Length": "0"})
    response = connection.getresponse()
    raw = response.read()
    server.shutdown()
    lines = raw.split(b"\n")
    longest = max(lines, key=len) if lines else b""
    carrying = [len(line) for line in lines if b"unknown: AAAA" in line]
    record = {
        "repository": repository,
        "manifest_digest": digest(MANIFEST),
        "registry_body_bytes": len(BODY),
        "blob_requests": Registry.blob_requests,
        "http_status": response.status,
        "content_type": response.getheader("Content-Type"),
        "response_bytes": len(raw),
        "progress_lines": len([line for line in lines if line.strip()]),
        "longest_line_bytes": len(longest),
        "lines_carrying_registry_body": carrying,
        "longest_line_prefix": longest[:160].decode(errors="replace"),
        "error_detail_present": b'"errorDetail"' in raw,
    }
    with open(argv[1], "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
    print(
        json.dumps({k: v for k, v in record.items() if k != "longest_line_prefix"}, sort_keys=True)
    )
    print("longest line starts:", record["longest_line_prefix"])
    return 0 if Registry.blob_requests > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
