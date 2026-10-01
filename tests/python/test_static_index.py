# SPDX-License-Identifier: AGPL-3.0-only
"""Static index ingestion against the normative static-site contract.

Byte-exact values are copied from the contract text (§3.5, §5.5, §7.1) so the
Python implementation, the Go canonical helpers
(``pkg/organic/static_contract_examples_test.go``) and the contract agree.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from static_context import (
    FILES,
    HTML,
    SERVER,
    SPA,
    key,
    manifest_document,
    release_bytes,
    release_key,
    sha,
    site_digest,
    stored,
    target,
    trust_policy,
)

from misscomputer_subnet.static_index import (
    StaticIndexAbstention,
    StaticPathError,
    StaticSiteManifest,
    VerifiedStaticIndex,
    expected_static_response,
    ingest_static_index,
    static_index_manifest_key,
    static_index_release_key,
    static_site_manifest_bytes,
    validate_file_path,
    validate_request_path,
)

#: §3.5 stored manifest (861 bytes including the final newline).
CONTRACT_MANIFEST = (
    b'{"fallback":{"kind":"spa-html-v1","target":"/index.html"},"files":[{"body_sha256":'
    b'"f9444510dc7403e41049deb133f6892aa6a63c05591b2b59e4ee5b234d7bbd99","content_length":22,'
    b'"content_type":"text/javascript; charset=utf-8","path":"/assets/app.js"},{"body_sha256":'
    b'"4ada0f02c1764cbf47214c80ddc1f17d4eafc571f4c82fe71774b70fb65f87d9","content_length":35,'
    b'"content_type":"text/html; charset=utf-8","path":"/docs/index.html"},{"body_sha256":'
    b'"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","content_length":0,'
    b'"content_type":"text/plain; charset=utf-8","path":"/empty.txt"},{"body_sha256":'
    b'"d628d86f44c331c490330a6c091d656e960ce76f429eaa739196e598a75796c5","content_length":74,'
    b'"content_type":"text/html; charset=utf-8","path":"/index.html"}],'
    b'"handler":"static-handler.v1","schema":"miss.computer/misscomputer-subnet/'
    b'static-site-manifest","schema_version":1}\n'
)
CONTRACT_SITE = "sha256:9db3b2a4b3f18c1d31fd7d3348f83e1dfde21163d5aca540fd2f63d6b88ab77f"
CONTRACT_RELEASE_PUBLIC_KEY = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
CONTRACT_RELEASE_SIGNATURE = (
    "5bab1ba140424869a6c97d61b28364253cd278aae288108abd82dba2cc6e8ac81f"
    "809edab150ae2d8acddc498715953a8b57a5cd19f5ef5bc2d3eaafb83f170c"
)
CONTRACT_RELEASE_DIGEST = "sha256:a3ea17b8d08367ae5e971b7ee495cfae6d6bbaff9483f4396fe21189086ae19c"
CONTRACT_GET_ROOT_HEADER_SHA256 = "b830308c459ff241874e1e9b218a44b7161985c4005cdd824573f3a4677eed05"
EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
NOT_FOUND_SHA256 = "7515bf959b73b956ceb967351c7e299cbb3668a53d35f9c770eb72e00d93ced6"

RELEASE = release_bytes(CONTRACT_SITE)


def ingest(
    manifest: bytes | None = CONTRACT_MANIFEST,
    release: bytes | None = RELEASE,
    *,
    site: str = CONTRACT_SITE,
    policy: Any = None,
    pinned: str = SERVER,
    **binding: Any,
) -> VerifiedStaticIndex | StaticIndexAbstention:
    return ingest_static_index(
        target(site, release or b"", **binding),
        manifest,
        release,
        policy or trust_policy(),
        pinned_server_implementation_digest=pinned,
    )


def verified(manifest: bytes = CONTRACT_MANIFEST) -> VerifiedStaticIndex:
    site = site_digest(manifest)
    result = ingest(manifest, release_bytes(site), site=site)
    assert isinstance(result, VerifiedStaticIndex)
    return result


def test_contract_worked_examples_are_reproduced_byte_for_byte() -> None:
    manifest = StaticSiteManifest.model_validate(manifest_document())

    assert static_site_manifest_bytes(manifest) == CONTRACT_MANIFEST
    assert len(CONTRACT_MANIFEST) == 861
    assert site_digest(CONTRACT_MANIFEST) == CONTRACT_SITE
    assert release_key().public_key_hex == CONTRACT_RELEASE_PUBLIC_KEY
    assert f'"signature":"{CONTRACT_RELEASE_SIGNATURE}"'.encode() in RELEASE
    assert "sha256:" + sha(RELEASE) == CONTRACT_RELEASE_DIGEST
    assert static_index_manifest_key(CONTRACT_SITE) == (
        "static-sites/v1/manifests/"
        "9db3b2a4b3f18c1d31fd7d3348f83e1dfde21163d5aca540fd2f63d6b88ab77f.json"
    )
    assert static_index_release_key(CONTRACT_RELEASE_DIGEST) == (
        "static-sites/v1/releases/"
        "a3ea17b8d08367ae5e971b7ee495cfae6d6bbaff9483f4396fe21189086ae19c.json"
    )


def test_contract_example_index_verifies_with_every_route() -> None:
    index = ingest()

    assert isinstance(index, VerifiedStaticIndex)
    assert [(item.path, item.kind) for item in index.responses] == [
        ("/", "directory_index"),
        ("/assets/app.js", "file"),
        ("/docs/", "directory_index"),
        ("/docs/index.html", "file"),
        ("/empty.txt", "file"),
        ("/index.html", "file"),
    ]
    assert expected_static_response(index, "GET", "/").header_sha256 == (
        CONTRACT_GET_ROOT_HEADER_SHA256
    )


IDX = (200, 74, "d628d86f44c331c490330a6c091d656e960ce76f429eaa739196e598a75796c5", HTML)
DOC = (200, 35, "4ada0f02c1764cbf47214c80ddc1f17d4eafc571f4c82fe71774b70fb65f87d9", HTML)
JS = (
    200,
    22,
    "f9444510dc7403e41049deb133f6892aa6a63c05591b2b59e4ee5b234d7bbd99",
    "text/javascript; charset=utf-8",
)
MISSING = (404, 10, NOT_FOUND_SHA256, "text/plain; charset=utf-8")

#: §6 rows a validator can send (GET/HEAD, canonical path, no query or body):
#: (method, path, expected with fallback, expected without fallback).
VECTORS: dict[str, tuple[str, str, tuple[Any, ...], tuple[Any, ...]]] = {
    "V01": ("GET", "/", IDX, IDX),
    "V02": ("HEAD", "/", (200, 74, EMPTY, HTML), (200, 74, EMPTY, HTML)),
    "V03": ("GET", "/index.html", IDX, IDX),
    "V04": ("GET", "/assets/app.js", JS, JS),
    "V05": ("GET", "/docs/", DOC, DOC),
    "V06": ("GET", "/docs/index.html", DOC, DOC),
    "V07": (
        "GET",
        "/empty.txt",
        (200, 0, EMPTY, "text/plain; charset=utf-8"),
        (200, 0, EMPTY, "text/plain; charset=utf-8"),
    ),
    "V08": ("GET", "/docs", IDX, MISSING),
    "V09": ("GET", "/about/team", IDX, MISSING),
    "V10": ("GET", "/assets/", IDX, MISSING),
    "V11": ("GET", "/missing.js", MISSING, MISSING),
    "V12": ("GET", "/Index.html", MISSING, MISSING),
    "V13": ("GET", "/caf%C3%A9", IDX, MISSING),
    "V16": (
        "HEAD",
        "/missing.js",
        (404, 10, EMPTY, "text/plain; charset=utf-8"),
        (404, 10, EMPTY, "text/plain; charset=utf-8"),
    ),
    "V37": ("GET", "/index.html/", IDX, MISSING),
}


@pytest.mark.parametrize("row", sorted(VECTORS))
def test_expected_response_matches_contract_vector(row: str) -> None:
    method, path, with_fallback, without_fallback = VECTORS[row]
    no_fallback = stored(manifest_document(fallback=None))

    for index, expected in ((verified(), with_fallback), (verified(no_fallback), without_fallback)):
        response = expected_static_response(index, method, path)  # type: ignore[arg-type]
        assert (
            response.status,
            response.content_length,
            response.body_sha256,
            response.content_type,
        ) == expected


@pytest.mark.parametrize(
    "path",
    [
        "/%69ndex.html",  # V18
        "/a%2Fb",  # V19
        "/a%2fb",  # V20
        "/../index.html",  # V21
        "/./index.html",  # V22
        "/%2E%2E/",  # V23
        "//index.html",  # V24
        "/a%5Cb",  # V25
        "/%00",  # V26
        "/%7F",  # V26
        "/a|b",  # V27
        "/caf%c3%a9",  # V28
        "/100%",  # V29
        "/" + "/".join(["a" * 204] * 5),  # V30: 1,025 bytes
        "/a" * 33,  # V31
        "/a b",
        "/é",
        "/" + "a" * 256,
    ],
)
def test_request_paths_the_handler_rejects_with_400(path: str) -> None:
    with pytest.raises(StaticPathError):
        validate_request_path(path)


def test_request_path_limits_are_inclusive() -> None:
    longest = "/" + "/".join(["a" * 204] * 4 + ["a" * 203])
    deepest = "/a" * 32

    assert (len(longest), deepest.count("/")) == (1_024, 32)
    assert validate_request_path(longest) == longest
    assert validate_request_path(deepest) == deepest


@pytest.mark.parametrize("path", ["/caf%C3%A9", "/a%22", "/a/", "/100%25"])
def test_file_paths_admit_only_percent_encoded_space(path: str) -> None:
    validate_request_path(path)
    with pytest.raises(StaticPathError):
        validate_file_path(path)


def _document(**overrides: Any) -> bytes:
    return stored(manifest_document(**overrides))


def _file_directory_collision() -> bytes:
    files = {**FILES, "/docs": (b"x", "application/octet-stream")}
    return stored(manifest_document(files))


def _wrong_content_type() -> bytes:
    document = manifest_document()
    document["files"][0]["content_type"] = "application/javascript"
    return stored(document)


def _unsorted() -> bytes:
    document = manifest_document()
    document["files"].reverse()
    return stored(document)


def _oversized_file() -> bytes:
    document = manifest_document()
    document["files"][0]["content_length"] = 16_777_217
    return stored(document)


MANIFEST_ABSTENTIONS: dict[str, tuple[Callable[[], bytes], str]] = {
    "extra producer member": (
        lambda: _document(producer_policy_version="static-producer-policy.v1"),
        "index_invalid",
    ),
    "unsupported handler": (lambda: _document(handler="static-handler.v2"), "handler_unsupported"),
    "fallback to a non-html file": (
        lambda: _document(fallback={**SPA, "target": "/empty.txt"}),
        "index_invalid",
    ),
    "content type outside the policy table": (_wrong_content_type, "index_invalid"),
    "files not ascending": (_unsorted, "index_invalid"),
    "case-fold collision": (
        lambda: stored(manifest_document({**FILES, "/Empty.txt": FILES["/empty.txt"]})),
        "index_invalid",
    ),
    "file/directory collision": (_file_directory_collision, "index_invalid"),
    "no /index.html": (
        lambda: stored(
            manifest_document(
                {path: value for path, value in FILES.items() if path != "/index.html"},
                fallback=None,
            )
        ),
        "index_invalid",
    ),
    "file over 16 MiB": (_oversized_file, "index_limits_exceeded"),
    "non-canonical bytes": (
        lambda: CONTRACT_MANIFEST.replace(b'"schema_version":1', b'"schema_version": 1'),
        "index_not_canonical",
    ),
}


@pytest.mark.parametrize("case", sorted(MANIFEST_ABSTENTIONS))
def test_invalid_manifest_abstains(case: str) -> None:
    build, code = MANIFEST_ABSTENTIONS[case]
    manifest = build()
    site = site_digest(manifest)

    result = ingest(manifest, release_bytes(site), site=site)

    assert result == StaticIndexAbstention("site-a", site, code)  # type: ignore[arg-type]
    assert result.record_code == "static_index_invalid"  # type: ignore[union-attr]


ABSTENTIONS: dict[str, tuple[Callable[[], Any], str, str]] = {
    "manifest unavailable": (
        lambda: ingest(manifest=None),
        "index_unavailable",
        "static_index_unavailable",
    ),
    "release unavailable": (
        lambda: ingest(release=None, release_digest=CONTRACT_RELEASE_DIGEST),
        "release_unavailable",
        "static_index_unavailable",
    ),
    "manifest bytes differ from site_digest": (
        lambda: ingest(CONTRACT_MANIFEST + b" "),
        "site_digest_mismatch",
        "static_index_invalid",
    ),
    "release bytes differ from release_digest": (
        lambda: ingest(release_digest=CONTRACT_RELEASE_DIGEST.replace("a3", "00", 1)),
        "release_digest_mismatch",
        "static_index_invalid",
    ),
    "release for another site": (
        lambda: ingest(release=release_bytes("sha256:" + "0" * 64)),
        "release_binding_mismatch",
        "static_index_invalid",
    ),
    "signer not in policy": (
        lambda: ingest(release=release_bytes(CONTRACT_SITE, key_id="static-release-other")),
        "signer_untrusted",
        "static_index_invalid",
    ),
    "signature by another key": (
        lambda: ingest(release=release_bytes(CONTRACT_SITE, private=key("forger"))),
        "signature_invalid",
        "static_index_invalid",
    ),
    "issued_at outside key window": (
        lambda: ingest(policy=trust_policy(release_key(valid_until_epoch=1_790_726_400))),
        "signer_outside_validity",
        "static_index_invalid",
    ),
    "legacy producer policy": (
        lambda: ingest(
            release=release_bytes(
                CONTRACT_SITE, producer_policy_version="static-producer-policy.v1"
            )
        ),
        "producer_policy_unsupported",
        "static_index_invalid",
    ),
    "release names an unpinned server": (
        lambda: ingest(pinned="sha256:" + "cd" * 32),
        "server_implementation_mismatch",
        "static_index_invalid",
    ),
    "manifest v3 names another server": (
        lambda: ingest(server="sha256:" + "cd" * 32),
        "server_implementation_mismatch",
        "static_index_invalid",
    ),
}


@pytest.mark.parametrize("case", sorted(ABSTENTIONS))
def test_unverifiable_release_or_binding_abstains(case: str) -> None:
    build, code, record = ABSTENTIONS[case]

    result = build()

    assert isinstance(result, StaticIndexAbstention)
    assert (result.code, result.record_code) == (code, record)


def test_release_key_window_starts_at_issuance() -> None:
    assert isinstance(
        ingest(policy=trust_policy(release_key(valid_from_epoch=1_790_726_400))),
        VerifiedStaticIndex,
    )
