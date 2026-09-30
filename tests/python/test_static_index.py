# SPDX-License-Identifier: AGPL-3.0-only
"""Validator ingestion of the signed static-site index: verify or abstain, never downgrade."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from static_context import (
    FILES,
    NOT_FOUND_BODY,
    NOW,
    RELEASE_KEY,
    canonical_bytes,
    key,
    manifest_document,
    release_bytes,
    release_key,
    sha,
    target,
    trust_policy,
)

from misscomputer_subnet.static_index import (
    StaticIndexAbstention,
    StaticPathError,
    VerifiedStaticIndex,
    expected_static_response,
    ingest_static_index,
    validate_static_path,
)

MANIFEST = canonical_bytes(manifest_document())
SITE = sha(MANIFEST)
EMPTY = sha(b"")


def verified() -> VerifiedStaticIndex:
    result = ingest_static_index(
        target(SITE), MANIFEST, release_bytes(SITE), trust_policy(), evaluation_epoch=NOW
    )
    assert isinstance(result, VerifiedStaticIndex)
    return result


def test_verified_index_lists_every_file_and_directory_index_response() -> None:
    index = verified()

    assert [(item.path, item.kind) for item in index.responses] == [
        ("/", "directory_index"),
        ("/app.js", "file"),
        ("/docs/", "directory_index"),
        ("/docs/index.html", "file"),
        ("/index.html", "file"),
        ("/logo.png", "file"),
    ]
    assert {item.path: item.body_sha256 for item in index.responses}["/docs/"] == sha(
        FILES["/docs/index.html"][0]
    )


def _ingest(
    manifest: bytes | None = MANIFEST,
    release: bytes | None = None,
    *,
    site: str | None = None,
    **policy: Any,
) -> VerifiedStaticIndex | StaticIndexAbstention:
    digest = site if site is not None else (sha(manifest) if manifest is not None else SITE)
    return ingest_static_index(
        target(digest),
        manifest,
        release if release is not None else release_bytes(digest),
        trust_policy(**policy),
        evaluation_epoch=NOW,
    )


def _big_file() -> VerifiedStaticIndex | StaticIndexAbstention:
    document = manifest_document()
    document["files"][0]["size_bytes"] = 16 * 1_024 * 1_024 + 1
    return _ingest(canonical_bytes(document))


def _case_collision() -> VerifiedStaticIndex | StaticIndexAbstention:
    return _ingest(canonical_bytes(manifest_document({**FILES, "/App.js": FILES["/app.js"]})))


def _no_root() -> VerifiedStaticIndex | StaticIndexAbstention:
    files = {path: value for path, value in FILES.items() if path != "/index.html"}
    return _ingest(canonical_bytes(manifest_document(files, fallback=None)))


def _other_site_release() -> VerifiedStaticIndex | StaticIndexAbstention:
    return _ingest(release=release_bytes(sha(b"another site")))


def _tampered_signature() -> VerifiedStaticIndex | StaticIndexAbstention:
    return _ingest(release=release_bytes(SITE, signers=(("release-a", key("forger")),)))


ABSTENTIONS: dict[str, tuple[Callable[[], VerifiedStaticIndex | StaticIndexAbstention], str]] = {
    "manifest fetch failed": (lambda: _ingest(None), "index_unavailable"),
    "release fetch failed": (
        lambda: ingest_static_index(
            target(SITE), MANIFEST, None, trust_policy(), evaluation_epoch=NOW
        ),
        "release_unavailable",
    ),
    "bytes differ from bound digest": (
        lambda: _ingest(MANIFEST + b" ", site=SITE),
        "site_digest_mismatch",
    ),
    "non-canonical bytes": (
        lambda: _ingest(MANIFEST.replace(b'"schema_version":1', b'"schema_version": 1')),
        "index_not_canonical",
    ),
    "file over 16 MiB cap": (_big_file, "index_caps_exceeded"),
    "case-fold path collision": (_case_collision, "index_invalid"),
    "no root response": (_no_root, "root_response_missing"),
    "release names another site": (_other_site_release, "release_binding_mismatch"),
    "release names another producer policy": (
        lambda: _ingest(release=release_bytes(SITE, producer="railpack-static-v2")),
        "release_binding_mismatch",
    ),
    "release signed by unpinned key": (
        lambda: _ingest(release=release_bytes(SITE, signers=(("release-z", RELEASE_KEY),))),
        "signer_untrusted",
    ),
    "signature by wrong private key": (_tampered_signature, "signature_invalid"),
    "release key revoked": (
        lambda: _ingest(release_keys=[release_key(revoked_at_epoch=NOW - 1)]),
        "signer_revoked",
    ),
    "threshold above signer count": (
        lambda: _ingest(
            threshold=2, release_keys=[release_key(), release_key("release-b", key("second"))]
        ),
        "threshold_not_met",
    ),
    "producer policy not approved": (
        lambda: _ingest(approved_producer_policy_versions=["railpack-static-v0"]),
        "producer_policy_unapproved",
    ),
    "server implementation not pinned": (
        lambda: _ingest(release=release_bytes(SITE, server="sha256:" + "0" * 64)),
        "server_implementation_unpinned",
    ),
    "trust policy expired": (
        lambda: _ingest(valid_from_epoch=NOW - 10, valid_until_epoch=NOW),
        "trust_policy_expired",
    ),
}


@pytest.mark.parametrize("case", sorted(ABSTENTIONS))
def test_unverifiable_index_abstains_with_stable_code(case: str) -> None:
    build, code = ABSTENTIONS[case]

    result = build()

    assert result == StaticIndexAbstention("site-a", result.site_digest, code)  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "path",
    ["/", "/a", "/docs/", "/a/b.c/d", "/caf%C3%A9", "/a%20b", "/%25", "/~user/x;y=1"],
)
def test_canonical_static_paths_are_accepted(path: str) -> None:
    assert validate_static_path(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "",
        "a",
        "//a",
        "/a//b",
        "/./a",
        "/a/..",
        "/%2e%2e/a",
        "/%2E",
        "/%2F",
        "/%5C",
        "/%41",
        "/%c3%a9",
        "/%0A",
        "/%zz",
        "/a\\b",
        "/a?b",
        "/a#b",
        "/a b",
        "/é",
        "/" + "a" * 256,
        "/a" * 33,
        "/" + "a/" * 511 + "aa",
    ],
)
def test_ambiguous_or_unsafe_paths_are_refused(path: str) -> None:
    with pytest.raises(StaticPathError):
        validate_static_path(path)


def test_lookup_vectors_follow_the_pinned_handler_rules() -> None:
    index = verified()
    home, _ = FILES["/index.html"]

    vectors = {
        ("GET", "/"): ("directory_index", 200, len(home), sha(home)),
        ("HEAD", "/"): ("directory_index", 200, len(home), EMPTY),
        ("GET", "/settings/profile"): ("navigation_fallback", 200, len(home), sha(home)),
        ("GET", "/missing.js"): ("not_found", 404, len(NOT_FOUND_BODY), sha(NOT_FOUND_BODY)),
        ("GET", "/docs"): ("navigation_fallback", 200, len(home), sha(home)),
    }

    for (method, path), expected in vectors.items():
        response = expected_static_response(index, method, path)  # type: ignore[arg-type]
        assert (
            response.kind,
            response.status,
            response.content_length,
            response.body_sha256,
        ) == expected, (method, path)


def test_missing_navigation_path_is_404_without_declared_fallback() -> None:
    manifest = canonical_bytes(manifest_document(fallback=None))
    site = sha(manifest)
    index = ingest_static_index(
        target(site), manifest, release_bytes(site), trust_policy(), evaluation_epoch=NOW
    )
    assert isinstance(index, VerifiedStaticIndex)

    assert expected_static_response(index, "GET", "/settings").status == 404
