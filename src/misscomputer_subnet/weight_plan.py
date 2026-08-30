# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical, immutable validator weight plans and safe local persistence."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import math
import os
import secrets
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from .chain import MetagraphSnapshot, NeuronRecord

WEIGHT_PLAN_SCHEMA = "miss.computer/misscomputer-subnet/weight-plan"
WEIGHT_PLAN_SCHEMA_VERSION = 1
# This is the protocol discriminator forwarded to Bittensor's weight call, not
# a per-plan nonce. Canonical plan and surrounding workflow digests bind each
# plan instance to its snapshot, identities, and provenance.
WEIGHT_PLAN_PROTOCOL_VERSION_KEY: Final = 2
SNAPSHOT_IDENTITY_SCHEMA = "miss.computer/misscomputer-subnet/metagraph-identity/v1"
WEIGHT_PLAN_FILE_MODE = 0o600
MAX_WEIGHT_PLAN_NEURONS = 65_536
MAX_WEIGHT_PLAN_BYTES = 16 << 20
MAX_BLOCK = (1 << 63) - 1
MAX_VERSION_KEY = (1 << 64) - 1


class WeightPlanError(ValueError):
    """The proposed plan data is unsafe or ambiguous."""


class WeightPlanTargetError(WeightPlanError):
    """The requested durable plan target is unsafe."""


def _canonical_json(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise WeightPlanError("weight plan is not canonical JSON") from exc
    return rendered.encode("ascii")


def _validate_text(value: object, *, field_name: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value != value.strip()
        or not value.isascii()
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise WeightPlanError(f"{field_name} is invalid")
    return value


def _validate_network_identity(value: object, *, field_name: str = "network") -> str:
    """Accept public aliases or credential-free canonical websocket endpoints."""

    network = _validate_text(value, field_name=field_name)
    if "://" not in network:
        if len(network) > 64 or any(
            not (character.isalnum() or character in {"-", "_"}) for character in network
        ):
            raise WeightPlanError(
                f"{field_name} must be a public alias or credential-free websocket endpoint"
            )
        return network
    try:
        endpoint = urlsplit(network)
        port = endpoint.port
    except ValueError as exc:
        raise WeightPlanError(f"{field_name} is invalid") from exc
    if (
        endpoint.scheme not in {"ws", "wss"}
        or not endpoint.netloc
        or endpoint.hostname is None
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.path
        or endpoint.query
        or endpoint.fragment
        or endpoint.netloc.endswith(":")
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise WeightPlanError(
            f"{field_name} must be a public alias or credential-free websocket endpoint"
        )
    return network


def _validate_integer(
    value: object,
    *,
    field_name: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise WeightPlanError(f"{field_name} is out of range")
    return value


@dataclass(frozen=True, slots=True)
class WeightPlanEntry:
    """One exact metagraph identity and its normalized positive weight."""

    uid: int
    hotkey: str
    weight: float

    def __post_init__(self) -> None:
        _validate_integer(self.uid, field_name="weight UID", minimum=0, maximum=65_535)
        _validate_text(self.hotkey, field_name="weight hotkey")
        try:
            normalized = float(self.weight)
        except (TypeError, ValueError, OverflowError) as exc:
            raise WeightPlanError("normalized weight is out of range") from exc
        if (
            isinstance(self.weight, bool)
            or not isinstance(self.weight, (int, float))
            or not (math.isfinite(normalized) and 0.0 < normalized <= 1.0)
        ):
            raise WeightPlanError("normalized weight is out of range")
        object.__setattr__(self, "weight", normalized)

    def document(self) -> dict[str, object]:
        return {"hotkey": self.hotkey, "uid": self.uid, "weight": self.weight}


@dataclass(frozen=True, slots=True)
class WeightPlanSnapshot:
    """The exact finalized metagraph view that authorizes a plan."""

    block: int
    tempo: int
    epoch: int
    finalized: bool
    identity_fingerprint: str

    def __post_init__(self) -> None:
        _validate_integer(self.block, field_name="snapshot block", minimum=0, maximum=MAX_BLOCK)
        _validate_integer(self.tempo, field_name="snapshot tempo", minimum=1, maximum=MAX_BLOCK)
        _validate_integer(self.epoch, field_name="snapshot epoch", minimum=0, maximum=MAX_BLOCK)
        if self.epoch != self.block // self.tempo:
            raise WeightPlanError("snapshot epoch does not match block and tempo")
        if self.finalized is not True:
            raise WeightPlanError("weight plans require a finalized metagraph snapshot")
        if len(self.identity_fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in self.identity_fingerprint
        ):
            raise WeightPlanError("snapshot identity fingerprint is invalid")

    def document(self) -> dict[str, object]:
        return {
            "block": self.block,
            "epoch": self.epoch,
            "finalized": self.finalized,
            "identity_fingerprint": self.identity_fingerprint,
            "tempo": self.tempo,
        }


@dataclass(frozen=True, slots=True)
class WeightPlan:
    """Immutable canonical input for a future, separate one-shot executor.

    ``digest_sha256`` authenticates the canonical JSON document without the
    digest field itself. The on-disk document adds that digest and one trailing
    newline; no wall-clock value participates, so the same snapshot and inputs
    always produce exactly the same bytes.
    """

    network: str
    netuid: int
    validator_hotkey: str
    snapshot: WeightPlanSnapshot
    weights: tuple[WeightPlanEntry, ...]
    version_key: int
    created_block: int
    expires_at_block: int
    schema: str = field(default=WEIGHT_PLAN_SCHEMA, init=False)
    schema_version: int = field(default=WEIGHT_PLAN_SCHEMA_VERSION, init=False)
    digest_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _validate_network_identity(self.network)
        _validate_integer(self.netuid, field_name="netuid", minimum=0, maximum=65_535)
        _validate_text(self.validator_hotkey, field_name="validator hotkey")
        _validate_integer(
            self.version_key,
            field_name="version key",
            minimum=0,
            maximum=MAX_VERSION_KEY,
        )
        _validate_integer(
            self.created_block,
            field_name="created block",
            minimum=0,
            maximum=MAX_BLOCK,
        )
        _validate_integer(
            self.expires_at_block,
            field_name="expiry block",
            minimum=0,
            maximum=MAX_BLOCK,
        )
        if self.created_block != self.snapshot.block:
            raise WeightPlanError("created block must equal the finalized snapshot block")
        expiry_limit = _conservative_expiry_limit(self.snapshot.block, self.snapshot.tempo)
        if not self.created_block < self.expires_at_block <= expiry_limit:
            raise WeightPlanError("expiry block exceeds the conservative snapshot window")
        if not self.weights:
            raise WeightPlanError("weight plan must contain at least one positive entry")
        ordered = tuple(sorted(self.weights, key=lambda entry: (entry.uid, entry.hotkey)))
        if self.weights != ordered:
            raise WeightPlanError("weight plan entries are not canonically ordered")
        if len({entry.uid for entry in self.weights}) != len(self.weights):
            raise WeightPlanError("weight plan contains duplicate UIDs")
        if len({entry.hotkey for entry in self.weights}) != len(self.weights):
            raise WeightPlanError("weight plan contains duplicate hotkeys")
        if any(entry.hotkey == self.validator_hotkey for entry in self.weights):
            raise WeightPlanError("weight plan cannot assign weight to its validator")
        if not math.isclose(
            math.fsum(entry.weight for entry in self.weights),
            1.0,
            rel_tol=0.0,
            abs_tol=1e-15,
        ):
            raise WeightPlanError("weight plan entries are not normalized")
        object.__setattr__(
            self,
            "digest_sha256",
            hashlib.sha256(_canonical_json(self._unsigned_document())).hexdigest(),
        )

    def _unsigned_document(self) -> dict[str, object]:
        return {
            "created_block": self.created_block,
            "expires_at_block": self.expires_at_block,
            "netuid": self.netuid,
            "network": self.network,
            "schema": self.schema,
            "schema_version": self.schema_version,
            "snapshot": self.snapshot.document(),
            "validator_hotkey": self.validator_hotkey,
            "version_key": self.version_key,
            "weights": [entry.document() for entry in self.weights],
        }

    def document(self) -> dict[str, object]:
        value = self._unsigned_document()
        value["digest_sha256"] = self.digest_sha256
        return value

    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.document()) + b"\n"


def _validate_snapshot_neuron(neuron: NeuronRecord) -> tuple[int, str, dict[str, object]]:
    uid = _validate_integer(neuron.uid, field_name="snapshot UID", minimum=0, maximum=65_535)
    hotkey = _validate_text(neuron.hotkey, field_name="snapshot hotkey")
    if not isinstance(neuron.validator_permit, bool) or not isinstance(neuron.active, bool):
        raise WeightPlanError("snapshot neuron flags are invalid")
    if (
        isinstance(neuron.tao_stake, bool)
        or not isinstance(neuron.tao_stake, (int, float))
        or not math.isfinite(float(neuron.tao_stake))
        or float(neuron.tao_stake) < 0.0
    ):
        raise WeightPlanError("snapshot stake is invalid")
    if neuron.axon is not None:
        _validate_text(neuron.axon, field_name="snapshot axon identity", maximum=4_096)
    identity: dict[str, object] = {
        "active": neuron.active,
        "axon": neuron.axon,
        "hotkey": hotkey,
        "tao_stake_hex": float(neuron.tao_stake).hex(),
        "uid": uid,
        "validator_permit": neuron.validator_permit,
    }
    return uid, hotkey, identity


def snapshot_identity_fingerprint(snapshot: MetagraphSnapshot) -> str:
    """Hash the complete, validated, order-independent metagraph identity."""

    network = _validate_network_identity(snapshot.network, field_name="snapshot network")
    netuid = _validate_integer(
        snapshot.netuid, field_name="snapshot netuid", minimum=0, maximum=65_535
    )
    block = _validate_integer(
        snapshot.block, field_name="snapshot block", minimum=0, maximum=MAX_BLOCK
    )
    tempo = _validate_integer(
        snapshot.tempo, field_name="snapshot tempo", minimum=1, maximum=MAX_BLOCK
    )
    if snapshot.finalized is not True:
        raise WeightPlanError("weight plans require a finalized metagraph snapshot")
    if not snapshot.neurons or len(snapshot.neurons) > MAX_WEIGHT_PLAN_NEURONS:
        raise WeightPlanError("snapshot neuron collection is empty or too large")
    identities = [_validate_snapshot_neuron(neuron) for neuron in snapshot.neurons]
    if len({uid for uid, _, _ in identities}) != len(identities):
        raise WeightPlanError("snapshot contains duplicate UIDs")
    if len({hotkey for _, hotkey, _ in identities}) != len(identities):
        raise WeightPlanError("snapshot contains duplicate hotkeys")
    ordered = [identity for _, _, identity in sorted(identities, key=lambda item: item[:2])]
    document = {
        "block": block,
        "epoch": block // tempo,
        "finalized": True,
        "netuid": netuid,
        "network": network,
        "neurons": ordered,
        "schema": SNAPSHOT_IDENTITY_SCHEMA,
        "tempo": tempo,
    }
    return hashlib.sha256(_canonical_json(document)).hexdigest()


def _conservative_expiry_limit(block: int, tempo: int) -> int:
    epoch = block // tempo
    next_epoch_block = (epoch + 1) * tempo
    quarter_tempo_window = max(1, tempo // 4)
    return min(block + quarter_tempo_window, next_epoch_block, MAX_BLOCK)


def conservative_expiry_block(snapshot: MetagraphSnapshot) -> int:
    """Expire within both one quarter-tempo and the current epoch boundary."""

    block = _validate_integer(
        snapshot.block, field_name="snapshot block", minimum=0, maximum=MAX_BLOCK
    )
    tempo = _validate_integer(
        snapshot.tempo, field_name="snapshot tempo", minimum=1, maximum=MAX_BLOCK
    )
    expiry = _conservative_expiry_limit(block, tempo)
    if expiry <= block:
        raise WeightPlanError("snapshot is too close to the supported block limit")
    return expiry


def _weight_rows(value: object) -> Sequence[object]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise WeightPlanError("weight rows must be a JSON array")
    if not value or len(value) > MAX_WEIGHT_PLAN_NEURONS:
        raise WeightPlanError("weight rows are empty or too large")
    return value


def build_weight_plan(
    *,
    snapshot: MetagraphSnapshot,
    validator_hotkey: str,
    rows: object,
    version_key: int,
) -> WeightPlan:
    """Validate and normalize Go dry-run rows against one finalized snapshot."""

    validator_hotkey = _validate_text(validator_hotkey, field_name="validator hotkey")
    fingerprint = snapshot_identity_fingerprint(snapshot)
    by_hotkey = {neuron.hotkey: neuron for neuron in snapshot.neurons}
    validator = by_hotkey.get(validator_hotkey)
    if validator is None or not validator.active or not validator.validator_permit:
        raise WeightPlanError(
            "validator hotkey is absent, inactive, or lacks a permit in the snapshot"
        )

    seen_hotkeys: set[str] = set()
    positive: list[tuple[int, str, float]] = []
    for item in _weight_rows(rows):
        if not isinstance(item, Mapping):
            raise WeightPlanError("weight row is not an object")
        hotkey = _validate_text(item.get("miner_hotkey"), field_name="weight hotkey")
        if hotkey in seen_hotkeys:
            raise WeightPlanError("weight rows contain a duplicate hotkey")
        seen_hotkeys.add(hotkey)
        raw_weight = item.get("weight")
        if isinstance(raw_weight, bool) or not isinstance(raw_weight, (int, float)):
            raise WeightPlanError("weight value is not a JSON number")
        weight = float(raw_weight)
        if not math.isfinite(weight) or not 0.0 <= weight <= 1.0:
            raise WeightPlanError("weight value is non-finite or out of range")
        neuron = by_hotkey.get(hotkey)
        if neuron is None:
            raise WeightPlanError("weight hotkey is absent from the finalized snapshot")
        if hotkey == validator_hotkey or not neuron.active:
            raise WeightPlanError("weight target is not an active miner")
        if weight > 0.0:
            positive.append((neuron.uid, hotkey, weight))

    if not positive:
        raise WeightPlanError("weight rows contain no positive targets")
    positive.sort(key=lambda item: (item[0], item[1]))
    if len({uid for uid, _, _ in positive}) != len(positive):
        raise WeightPlanError("weight rows resolve to duplicate UIDs")
    total = math.fsum(weight for _, _, weight in positive)
    if not math.isfinite(total) or total <= 0.0:
        raise WeightPlanError("weight total is invalid")
    normalized = [weight / total for _, _, weight in positive]
    correction_index = max(range(len(normalized)), key=lambda index: normalized[index])
    normalized[correction_index] += 1.0 - math.fsum(normalized)
    entries = tuple(
        WeightPlanEntry(uid=uid, hotkey=hotkey, weight=normalized[index])
        for index, (uid, hotkey, _) in enumerate(positive)
    )
    plan_snapshot = WeightPlanSnapshot(
        block=snapshot.block,
        tempo=snapshot.tempo,
        epoch=snapshot.epoch,
        finalized=snapshot.finalized,
        identity_fingerprint=fingerprint,
    )
    return WeightPlan(
        network=snapshot.network,
        netuid=snapshot.netuid,
        validator_hotkey=validator_hotkey,
        snapshot=plan_snapshot,
        weights=entries,
        version_key=version_key,
        created_block=snapshot.block,
        expires_at_block=conservative_expiry_block(snapshot),
    )


def _validate_existing_target(target: os.stat_result) -> None:
    if not stat.S_ISREG(target.st_mode):
        raise WeightPlanTargetError("weight plan target must be a regular file, not a symlink")
    if target.st_nlink != 1:
        raise WeightPlanTargetError("weight plan target must not have hard links")
    if hasattr(os, "geteuid") and target.st_uid != os.geteuid():
        raise WeightPlanTargetError("weight plan target must be owned by the validator user")
    if stat.S_IMODE(target.st_mode) != WEIGHT_PLAN_FILE_MODE:
        raise WeightPlanTargetError("existing weight plan target must have mode 0600")
    if target.st_size > MAX_WEIGHT_PLAN_BYTES:
        raise WeightPlanTargetError("existing weight plan target is unexpectedly large")


def _target_stat(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        target = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    _validate_existing_target(target)
    return target


def _same_target(first: os.stat_result | None, second: os.stat_result | None) -> bool:
    if first is None or second is None:
        return first is second
    return (
        first.st_dev,
        first.st_ino,
        first.st_mode,
        first.st_nlink,
        first.st_uid,
        first.st_size,
        first.st_mtime_ns,
        first.st_ctime_ns,
    ) == (
        second.st_dev,
        second.st_ino,
        second.st_mode,
        second.st_nlink,
        second.st_uid,
        second.st_size,
        second.st_mtime_ns,
        second.st_ctime_ns,
    )


def _read_existing(directory_fd: int, name: str, expected: os.stat_result) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        opened = os.fstat(descriptor)
        _validate_existing_target(opened)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise WeightPlanTargetError("weight plan target changed during validation")
        chunks: list[bytes] = []
        remaining = MAX_WEIGHT_PLAN_BYTES
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining == 0 and os.read(descriptor, 1):
            raise WeightPlanTargetError("existing weight plan target is unexpectedly large")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _secure_file_location(path: str | os.PathLike[str]) -> tuple[str, str]:
    raw_path = os.fspath(path)
    if not isinstance(raw_path, str) or not raw_path or "\x00" in raw_path:
        raise WeightPlanTargetError("weight plan path is invalid")
    if (
        raw_path.endswith(os.sep)
        or os.path.basename(raw_path) in {".", ".."}
        or any(component in {".", ".."} for component in raw_path.split(os.sep))
    ):
        raise WeightPlanTargetError("weight plan path must name a file")
    absolute_path = os.path.abspath(raw_path)
    parent = os.path.dirname(absolute_path)
    name = os.path.basename(absolute_path)
    if not name or name in {".", ".."}:
        raise WeightPlanTargetError("weight plan path must name a file")
    return parent, name


@dataclass(slots=True)
class _PinnedDirectoryChain:
    absolute_parent: str
    components: tuple[str, ...]
    descriptors: list[int]
    identities: tuple[tuple[int, int], ...]

    @property
    def parent_fd(self) -> int:
        return self.descriptors[-1]

    def close(self) -> None:
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)
        self.descriptors.clear()


@dataclass(slots=True)
class _TemporaryPlan:
    descriptor: int
    identity: tuple[int, int]
    name: str | None


def _effective_uid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else os.getuid()


def _validate_directory(
    value: os.stat_result,
    *,
    final_parent: bool,
) -> None:
    if not stat.S_ISDIR(value.st_mode):
        raise WeightPlanTargetError("weight plan path component is not a directory")
    if value.st_uid not in {0, _effective_uid()}:
        raise WeightPlanTargetError(
            "weight plan ancestor must be owned by root or the validator user"
        )
    unsafe_write_bits = stat.S_IMODE(value.st_mode) & 0o022
    sticky_ancestor = bool(value.st_mode & stat.S_ISVTX) and not final_parent
    if unsafe_write_bits and not sticky_ancestor:
        location = "parent" if final_parent else "ancestor"
        raise WeightPlanTargetError(
            f"weight plan {location} must not be writable by group or other users"
        )


def _directory_flags() -> int:
    required = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required) or os.open not in os.supports_dir_fd:
        raise WeightPlanTargetError("secure openat directory traversal is unavailable")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW


def _pin_directory_chain(absolute_parent: str) -> _PinnedDirectoryChain:
    components = tuple(component for component in absolute_parent.split(os.sep) if component)
    descriptors: list[int] = []
    identities: list[tuple[int, int]] = []
    flags = _directory_flags()
    try:
        descriptor = os.open(os.sep, flags)
        descriptors.append(descriptor)
        root_stat = os.fstat(descriptor)
        _validate_directory(root_stat, final_parent=not components)
        identities.append((root_stat.st_dev, root_stat.st_ino))
        for index, component in enumerate(components):
            if component in {".", ".."} or os.sep in component:
                raise WeightPlanTargetError("weight plan path component is invalid")
            try:
                descriptor = os.open(component, flags, dir_fd=descriptors[-1])
            except OSError as exc:
                raise WeightPlanTargetError(
                    "weight plan parent chain is missing, symlinked, or unsafe"
                ) from exc
            descriptors.append(descriptor)
            component_stat = os.fstat(descriptor)
            _validate_directory(component_stat, final_parent=index == len(components) - 1)
            identities.append((component_stat.st_dev, component_stat.st_ino))
        return _PinnedDirectoryChain(
            absolute_parent=absolute_parent,
            components=components,
            descriptors=descriptors,
            identities=tuple(identities),
        )
    except Exception:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def _revalidate_pinned_chain(chain: _PinnedDirectoryChain) -> None:
    for index, descriptor in enumerate(chain.descriptors):
        current = os.fstat(descriptor)
        _validate_directory(current, final_parent=index == len(chain.descriptors) - 1)
        if (current.st_dev, current.st_ino) != chain.identities[index]:
            raise WeightPlanTargetError("pinned weight plan directory changed identity")
    reopened = _pin_directory_chain(chain.absolute_parent)
    try:
        if reopened.identities != chain.identities:
            raise WeightPlanTargetError("configured weight plan directory changed during install")
    finally:
        reopened.close()


def _read_descriptor(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = MAX_WEIGHT_PLAN_BYTES
    while remaining:
        chunk = os.read(descriptor, min(remaining, 1 << 20))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    if remaining == 0 and os.read(descriptor, 1):
        raise WeightPlanTargetError("installed weight plan is unexpectedly large")
    return b"".join(chunks)


def _validate_temporary_descriptor(
    temporary: _TemporaryPlan,
    *,
    expected_size: int,
    expected_nlink: int,
) -> os.stat_result:
    value = os.fstat(temporary.descriptor)
    if not stat.S_ISREG(value.st_mode):
        raise WeightPlanTargetError("temporary weight plan inode is not a regular file")
    if (value.st_dev, value.st_ino) != temporary.identity:
        raise WeightPlanTargetError("temporary weight plan inode changed identity")
    if value.st_uid != _effective_uid():
        raise WeightPlanTargetError("temporary weight plan inode changed owner")
    if stat.S_IMODE(value.st_mode) != WEIGHT_PLAN_FILE_MODE:
        raise WeightPlanTargetError("temporary weight plan inode changed mode")
    if value.st_size != expected_size:
        raise WeightPlanTargetError("temporary weight plan inode changed size")
    if value.st_nlink != expected_nlink:
        raise WeightPlanTargetError("temporary weight plan inode acquired an unexpected hard link")
    return value


def _validate_temporary_name(
    temporary: _TemporaryPlan,
    directory_fd: int,
    *,
    expected_size: int,
) -> None:
    if temporary.name is None:
        raise WeightPlanTargetError("temporary weight plan has no install name")
    named = os.stat(temporary.name, dir_fd=directory_fd, follow_symlinks=False)
    _validate_existing_target(named)
    if named.st_size != expected_size or (named.st_dev, named.st_ino) != temporary.identity:
        raise WeightPlanTargetError("temporary weight plan name changed identity")


def _write_all(descriptor: int, rendered: bytes) -> None:
    view = memoryview(rendered)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError("short write while persisting weight plan")
        offset += written


def _open_unnamed_temporary(directory_fd: int) -> int | None:
    if not hasattr(os, "O_TMPFILE"):
        return None
    flags = os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC
    try:
        return os.open(".", flags, WEIGHT_PLAN_FILE_MODE, dir_fd=directory_fd)
    except OSError as exc:
        if exc.errno in {
            errno.EINVAL,
            errno.EISDIR,
            errno.ENOSYS,
            errno.EOPNOTSUPP,
            errno.EPERM,
        }:
            return None
        raise


def _link_unnamed_temporary(descriptor: int, directory_fd: int, name: str) -> None:
    # Python does not expose linkat(AT_EMPTY_PATH).  Linux filesystems that
    # support O_TMPFILE use this tiny libc seam to materialize the already
    # fsynced inode only for the final rename.  Other systems use the visible
    # O_EXCL fallback below.
    libc: Any = ctypes.CDLL(None, use_errno=True)
    result = libc.linkat(
        descriptor,
        ctypes.c_char_p(b""),
        directory_fd,
        ctypes.c_char_p(os.fsencode(name)),
        0x1000,  # AT_EMPTY_PATH
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), name)


def _allocate_visible_temporary(directory_fd: int) -> tuple[int, str]:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    for _ in range(32):
        candidate = f".weight-plan.tmp-{secrets.token_hex(16)}"
        try:
            descriptor = os.open(
                candidate,
                flags,
                WEIGHT_PLAN_FILE_MODE,
                dir_fd=directory_fd,
            )
        except FileExistsError:
            continue
        return descriptor, candidate
    raise WeightPlanTargetError("could not allocate a private temporary plan file")


def _prepare_temporary_plan(directory_fd: int, rendered: bytes) -> _TemporaryPlan:
    descriptor = _open_unnamed_temporary(directory_fd)
    if descriptor is not None:
        value = os.fstat(descriptor)
        temporary = _TemporaryPlan(
            descriptor=descriptor,
            identity=(value.st_dev, value.st_ino),
            name=None,
        )
        try:
            os.fchmod(descriptor, WEIGHT_PLAN_FILE_MODE)
            _write_all(descriptor, rendered)
            os.fsync(descriptor)
            _validate_temporary_descriptor(
                temporary,
                expected_size=len(rendered),
                expected_nlink=0,
            )
            for _ in range(32):
                candidate = f".weight-plan.tmp-{secrets.token_hex(16)}"
                try:
                    _link_unnamed_temporary(descriptor, directory_fd, candidate)
                except OSError as exc:
                    if exc.errno == errno.EEXIST:
                        continue
                    if exc.errno in {
                        errno.EINVAL,
                        errno.ENOENT,
                        errno.ENOSYS,
                        errno.EOPNOTSUPP,
                        errno.EPERM,
                    }:
                        break
                    raise
                temporary.name = candidate
                _validate_temporary_descriptor(
                    temporary,
                    expected_size=len(rendered),
                    expected_nlink=1,
                )
                _validate_temporary_name(
                    temporary,
                    directory_fd,
                    expected_size=len(rendered),
                )
                return temporary
        except Exception:
            if temporary.name is not None:
                try:
                    named = os.stat(
                        temporary.name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    if (named.st_dev, named.st_ino) == temporary.identity:
                        os.unlink(temporary.name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
            os.close(descriptor)
            raise
        os.close(descriptor)

    descriptor, name = _allocate_visible_temporary(directory_fd)
    value = os.fstat(descriptor)
    temporary = _TemporaryPlan(
        descriptor=descriptor,
        identity=(value.st_dev, value.st_ino),
        name=name,
    )
    try:
        os.fchmod(descriptor, WEIGHT_PLAN_FILE_MODE)
        _write_all(descriptor, rendered)
        os.fsync(descriptor)
        _validate_temporary_descriptor(
            temporary,
            expected_size=len(rendered),
            expected_nlink=1,
        )
        _validate_temporary_name(temporary, directory_fd, expected_size=len(rendered))
        return temporary
    except Exception:
        os.close(descriptor)
        try:
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (named.st_dev, named.st_ino) == temporary.identity:
                os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise


def _verify_configured_target(
    chain: _PinnedDirectoryChain,
    name: str,
    *,
    identity: tuple[int, int],
    rendered: bytes,
) -> None:
    _revalidate_pinned_chain(chain)
    reopened = _pin_directory_chain(chain.absolute_parent)
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(name, flags, dir_fd=reopened.parent_fd)
        before = os.fstat(descriptor)
        _validate_existing_target(before)
        if (before.st_dev, before.st_ino) != identity:
            raise WeightPlanTargetError("configured weight plan target changed identity")
        if _read_descriptor(descriptor) != rendered:
            raise WeightPlanTargetError("configured weight plan target has different bytes")
        after = os.fstat(descriptor)
        _validate_existing_target(after)
        if not _same_target(before, after):
            raise WeightPlanTargetError("configured weight plan target changed while verified")
        named = _target_stat(reopened.parent_fd, name)
        if named is None or not _same_target(after, named):
            raise WeightPlanTargetError("configured weight plan target changed after verification")
    except OSError as exc:
        raise WeightPlanTargetError("configured weight plan target is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        reopened.close()


def _exact_object(
    value: object,
    *,
    field_name: str,
    keys: frozenset[str],
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise WeightPlanError(f"{field_name} has an unsupported shape")
    return value


def _parse_weight_plan(rendered: bytes) -> WeightPlan:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise WeightPlanError("weight plan contains a duplicate JSON key")
            value[key] = item
        return value

    try:
        document = json.loads(rendered.decode("ascii"), object_pairs_hook=unique_object)
    except WeightPlanError:
        raise
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise WeightPlanError("weight plan is not valid canonical JSON") from exc
    root = _exact_object(
        document,
        field_name="weight plan",
        keys=frozenset(
            {
                "created_block",
                "digest_sha256",
                "expires_at_block",
                "netuid",
                "network",
                "schema",
                "schema_version",
                "snapshot",
                "validator_hotkey",
                "version_key",
                "weights",
            }
        ),
    )
    if root["schema"] != WEIGHT_PLAN_SCHEMA:
        raise WeightPlanError("weight plan schema is unsupported")
    if root["schema_version"] != WEIGHT_PLAN_SCHEMA_VERSION:
        raise WeightPlanError("weight plan schema version is unsupported")
    snapshot_document = _exact_object(
        root["snapshot"],
        field_name="weight plan snapshot",
        keys=frozenset({"block", "epoch", "finalized", "identity_fingerprint", "tempo"}),
    )
    raw_weights = _weight_rows(root["weights"])
    entries: list[WeightPlanEntry] = []
    for raw_entry in raw_weights:
        entry = _exact_object(
            raw_entry,
            field_name="weight plan entry",
            keys=frozenset({"hotkey", "uid", "weight"}),
        )
        entries.append(
            WeightPlanEntry(
                uid=entry["uid"],  # type: ignore[arg-type]
                hotkey=entry["hotkey"],  # type: ignore[arg-type]
                weight=entry["weight"],  # type: ignore[arg-type]
            )
        )
    plan = WeightPlan(
        network=root["network"],  # type: ignore[arg-type]
        netuid=root["netuid"],  # type: ignore[arg-type]
        validator_hotkey=root["validator_hotkey"],  # type: ignore[arg-type]
        snapshot=WeightPlanSnapshot(
            block=snapshot_document["block"],  # type: ignore[arg-type]
            tempo=snapshot_document["tempo"],  # type: ignore[arg-type]
            epoch=snapshot_document["epoch"],  # type: ignore[arg-type]
            finalized=snapshot_document["finalized"],  # type: ignore[arg-type]
            identity_fingerprint=snapshot_document["identity_fingerprint"],  # type: ignore[arg-type]
        ),
        weights=tuple(entries),
        version_key=root["version_key"],  # type: ignore[arg-type]
        created_block=root["created_block"],  # type: ignore[arg-type]
        expires_at_block=root["expires_at_block"],  # type: ignore[arg-type]
    )
    supplied_digest = root["digest_sha256"]
    if supplied_digest != plan.digest_sha256:
        raise WeightPlanError("weight plan digest does not match its canonical document")
    if rendered != plan.canonical_bytes():
        raise WeightPlanError("weight plan bytes are not the exact canonical document")
    return plan


def load_weight_plan(path: str | os.PathLike[str]) -> WeightPlan:
    """Safely load one exact canonical WeightPlan v1 from a pinned path.

    The returned immutable object no longer depends on the configured pathname.
    The complete parent chain, target inode, link count, owner, mode, size, and
    bytes are revalidated before the pinned descriptors are released.
    """

    parent, name = _secure_file_location(path)
    chain = _pin_directory_chain(parent)
    try:
        _revalidate_pinned_chain(chain)
        target = _target_stat(chain.parent_fd, name)
        if target is None:
            raise WeightPlanTargetError("weight plan target does not exist")
        rendered = _read_existing(chain.parent_fd, name, target)
        if not _same_target(target, _target_stat(chain.parent_fd, name)):
            raise WeightPlanTargetError("weight plan target changed during validation")
        _verify_configured_target(
            chain,
            name,
            identity=(target.st_dev, target.st_ino),
            rendered=rendered,
        )
        return _parse_weight_plan(rendered)
    finally:
        chain.close()


def write_weight_plan_atomic(plan: WeightPlan, path: str | os.PathLike[str]) -> bool:
    """Durably install a plan with atomic replacement and strict target checks.

    Returns ``False`` when the already-installed canonical bytes are identical.
    The target's parent must already exist and must not traverse symlinks.
    """

    parent, name = _secure_file_location(path)
    chain = _pin_directory_chain(parent)
    temporary: _TemporaryPlan | None = None
    try:
        directory_fd = chain.parent_fd
        rendered = plan.canonical_bytes()
        if len(rendered) > MAX_WEIGHT_PLAN_BYTES:
            raise WeightPlanError("canonical weight plan exceeds the size limit")
        _revalidate_pinned_chain(chain)
        existing = _target_stat(directory_fd, name)
        if existing is not None:
            existing_bytes = _read_existing(directory_fd, name, existing)
            if not _same_target(existing, _target_stat(directory_fd, name)):
                raise WeightPlanTargetError("weight plan target changed during validation")
            if existing_bytes == rendered:
                _verify_configured_target(
                    chain,
                    name,
                    identity=(existing.st_dev, existing.st_ino),
                    rendered=rendered,
                )
                return False

        temporary = _prepare_temporary_plan(directory_fd, rendered)
        _revalidate_pinned_chain(chain)
        if not _same_target(existing, _target_stat(directory_fd, name)):
            raise WeightPlanTargetError("weight plan target changed before atomic replacement")
        _validate_temporary_descriptor(
            temporary,
            expected_size=len(rendered),
            expected_nlink=1,
        )
        _validate_temporary_name(temporary, directory_fd, expected_size=len(rendered))
        assert temporary.name is not None
        os.replace(
            temporary.name,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary.name = None
        _validate_temporary_descriptor(
            temporary,
            expected_size=len(rendered),
            expected_nlink=1,
        )
        installed = _target_stat(directory_fd, name)
        if installed is None or (installed.st_dev, installed.st_ino) != temporary.identity:
            raise WeightPlanTargetError("installed weight plan target changed identity")
        os.fsync(directory_fd)
        _validate_temporary_descriptor(
            temporary,
            expected_size=len(rendered),
            expected_nlink=1,
        )
        _verify_configured_target(
            chain,
            name,
            identity=temporary.identity,
            rendered=rendered,
        )
        return True
    finally:
        if temporary is not None and temporary.name is not None:
            try:
                named = os.stat(
                    temporary.name,
                    dir_fd=chain.parent_fd,
                    follow_symlinks=False,
                )
                if (named.st_dev, named.st_ino) == temporary.identity:
                    os.unlink(temporary.name, dir_fd=chain.parent_fd)
            except FileNotFoundError:
                pass
        if temporary is not None:
            os.close(temporary.descriptor)
        chain.close()
