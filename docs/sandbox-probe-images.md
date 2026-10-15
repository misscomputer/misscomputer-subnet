# Sandbox probe images

Status: **not published.** The builder, the pins and a manual publication
workflow are reviewed here. Nothing is pushed until an org owner decides to
publish and to make the package public.

`GVisor.Create` pulls every image by digest from a public registry: the
backend supports no registry credentials, and D8 refuses local and private
registries before any engine call. The digest-pinned proofs of `Create` for
D11 (workload exits) and D23 (never-started starts) therefore need these
images on a public registry, at exactly the reviewed bytes.

## The images

`scripts/sandbox-probes/build_probe_images.py` builds nine linux/amd64 probe
images as one OCI image layout. It uses only the Python standard library: no
network, credentials or container engine. Every byte is a function of that
file:
- the tar headers are fixed;
- the layers are uncompressed OCI tar;
- the JSON is canonical;
- the configs have no `created` or `history` fields;
- the ELF binaries are assembled from fixed instruction bytes.

`scripts/sandbox-probes/probe-images.manifest.json` pins every manifest,
config and layer digest.

| probe | Entrypoint / User | manifest digest | expected Create outcome |
|---|---|---|---|
| probe-pause | `/probe-pause` | `sha256:6af656b1be6991ede796a958e54b5b3eb3f7506319f2384382ec5f6e5858f86f` | ready (positive control) |
| probe-exits | `/probe-exits` | `sha256:228eddc01cb41c951cc2966d4bc985fc1727651f754f36af55ec8ab763a879aa` | D11: served |
| probe-no-command | none | `sha256:b95ff56224d4d9259b0a5e95931008f0df104bc54536e93049934cb724c50da5` | `image_unavailable` before create |
| probe-missing-command | `/no/such/command` | `sha256:8c34a048271307fa124f890f58200a9f3ddd1f4677eeef918d9cfc9f21c6a2b2` | D23: never started |
| probe-noexec | `/probe-noexec` (mode 0644) | `sha256:131bcb3f0ae721dad7551e6b366ae4f4beeae7962092abcefb206716f8e1ffa9` | D23: never started |
| probe-arm64-elf | `/probe-arm64` (aarch64) | `sha256:27a0f777c2fd99798bdc1ac7b1ab180729badf4fb471dfd53b7ac6e351f71ca1` | D23: never started |
| probe-missing-interpreter | `/probe-script` | `sha256:54bfeebcaf0ef5dbe995e8413992d50456476304aa43f1e3e38b87020c4fb7b2` | D23 expected, not yet observed |
| probe-missing-elf-loader | `/probe-dynamic` | `sha256:57a2379eb3a1140ec99e7d3fa09719e584c96bf8c838564edc845bf6844561f0` | D23 expected, not yet observed |
| probe-unknown-user | `/probe-exits`, User `probe-nosuchuser` | `sha256:7c8bb0708ab14fd2af6c93cc81dbc2b06e9cfdb5d367d9b5f647007614e14e1b` | D23 expected, not yet observed |

The committed manifest is authoritative; this table only repeats it. To
check the bytes locally:

```
scripts/sandbox-probes/publish-probes.sh layout OUT_DIR
```

That rebuilds the layout and requires `build_probe_images.py --verify` to
pass, so every blob matches a rebuild. It also requires the layout's nine
references to equal the committed pins.

## Publication

`.github/workflows/publish-sandbox-probes.yml` runs only on manual dispatch.

- **`publish` mode:**
  - It refuses unless it runs on `main` at the full commit SHA given as `expected_sha`.
  - It rebuilds and verifies the layout as above.
  - It installs oras 1.3.4, checked against its pinned SHA-256.
  - With the job's `GITHUB_TOKEN` (`packages: write`, `contents: read`; no personal token or stored secret), it copies each pinned manifest to `ghcr.io/misscomputer/sandbox-probes:<probe>-v1`. `oras cp --from-oci-layout` copies the manifest, config and layer bytes unchanged, so the pushed digests are the pinned ones. Then it resolves every pin by digest and by tag.
  - It never overwrites a tag that names another digest.
  - Its record (run, oras version and checksum, pushed digests) is uploaded as an artifact.
- **`check-public` mode** has no write permission and uses no credentials. It reads every pinned manifest and every blob it names anonymously, and requires their SHA-256 digests to match.

A first run fails until the package is public. Tags only keep the versions
from being cleaned up as untagged; identity is always the digest.

## Owner steps

These are outside the repository:
- **Visibility:** an org owner sets `ghcr.io/misscomputer/sandbox-probes` to
  public in the package settings, once the organisation allows public
  packages. The token cannot do this.
- **Repository link:** the owner links the package to this repository in the
  package settings. Adding `org.opencontainers.image.source` or any other
  label at push time would change the manifest bytes and therefore the
  pins.
- **Retention:** keep every pinned version while any evidence record, review
  or contract version cites it, and for at least 180 days. Delete only by a
  later explicit decision, by digest. A changed image is a new builder
  revision with new `-v2` tags and pins, never an overwrite.
