# Sandbox probe images

Status: **not published.** The builder, the pins and a manual publication
workflow are reviewed here. Nothing is pushed until the repository's owner,
the GitHub user account `misscomputer` (not an organisation), decides to
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
references to equal the committed pins. The ordinary `ci` workflow runs this
check, and shellcheck on the script, on every push and pull request. So a
builder or manifest edit that does not reproduce the pins fails before
review.

## Publication

`.github/workflows/publish-sandbox-probes.yml` runs only on manual dispatch.

- **`publish` mode:**
  - The job runs in the `probe-publication` environment (see Owner steps).
  - Before it touches the registry, it reads the environment's settings with the job token (`actions: read`) and refuses unless all of these hold:
    - at least one required reviewer;
    - "Prevent self-review" on, so the person who dispatches a run cannot approve it;
    - administrators cannot bypass;
    - deployments are allowed from exactly the branch `main`.

    GitHub creates an environment named in a workflow, without any protection, if it does not exist yet. This check makes such a run fail.
  - It refuses unless it runs on `main` at the full commit SHA given as `expected_sha`.
  - It rebuilds and verifies the layout as above.
  - It installs oras 1.3.4, checked against its pinned SHA-256.
  - With the job's `GITHUB_TOKEN` (`packages: write`, `contents: read`; no personal token or stored secret), it copies each pinned manifest to `ghcr.io/misscomputer/sandbox-probes:<probe>-v1`. `oras cp --from-oci-layout` copies the manifest, config and layer bytes unchanged, so the pushed digests are the pinned ones. Then it resolves every pin by digest and by tag.
  - It never overwrites a tag that names another digest. A tag counts as absent only when oras answers exactly `Error response from registry: failed to resolve digest: <repository>:<tag>: not found` (or, for a local layout dry run, `Error: failed to resolve digest: not found`). Any other lookup failure stops the run, including one whose text merely contains "not found", such as a missing credential helper.
  - Its record (run, oras version and checksum, pushed digests) is uploaded as an artifact.
- **`check-public` mode** has no write permission and uses no credentials. It reads every pinned manifest, every blob it names and every `<probe>-v1` tag anonymously, and requires their SHA-256 digests to match. A re-pointed tag therefore fails it.

A first run fails until the package is public. Tags only keep the versions
from being cleaned up as untagged; identity is always the digest.

## Owner steps

These are outside the repository.

- **Environment (before any dispatch):** in the repository's settings under Environments, the repository owner (the user `misscomputer`) or a repository admin creates `probe-publication` with:
  - **Required reviewers:** at least one person or team who will not dispatch the run. Turn on "Prevent self-review". A dispatcher cannot approve their own run, so publishing needs a second person with read access to the repository. With only the owner's account, add a collaborator first; turning self-review prevention off makes the publish job refuse to run.
  - **Allow administrators to bypass configured protection rules:** off.
  - **Deployment branches and tags:** "Selected branches and tags", with exactly one rule: the branch `main`.
  - **No environment secrets or variables:** the job uses only its own token.

  The publish job checks the reviewer, self-review, bypass and branch settings and stops if any is missing.
- **Visibility:** the package belongs to the user account `misscomputer`.
  After the first publish, that account sets `ghcr.io/misscomputer/sandbox-probes`
  to public in the package settings. The job token cannot do this.
- **Repository link:** the owner links the package to this repository in the
  package settings. Adding `org.opencontainers.image.source` or any other
  label at push time would change the manifest bytes and therefore the
  pins.
- **Retention:** keep every pinned version while any evidence record, review
  or contract version cites it, and for at least 180 days. Delete only by a
  later explicit decision, by digest. A changed image is a new builder
  revision with new `-v2` tags and pins, never an overwrite.

## What the environment does not cover

The environment's branch policy and required reviewers apply to jobs that name the environment. The job token's `packages: write` comes from the `permissions:` of whichever workflow file runs, not from the environment.

A person with write access to this repository can therefore push a branch with a modified copy of this workflow, or any other workflow, that drops `environment:` and its checks, and dispatch it. That job's token can push tags and new digests to `ghcr.io/misscomputer/sandbox-probes`. This is the same capability every repository writer already has for any package this repository's workflows can write. No guard in a workflow file can remove it, because the writer controls the file.

The consequences are bounded:
- **The pinned bytes cannot change:** consumers (P3, the D23 lab) pull `repository@digest`, and a digest names the bytes.
- **A re-pointed or new tag is detectable:** `check-public` reads every `<probe>-v1` tag and requires the pinned digest.

Closing the gap server-side is an owner decision outside this change. Two options:
- **Limit write access** to the repository to the people trusted to publish.
- **Use a credential only the environment holds:** for example, a GitHub App installation token whose private key is an environment secret, used instead of the job token for the push. The owner then removes this repository's Actions access in the package settings ("Manage Actions access"). That access is what lets any job token of the repository write the package, and a workflow that first publishes the package receives it automatically. After that, a job outside the environment cannot push, whatever its `permissions:` say. This brings back a long-lived credential, which the current design avoids, and needs a change to the push step.
