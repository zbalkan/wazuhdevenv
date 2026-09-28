# wazuhdevenv

`wazuhdevenv` provisions and maintains a local Wazuh rule and decoder development environment.

The installable Python CLI owns environment preparation; default Wazuh regression content is distributed independently by [wazuh-rule-tests](https://github.com/zbalkan/wazuh-rule-tests), and logtest communication is provided by [wazuhtester](https://github.com/zbalkan/wazuhtester).

## Architecture

The tooling is deliberately separated by responsibility:

| Project | Responsibility |
| --- | --- |
| [`wazuhtester`](https://github.com/zbalkan/wazuhtester) | reusable Wazuh logtest library, CLI, and pytest plugin |
| [`wazuh-rule-tests`](https://github.com/zbalkan/wazuh-rule-tests) | versioned pytest regression corpus for built-in Wazuh rules |
| [`wazuhcoverage`](https://github.com/zbalkan/wazuhcoverage) | runtime Wazuh JSON archive coverage analysis |
| [`wazuhtestgen`](https://github.com/zbalkan/wazuhtestgen) | generation of pytest rule-test content |
| `wazuhdevenv` | environment installation, configuration, managed content, and orchestration |

## Installation

For CLI use, install `wazuhdevenv` with an isolated application installer. Before the first PyPI release, install the current `main` branch directly:

```bash
pipx install "git+https://github.com/zbalkan/wazuhdevenv.git@main"
```

After the package is published to PyPI, the stable installation command will be:

```bash
pipx install wazuhdevenv
```

A development checkout can be installed with:

```bash
python -m pip install -e ".[dev]"
```

The tool supports Linux. WSL is supported because the Wazuh manager and the tool run inside Linux.

## Initialize a workspace

Create or enter a project directory and run:

```bash
mkdir my-wazuh-rules
cd my-wazuh-rules
wazuhdevenv init
```

An explicit workspace path is also accepted:

```bash
wazuhdevenv init ~/projects/my-wazuh-rules
```

`init` is a one-shot provisioning operation. After a successful initialization, any later `init` invocation fails immediately using the recorded state; it does not reconcile, repair, switch, or re-provision the environment. It performs the following:

- detects APT, DNF, or YUM;
- installs or verifies Wazuh Manager;
- optionally pins the requested Wazuh version;
- disables the Wazuh package repository after installation;
- creates `rules/`, `decoders/`, and `tests/`;
- creates the workspace `.venv`;
- installs pytest and the released `wazuhtester` package into that venv;
- enables JSON archive output required by the development workflow;
- disables unnecessary manager modules used by the old development profile;
- configures the Wazuh `rule_test` service for development throughput;
- applies the known rule-60000 Windows EventChannel testing transformation;
- expects a fresh/default Wazuh rules/decoders installation, ignores Wazuh's disposable `local_rules.xml` and `local_decoder.xml` samples, and refuses to migrate other existing custom content;
- bind-mounts workspace rules and decoders into `/var/ossec/etc`;
- persists the mounts in `/etc/fstab`;
- adds the invoking developer to the `wazuh` group, which is required to use Wazuh tooling without root;
- keeps the invoking developer as owner of workspace rules and decoders while granting the `wazuh` group access;
- when `setfacl` is available and the filesystem supports ACLs, adds optional default ACLs so future rule and decoder files remain accessible to the `wazuh` account and group;
- validates Wazuh configuration using Wazuh's own `-t` checks;
- backs up and restores the Wazuh configuration, Windows testing rule, fstab entries, and newly created bind mounts if host configuration fails;
- starts the manager and waits for a stable logtest socket;
- initializes `~/.wazuhdevenv`;
- downloads and validates the default rule-test corpus whose version exactly matches the installed Wazuh version unless `--skip-corpus` is specified; corpus failures are fatal and reported to the user.

The CLI is intended to be run as the developer:

```bash
wazuhdevenv init
```

It invokes `sudo` only for operations that require system privileges. Do not run the CLI itself with `sudo` or as root. If `init` adds your account to the `wazuh` group, start a new login session before using Wazuh tools without `sudo`; an already-running shell cannot acquire newly assigned supplementary groups. Default ACLs are only a maintenance helper: they preserve access for future files but do not change file ownership. If `setfacl` is unavailable or the filesystem rejects ACLs, initialization continues normally.

Do not run `init` again after it succeeds. A second invocation exits with the recorded workspace, Wazuh home, Wazuh version, and state-file path so the environment can be inspected manually. If only the managed rule-test corpus needs attention, use `wazuhdevenv update`; `init` does not act as a repair command.

To require an exact Wazuh version:

```bash
wazuhdevenv init --wazuh-version 4.14.8
```

For development before a corpus release is available:

```bash
wazuhdevenv init --skip-corpus
```

Wazuh installs sample `local_rules.xml` and `local_decoder.xml` files. In a workspace provisioned by `wazuhdevenv`, these samples are not treated as user
content and are never copied into the project. Users can add their own rule or decoder files later, including files with those names if they choose.

## Workspace

User-owned content stays in the project:

```text
my-wazuh-rules/
├── .venv/
├── rules/
├── decoders/
└── tests/
```

The workspace virtual environment belongs to the project. It is deliberately separate from the private environment used by `pipx` to run `wazuhdevenv`.

## Run rule and decoder tests

`wazuhdevenv` prepares the environment and managed test content. It does not provide a separate test runner; use pytest from the workspace virtual environment.

Run your workspace tests:

```bash
.venv/bin/python -m pytest tests --wazuh-require-logtest
```

Run the managed Wazuh regression corpus:

```bash
.venv/bin/python -m pytest \
  "${WAZUHDEVENV_HOME:-$HOME/.wazuhdevenv}/current-corpus/tests" \
  --wazuh-require-logtest
```

Run both together:

```bash
.venv/bin/python -m pytest \
  tests \
  "${WAZUHDEVENV_HOME:-$HOME/.wazuhdevenv}/current-corpus/tests" \
  --wazuh-require-logtest
```

These are ordinary pytest suites, so normal pytest selection, markers, fail-fast options, IDE integration, and plugins remain available without a `wazuhdevenv` wrapper.

## Report custom rule test coverage

`wazuhdevenv coverage` reports how many custom rule IDs defined under the initialized workspace's `rules/` directory are explicitly referenced by tests under `tests/`.

```bash
wazuhdevenv coverage
```

The analysis is static and read-only. It recognizes direct rule-ID assertions such as `assert response.rule_id == "100100"`, the equivalent reversed comparison, legacy `assertEqual` calls, and pytest parametrization where `rule_id` is one of the parameter columns. Built-in Wazuh rules are intentionally excluded: their regression corpus is maintained separately by `wazuh-rule-tests`.

Example output:

```text
=== Wazuh Rule Coverage Report ===
Total rules defined: 2
Total test functions: 1
Rules referenced in tests: 1
Coverage: 50.00%

Uncovered Rule IDs:
  - 222016
```

This is different from `wazuhcoverage`, which analyzes runtime Wazuh JSON archive coverage rather than static test-to-rule coverage.

## Managed state

Tool-managed state defaults to:

```text
~/.wazuhdevenv/
├── state.json
├── current-corpus -> corpora/<active-release>/
├── cache/
├── corpora/
└── logs/
```

Override the root for CI or disposable environments with:

```bash
export WAZUHDEVENV_HOME=/path/to/state
```

Do not store custom rules, decoders, or project tests under this directory.

## Update managed tests

```bash
wazuhdevenv update
```

`update`:

1. detects the installed Wazuh version;
2. reads `wazuh-rule-tests` GitHub Release manifests;
3. selects the corpus whose `version` exactly matches the installed Wazuh version;
4. downloads the ZIP and its SHA-256 checksum;
5. verifies the digest;
6. rejects unsafe ZIP paths, symlinks, and special files;
7. validates that the external and embedded manifests match;
8. extracts into a new versioned corpus directory;
9. atomically repoints `current-corpus` to the selected corpus;
10. records the active corpus in `state.json`.

Check what would be selected without modifying state:

```bash
wazuhdevenv update --check
```

`update` does not upgrade Wazuh Manager, `wazuhdevenv`, `wazuhtester`, or user content. Corpus compatibility is exact: Wazuh `4.14.7` uses corpus `4.14.7`; a corpus for another Wazuh version is not selected.

## Uninstall the development environment

Remove the host integration created by `wazuhdevenv` with:

```bash
wazuhdevenv uninstall
```

The command is ownership-aware. It removes only state that can be attributed to `wazuhdevenv`, restores pre-existing Wazuh state where provenance is available, and refuses to overwrite Wazuh configuration that changed after initialization.

For a normal environment created by current versions, teardown first validates the managed mount state, the exact `/etc/fstab` entries, and package-directory safety before changing host state. When Wazuh Manager was installed by `wazuhdevenv`, an active bind mount that predates initialization causes a safe refusal before Wazuh is stopped or workspace access is changed. After preflight, the command stops Wazuh Manager, unmounts the managed `rules` and `decoders` directories and verifies that they are no longer mount points, removes the matching `/etc/fstab` entries, verifies that neither package directory nor any content below it is mounted, empties the underlying `/var/ossec/etc/rules` and `/var/ossec/etc/decoders` package directories while preserving the directories themselves, restores their expected `root:wazuh` ownership and `0770` mode (creating them only if missing), uninstalls the `wazuh-manager` package, and finally removes managed `wazuhdevenv` state.

Uninstall also:

- unmounts the managed `rules` and `decoders` bind mounts;
- removes only the exact matching entries added to `/etc/fstab`;
- removes the developer's `wazuh` group membership only when `init` added it;
- removes Wazuh-specific default ACL entries and returns files still using the `wazuh` group to the invoking user's primary group;
- removes the workspace `.venv` only when `wazuhdevenv` created it;
- removes the managed `~/.wazuhdevenv` state, caches, corpora, and logs;
- removes Wazuh Manager and the tool-owned `/var/ossec` tree only when `wazuhdevenv` installed Wazuh;
- restores or removes the Wazuh package repository according to its recorded pre-initialization state;
- removes an APT Wazuh keyring when the tool created it and doing so would not break a repository configuration modified after initialization;
- when Wazuh already existed before `init`, preserves the package and restores the exact pre-initialization `ossec.conf`, Windows rule file, and service state recorded during provisioning.

User content under `rules/`, `decoders/`, and `tests/` is always preserved. If a pre-existing workspace virtual environment was present, it is preserved as well.

On successful completion, uninstall prints a final inventory with four sections: `Removed`, `Restored`, `Preserved`, and `Remnants`. Preflight refusals return an error before teardown begins and therefore do not print a completion inventory. The remnant list is deliberate; the command does not claim to return the host to an unknowable pristine state.

Known intentional remnants include the `wazuhdevenv` Python or pipx installation itself, which must be removed using the installer that installed the CLI. A small sibling lock file is also retained outside the managed state directory so concurrent commands remain serialized while that directory is deleted. System prerequisite packages installed during provisioning are also retained because they may have acquired other consumers; current state records the exact package names so uninstall can report them. Package-manager cache and metadata changes made by APT, DNF, or YUM are not rolled back.

Workspace permission modes are not reconstructed. Initialization standardizes rule and decoder directories/files to development permissions, currently `0770` and `0660`. Uninstall removes Wazuh-specific group/ACL access but does not have enough information to restore arbitrary per-file modes or a pre-initialization non-primary group. Pre-existing/default ACL base and mask entries are preserved. If group membership was removed, already-running login sessions may continue to carry the old supplementary group until a new login session starts.

On RPM-family systems, an RPM signing-key database entry imported during Wazuh repository setup is not removed automatically because its prior ownership cannot be attributed safely. Wazuh system users or groups may also remain if the distribution package's uninstall scripts deliberately retain them; the final report detects and lists those accounts when present.

State created before uninstall provenance tracking is handled conservatively. The command can clean exact managed mounts, fstab entries, and reversible Wazuh configuration changes, but it preserves components whose ownership cannot be proved, including the Wazuh package, user group membership, workspace `.venv`, and legacy initialization backup files. Those preserved remnants are printed explicitly.

## Development

Run the package tests:

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

The unit suite does not alter the host Wazuh installation.

## License

GNU General Public License version 2 only. See [LICENSE](LICENSE).
