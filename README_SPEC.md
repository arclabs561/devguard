# devguard Monitoring Spec

devguard uses a declarative YAML specification to define what resources to monitor. This makes it easy to customize discovery without changing code.

## Quick Start

### Create a spec interactively

```bash
devguard spec --init
```

This will ask you what to discover and create a `devguard.spec.yaml` file.

### Generate spec from current .env

```bash
devguard spec --from-env
```

This reads your current `.env` configuration and generates a spec that matches it.

### Edit your spec

```bash
devguard spec --edit
```

Opens the spec file in your `$EDITOR`.

## Spec Structure

A spec file looks like this:

```yaml
name: my-monitoring
description: Monitor my projects

discovery_rules:
  - name: npm_list
    type: npm
    method: cli
    command: npm list --depth=0 --json
    command_parser: json
    extract_path: dependencies.keys()
    timeout: 10
    enabled: true

  - name: github_repos
    type: github
    method: cli
    command: gh repo list --json nameWithOwner --limit 100
    command_parser: json
    extract_path: "[].nameWithOwner"
    timeout: 10
    enabled: true

manual_resources:
  npm: [package1, package2]
  github: [owner/repo1, owner/repo2]
```

## Discovery Methods

### CLI Method

Runs a command and parses the output:

```yaml
- name: my_rule
  type: mytype
  method: cli
  command: my-command --json
  command_parser: json  # json, json_lines, lines, text
  extract_path: "[].name"  # Optional: JSON path to extract
  timeout: 10
```

### File Scan Method

Scans files matching a pattern:

```yaml
- name: my_rule
  type: mytype
  method: file_scan
  file_pattern: "**/package.json"
  file_extractor: json_path  # json_path, yaml_path, regex, raw
  extract_path: name  # Path to extract (JSON/YAML path, regex, or ignored for raw)
  timeout: 30
```

## Using Discovery

### Discover resources

```bash
devguard discover
```

Shows what was discovered without changing anything.

### Discover and update .env

```bash
devguard discover --update-env
```

Discovers resources and automatically updates your `.env` file.

### JSON output

```bash
devguard discover --json
```

Outputs discovery results as JSON for scripting.

## Examples

### Minimal spec (just npm)

```yaml
name: npm-only
discovery_rules:
  - name: npm_list
    type: npm
    method: cli
    command: npm list --depth=0 --json
    command_parser: json
    extract_path: dependencies.keys()
```

### Custom discovery rule

```yaml
discovery_rules:
  - name: my_custom_rule
    type: custom_type
    method: cli
    command: my-tool list --format json
    command_parser: json
    extract_path: "[].id"
    timeout: 5
    enabled: true
    metadata:
      description: "Custom discovery for my tool"
```

## Best Practices

1. **Start simple**: Use `devguard spec --init` to get started
2. **Test discovery**: Run `devguard discover` before `--update-env`
3. **Customize gradually**: Edit the spec file to add/remove rules
4. **Use timeouts**: Set reasonable timeouts to avoid hanging on slow commands
5. **Combine methods**: Use both CLI and file_scan for comprehensive discovery

