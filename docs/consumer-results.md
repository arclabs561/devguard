# Import consumer evidence

Use a report produced by a trusted first-party CI job or a local verification. Supply the repository and exact revisions from a separate source. The importer reads a single JSON file. It treats evidence references as labels and never fetches them or runs producer instructions. Trust in the producer and its artifacts comes from the CI or local environment.

```sh
devguard consumer-results evidence.json --repository org/writer \
  --base aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --head bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

The following version 1 report records a successful producer process whose consumer assertion failed.

```json
{
  "schema_version": 1,
  "repository": "org/writer",
  "cases": [{
    "fixture": "released-reader",
    "assertion": "released decoder reads the exported image",
    "tool": "decoder 1.2.0",
    "base": {
      "revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "outcome": "pass",
      "exit_code": 0,
      "evidence": "logs/base-decoder.txt"
    },
    "head": {
      "revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "outcome": "fail",
      "exit_code": 0,
      "reason": "decoder rejected the artifact header",
      "evidence": "logs/head-decoder.txt",
      "artifact": {
        "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "package": "image-writer",
        "version": "1.3.0",
        "registry": "local"
      }
    }
  }]
}
```

Use one case per fixture and assertion. Both observations describe the same assertion with the recorded tool and fixture. Revisions are full lowercase Git object IDs. Record the tested combined-tree commit when CI tested a merge. An optional observation-level `command` array preserves the producer argv as data. The raw exit code can be omitted or null when no process ran. A referenced artifact requires its SHA-256 digest. Packaged artifacts can also identify the package, version and registry. Unknown optional fields are ignored. Duplicate JSON object keys are rejected because they can hide conflicting outcomes, revision IDs or artifact digests.

A base pass followed by a head failure is a regression. A failing base, stale revision, mismatched repository, missing comparison observation, or skipped or errored execution is inconclusive. Conflicting outcomes at the same revision and conflicting package or registry identities also produce inconclusive comparisons. Version and digest changes are expected for upgrades. Include a reason for every skip and error. Omit the base and its CLI flag for a single observed pass or failure. This records the condition at that revision without attributing it to a change.

The JSON output preserves the observations and the decision for each case. Exit 1 indicates an observed failure or regression, even if another case is inconclusive. Exit 3 indicates only inconclusive cases or bad input alongside any passes. Exit 0 means all cases passed. These observations concern only the named consumer assertions.
