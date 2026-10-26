# webhook-claim-audit

A stdlib-only static documentation auditor for Python projects. It compares statements about outbound subscriber notifications with AST evidence. Source files are parsed, never executed. Requires Python 3.9 or newer.

Install and run:

```sh
python3 -m pip install .
webhook-claim-audit /path/to/project
python3 -m webhook_claim_audit /path/to/project --json
python3 -m webhook_claim_audit --version
```

Root README.md and Markdown files with a docs directory component supply claims. Fenced blocks are excluded; inline code counts. Matching lowercases text, replaces hyphens with spaces, joins paragraph lines, and uses word boundaries. Negative spans are removed before positive matching.

Positive phrases:

```text
sends webhooks
sends webhook notifications
webhook notifications
webhook support
supports webhooks
supports webhook notifications
notifies via webhook
notifies via webhooks
delivers webhooks
webhook delivery
posts webhooks
triggers webhooks
emits webhooks
sends events via webhook
sends events via webhooks
webhook integration
```

Negative phrases:

```text
no webhook support
does not support webhooks
no webhooks
does not send webhooks
webhooks not supported
no webhook notifications
does not deliver webhooks
```

Evidence requires an outbound POST or PUT through a requests/httpx/urllib family client, session, or opener. urllib Request/urlopen also qualifies with a literal POST method. The destination must reference a webhook/subscriber name, a registry loop variable within its loop, or a subscript/call with a recognized key. A name assigned directly from such an expression in the same module also qualifies; assignment chains are not followed.

```text
webhook_url
webhooks
subscriber_url
callback_url
```

Constant destinations, generic destination variables, GET calls, bare registries, incoming route handlers, comments, docstrings, and unrelated string literals are insufficient. Registry bindings do not cross modules. Tests directories and test_*.py files are excluded from evidence. Symlinks and dotfiles/directories are skipped. Invalid source or unreadable input produces an input error. This is a syntactic check: it cannot establish runtime reachability or successful network delivery.

Findings (one per family):

```text
documented-webhook-claim-false HIGH
documented-no-webhook-claim-false HIGH
```

The first identifies a positive statement without evidence, including projects without source. The second identifies a negative statement contradicted by evidence. Statements found only under tests/docs have MEDIUM severity. No statement means PASS.

Options: optional ROOT defaults to the current directory; --json emits status, evidence, claims, and findings; --verbose adds paths; --ignore accepts one or more fnmatch patterns against POSIX relative paths (matching directories exclude descendants); --fail-on HIGH|MEDIUM selects the exit threshold, default MEDIUM. Exit codes are 0 for no findings at the threshold, 2 for findings at the threshold, and 1 for usage/input errors. JSON retains findings below the threshold while status reflects the selected threshold.

Development:

```sh
python3 -m unittest discover
python3 -m build
```
