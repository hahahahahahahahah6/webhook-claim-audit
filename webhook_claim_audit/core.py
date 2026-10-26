"""Static documentation and subscriber delivery analysis."""
import ast
import fnmatch
import re
from pathlib import Path

WEBHOOK = ('sends webhooks', 'sends webhook notifications', 'webhook notifications',
           'webhook support', 'supports webhooks', 'supports webhook notifications',
           'notifies via webhook', 'notifies via webhooks', 'delivers webhooks',
           'webhook delivery', 'posts webhooks', 'triggers webhooks', 'emits webhooks',
           'sends events via webhook', 'sends events via webhooks', 'webhook integration')
NOWEBHOOK = ('no webhook support', 'does not support webhooks', 'no webhooks',
             'does not send webhooks', 'webhooks not supported',
             'no webhook notifications', 'does not deliver webhooks')
KEYS = {'webhook_url', 'webhooks', 'subscriber_url', 'callback_url'}


def pattern(phrases):
    return re.compile(r'\b(?:' + '|'.join(re.escape(s) for s in sorted(phrases, key=len, reverse=True)) + r')\b')


def prose(text):
    lines = []
    fence = None
    for line in text.splitlines():
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            lines.append('')
        elif fence is None:
            lines.append(line)
    return [' '.join(part.lower().replace('-', ' ').split())
            for part in re.split(r'\n\s*\n', '\n'.join(lines))]


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return dotted(node.value) + '.' + node.attr
    if isinstance(node, ast.Subscript):
        return dotted(node.value)
    return ''


def registry(node, loops=()):
    name = dotted(node)
    if name and (any(s in name.lower() for s in ('webhook', 'subscriber')) or name.split('.')[0] in loops):
        return True
    if isinstance(node, ast.Subscript):
        key = node.slice
        if isinstance(key, ast.Index):
            key = key.value
        return isinstance(key, ast.Constant) and key.value in KEYS
    if isinstance(node, ast.Call):
        return any(isinstance(a, ast.Constant) and a.value in KEYS
                   for a in list(node.args) + [k.value for k in node.keywords])
    return False


def outbound(node):
    func = node.func
    name = dotted(func)
    if isinstance(func, ast.Attribute) and func.attr in ('post', 'put'):
        base = dotted(func.value).lower().split('.')
        return any(x in ('requests', 'httpx', 'urllib', 'session', 'client', 'opener')
                   or x.endswith(('_session', '_client', '_opener')) for x in base)
    if name in ('urllib.request.urlopen', 'urllib.request.Request', 'urlopen', 'Request'):
        keyword_post = any(k.arg == 'method' and isinstance(k.value, ast.Constant)
                           and k.value.value == 'POST' for k in node.keywords)
        positional_post = (name in ('urllib.request.Request', 'Request')
                           and len(node.args) > 5
                           and isinstance(node.args[5], ast.Constant)
                           and node.args[5].value == 'POST')
        return keyword_post or positional_post
    return False


def delivery(tree):
    bindings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None and registry(node.value):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            bindings.update(t.id for t in targets if isinstance(t, ast.Name))
    found = []

    def visit(node, loops):
        if isinstance(node, (ast.For, ast.AsyncFor)):
            visit(node.iter, loops)
            bound = set(loops)
            if registry(node.iter, loops):
                bound.update(n.id for n in ast.walk(node.target) if isinstance(n, ast.Name))
            for child in node.body:
                visit(child, bound)
            for child in node.orelse:
                visit(child, loops)
            return
        if isinstance(node, ast.Call) and outbound(node):
            url = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == 'url'), None)
            if url is not None and (registry(url, loops) or isinstance(url, ast.Name) and url.id in bindings):
                found.append(node.lineno)
        for child in ast.iter_child_nodes(node):
            visit(child, loops)
    visit(tree, set())
    return found


def audit(root, ignores=(), fail_on='MEDIUM'):
    root = Path(root)
    if not root.is_dir():
        raise ValueError('ROOT must be an existing directory')
    claims = []
    evidence = []

    def walk(directory):
        for path in sorted(directory.iterdir()):
            rel = path.relative_to(root).as_posix()
            if path.is_symlink() or path.name.startswith('.') or any(fnmatch.fnmatchcase(rel, g) for g in ignores):
                continue
            if path.is_dir():
                yield from walk(path)
            elif path.is_file():
                yield path, rel
    for path, rel in walk(root):
        parts = Path(rel).parts
        if rel == 'README.md' or path.suffix.lower() == '.md' and 'docs' in parts[:-1]:
            for paragraph in prose(path.read_text(encoding='utf-8')):
                negative = pattern(NOWEBHOOK)
                for family, text, regex in (('NOWEBHOOK', paragraph, negative),
                                            ('WEBHOOK', negative.sub(' ', paragraph), pattern(WEBHOOK))):
                    if regex.search(text):
                        claim = {'family': family, 'path': rel, 'severity': 'MEDIUM' if parts[0] == 'tests' else 'HIGH'}
                        if claim not in claims:
                            claims.append(claim)
        if path.suffix == '.py' and 'tests' not in parts[:-1] and not path.name.startswith('test_'):
            try:
                tree = ast.parse(path.read_text(encoding='utf-8'), filename=rel)
            except (SyntaxError, UnicodeError) as exc:
                raise ValueError('Cannot parse ' + rel + ': ' + str(exc)) from exc
            evidence.extend({'path': rel, 'line': line} for line in delivery(tree))
    findings = []
    for family, rule, false in (('WEBHOOK', 'documented-webhook-claim-false', not evidence),
                                 ('NOWEBHOOK', 'documented-no-webhook-claim-false', bool(evidence))):
        matched = [c for c in claims if c['family'] == family]
        if matched and false:
            claim = sorted(matched, key=lambda c: (c['severity'] != 'HIGH', c['path']))[0]
            findings.append({'rule': rule, 'severity': claim['severity'], 'path': claim['path']})
    failed = any(fail_on == 'MEDIUM' or f['severity'] == 'HIGH' for f in findings)
    return {'status': 'FAIL' if failed else 'PASS', 'evidence': evidence, 'claims': claims, 'findings': findings}
