import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from webhook_claim_audit.cli import main
from webhook_claim_audit.core import audit, WEBHOOK, NOWEBHOOK


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')

    def check(self, source='', claim='supports webhooks', expected=False):
        self.write('README.md', claim)
        if source:
            self.write('app.py', source)
        result = audit(self.root)
        self.assertEqual(bool(result['evidence']), expected)
        self.assertEqual(result['status'], 'PASS' if expected else 'FAIL')
        if not expected:
            self.assertEqual(result['findings'], [{'rule': 'documented-webhook-claim-false', 'severity': 'HIGH', 'path': 'README.md'}])
        return result

    def test_registry_name(self):
        self.check('requests.post(webhook_url)', expected=True)

    def test_attribute(self):
        self.check('client.post(subscriber.url)', expected=True)

    def test_subscript_registry(self):
        self.check('session.post(self.webhook_urls[i])', expected=True)

    def test_config_keys(self):
        for key in ('webhook_url', 'webhooks', 'subscriber_url', 'callback_url'):
            with self.subTest(key=key):
                self.check('httpx.post(config["' + key + '"])', expected=True)

    def test_config_get(self):
        self.check('requests.put(settings.get("webhook_url"))', expected=True)

    def test_loop_variable(self):
        self.check('for url in webhooks:\n    requests.post(url)', expected=True)

    def test_loop_attribute(self):
        self.check('for item in self.subscribers:\n    client.post(item.url)', expected=True)

    def test_loop_binding_does_not_escape(self):
        self.check('for url in webhooks:\n    pass\nrequests.post(url)')

    def test_assignment(self):
        self.check('url = subscriber["webhook_url"]\nrequests.post(url)', expected=True)

    def test_annotated_assignment(self):
        self.check('url: str = config.get("callback_url")\nrequests.post(url=url)', expected=True)

    def test_one_step_only(self):
        self.check('url = config["callback_url"]\nendpoint = url\nrequests.post(endpoint)')

    def test_constant(self):
        self.check('requests.post("https://api.example.org")')

    def test_generic_variables(self):
        for name in ('url', 'api_url', 'endpoint', 'base_url'):
            with self.subTest(name=name):
                self.check(name + ' = "https://example.org"\nrequests.post(' + name + ')')

    def test_get(self):
        self.check('requests.get(webhook_url)')

    def test_bare_registry(self):
        self.check('webhooks = {"url": "https://example.org"}')

    def test_receiver_only(self):
        self.check('@app.post("/webhook")\ndef receiver():\n    return "ok"')

    def test_non_http_post(self):
        self.check('queue.post(webhook_url)')

    def test_comments_docstrings_strings(self):
        self.check('# requests.post(webhook_url)\n"""requests.post(webhook_url)"""\n"webhook"')

    def test_cross_module(self):
        self.write('registry.py', 'webhooks = []')
        self.check('requests.post(url)')

    def test_cross_module_binding(self):
        self.write('registry.py', 'url = config["webhook_url"]')
        self.check('requests.post(url)')

    def test_no_source(self):
        self.check()

    def test_negative_without_evidence(self):
        self.write('README.md', 'does not support webhooks')
        result = audit(self.root)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual([c['family'] for c in result['claims']], ['NOWEBHOOK'])

    def test_negative_with_evidence(self):
        self.write('README.md', 'no webhook support')
        self.write('app.py', 'requests.post(webhook_url)')
        self.assertEqual(audit(self.root)['findings'], [{'rule': 'documented-no-webhook-claim-false', 'severity': 'HIGH', 'path': 'README.md'}])

    def test_all_positive_phrases(self):
        for phrase in WEBHOOK:
            with self.subTest(phrase=phrase):
                self.check(claim=phrase)

    def test_all_negative_phrases(self):
        for phrase in NOWEBHOOK:
            with self.subTest(phrase=phrase):
                self.write('README.md', phrase)
                result = audit(self.root)
                self.assertEqual(result['status'], 'PASS')
                self.assertEqual([c['family'] for c in result['claims']], ['NOWEBHOOK'])

    def test_bare_nouns(self):
        self.write('README.md', 'webhook webhooks notification event')
        self.assertEqual(audit(self.root)['claims'], [])

    def test_word_boundary(self):
        self.write('README.md', 'supports webhookserver; xsupports webhooks; supports webhooksuffix')
        self.assertEqual(audit(self.root)['claims'], [])

    def test_normalization(self):
        self.check(claim='SUPPORTS-\n  WEBHOOKS')

    def test_paragraph_boundary(self):
        self.write('README.md', 'supports\n\nwebhooks')
        self.assertEqual(audit(self.root)['claims'], [])

    def test_fences(self):
        self.write('README.md', '```text\nsupports webhooks\n```\n\n~~~~\nno webhooks\n~~~~')
        self.assertEqual(audit(self.root)['claims'], [])

    def test_inline_counts(self):
        self.check(claim='`supports webhooks`')

    def test_docs_paths(self):
        self.write('nested/docs/guide.md', 'supports webhooks')
        self.assertEqual(audit(self.root)['findings'][0]['severity'], 'HIGH')

    def test_other_markdown_excluded(self):
        self.write('notes.md', 'supports webhooks')
        self.assertEqual(audit(self.root)['claims'], [])

    def test_testonly_threshold(self):
        self.write('tests/docs/guide.md', 'supports webhooks')
        self.assertEqual(audit(self.root)['findings'][0]['severity'], 'MEDIUM')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(self.root), '--fail-on', 'HIGH']), 0)
            self.assertEqual(main([str(self.root)]), 2)

    def test_high_claim_preferred(self):
        self.write('tests/docs/a.md', 'supports webhooks')
        self.write('docs/b.md', 'supports webhooks')
        self.write('README.md', 'supports webhooks; supports webhooks')
        result = audit(self.root)
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['severity'], 'HIGH')

    def test_test_sources_excluded(self):
        self.write('tests/app.py', 'requests.post(webhook_url)')
        self.write('nested/test_delivery.py', 'requests.post(webhook_url)')
        self.check()

    def test_ignore_directory(self):
        self.write('docs/a.md', 'supports webhooks')
        self.assertEqual(audit(self.root, ['docs'])['claims'], [])

    def test_ignore_glob(self):
        self.write('docs/a.md', 'supports webhooks')
        self.assertEqual(audit(self.root, ['docs/*.md'])['claims'], [])

    def test_symlinks_and_dotfiles(self):
        self.write('.env', '\x00supports webhooks')
        self.write('.private/docs/a.md', 'supports webhooks')
        (self.root / 'README.md').symlink_to(self.root / '.env')
        (self.root / 'docs').symlink_to(self.root / '.private/docs', target_is_directory=True)
        self.assertEqual(audit(self.root)['claims'], [])

    def test_urllib(self):
        self.check('urllib.request.urlopen(webhook_url, method="POST")', expected=True)
        self.check('urllib.request.Request(webhook_url, method="POST")', expected=True)

    def test_urllib_positional_method(self):
        self.check('urllib.request.Request(webhook_url, None, {}, None, False, "POST")', expected=True)

    def test_urllib_get(self):
        self.check('urllib.request.urlopen(webhook_url)')

    def test_json_shape(self):
        self.write('README.md', 'supports webhooks')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main([str(self.root), '--json']), 2)
        result = json.loads(output.getvalue())
        self.assertEqual(set(result), {'status', 'claims', 'evidence', 'findings'})
        self.assertEqual(set(result['findings'][0]), {'rule', 'severity', 'path'})

    def test_text_verbose(self):
        self.write('README.md', 'supports webhooks')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main([str(self.root), '--verbose']), 2)
        self.assertEqual(output.getvalue(), 'FAIL\ndocumented-webhook-claim-false HIGH README.md\n')

    def test_usage_errors(self):
        for args in (['--unknown'], ['--fail-on', 'LOW']):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    main(args)
                self.assertEqual(error.exception.code, 1)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.root / 'absent')]), 1)

    def test_invalid_source(self):
        self.write('app.py', 'def !!!')
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.root)]), 1)

    def test_version(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as error:
            main(['--version'])
        self.assertEqual(error.exception.code, 0)
        self.assertEqual(output.getvalue(), '0.1.0\n')

    def test_self_audit(self):
        result = audit(Path(__file__).resolve().parents[1])
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['claims'], [])
        self.assertEqual(result['evidence'], [])


if __name__ == '__main__':
    unittest.main()
