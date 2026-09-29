"""Run the copy CLI against an in-memory Sentry API."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

import httpx

from org_copy.cli import main
from org_copy.client import SentryClient, next_link
from tests.fake_sentry import seed


class ClientTests(unittest.TestCase):
    def test_next_link_skips_empty_page(self) -> None:
        header = (
            '<https://us.sentry.io/api/0/organizations/o/projects/?cursor=1>; rel="next"; results="false", '
            '<https://us.sentry.io/api/0/organizations/o/projects/?cursor=0>; rel="previous"; results="true"'
        )
        self.assertIsNone(next_link(header))

    def test_pagination_and_rate_limit(self) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(429, headers={"Retry-After": "0"}, json={"detail": "slow"})
            if "cursor" not in str(request.url):
                link = '<https://us.sentry.io/api/0/organizations/o/projects/?cursor=1>; rel="next"; results="true"'
                return httpx.Response(200, json=[{"slug": "a"}], headers={"Link": link})
            return httpx.Response(200, json=[{"slug": "b"}])

        with SentryClient("https://us.sentry.io", "token", "o", transport=httpx.MockTransport(handler)) as client:
            rows = client.get_all("/organizations/o/projects/")
        self.assertEqual([row["slug"] for row in rows], ["a", "b"])
        self.assertGreaterEqual(calls["n"], 3)


class CopyTests(unittest.TestCase):
    def test_export_plan_and_apply_round_trip(self) -> None:
        fake = seed()
        transport = httpx.MockTransport(fake.handle)
        original = SentryClient.__init__

        def patched(self, host: str, token: str, org: str, **kwargs: object) -> None:
            kwargs["transport"] = transport
            original(self, host, token, org, **kwargs)

        previous = os.getcwd()
        work = tempfile.TemporaryDirectory()
        os.chdir(work.name)
        SentryClient.__init__ = patched  # type: ignore[method-assign]
        try:
            self.assertEqual(_run(["export", "--source-org", "sana-us", "--source-token", "us-token"]), 0)
            snapshot = json.loads(Path("snapshot.json").read_text())
            text = Path("snapshot.json").read_text()
            checklist = Path("manual-checklist.md").read_text()
            self.assertNotIn("org-token-secret-value", text)
            self.assertNotIn("hook-secret", text)
            self.assertNotIn("csp-token-value", text)
            self.assertIn("super-secret-splunk-token", text)
            self.assertNotIn("super-secret-splunk-token", checklist)
            self.assertIn("saml2", checklist)
            self.assertIn("Homepage uptime", checklist)
            self.assertIn("CI Upload", checklist)
            self.assertIn("staging", checklist)
            self.assertEqual(stat.S_IMODE(os.stat("snapshot.json").st_mode), 0o600)

            dest = fake.orgs[("de.sentry.io", "sana-de")]
            before = len(dest.calls)
            plan_out = StringIO()
            self.assertEqual(
                _run(
                    ["plan", "--dest-org", "sana-de", "--dest-token", "de-token"],
                    stdout=plan_out,
                ),
                0,
            )
            plan_calls = dest.calls[before:]
            self.assertTrue(plan_out.getvalue())
            self.assertFalse([call for call in plan_calls if call[0] in {"POST", "PUT"}])
            self.assertIn("create team backend", plan_out.getvalue())

            self.assertEqual(
                _run(
                    [
                        "apply",
                        "--dest-org",
                        "sana-de",
                        "--dest-token",
                        "de-token",
                        "--send-invites",
                        "--hide-environments",
                        "--apply-replay-access",
                    ]
                ),
                0,
            )
            self._assert_destination(fake)
            checklist = Path("manual-checklist.md").read_text()
            self.assertNotIn("super-secret-splunk-token", checklist)
            self.assertIn("slack", checklist.lower())
            self.assertIn("Could not hide environments", checklist)
            dsn_mode = stat.S_IMODE(os.stat("dsn-map.json").st_mode)
            self.assertEqual(dsn_mode, 0o600)

            again = StringIO()
            self.assertEqual(
                _run(["apply", "--dest-org", "sana-de", "--dest-token", "de-token"], stdout=again),
                0,
            )
            self.assertIn("skip team backend", again.getvalue())
            self.assertEqual(len(dest.teams), 1)
            self.assertEqual(len(dest.workflows), 1)
            self.assertEqual(len(dest.projects), 1)
            self._assert_destination(fake)
        finally:
            SentryClient.__init__ = original  # type: ignore[method-assign]
            os.chdir(previous)
            work.cleanup()

    def _assert_destination(self, fake) -> None:
        dest = fake.orgs[("de.sentry.io", "sana-de")]
        self.assertTrue(dest.fields["require2FA"])
        self.assertEqual(dest.fields["relayPiiConfig"], '{"rules":{}}')
        self.assertNotIn("hideAiFeatures", dest.fields)
        project = dest.projects["api"]
        self.assertEqual(project["fingerprintingRules"], "error.type:DatabaseUnavailable -> database-unavailable")
        self.assertEqual(project["ownership"]["raw"], "path:src/* #backend")
        self.assertFalse(project["ownership"]["codeownersAutoSync"])
        filters = {item["id"]: item["active"] for item in project["filters"]}
        self.assertTrue(filters["browser-extensions"])
        self.assertEqual(filters["legacy-browsers"], ["ie", "safari"])
        keys = {key["name"]: key for key in project["keys"]}
        self.assertEqual(keys["Production"]["rateLimit"], {"window": 60, "count": 10})
        self.assertTrue(keys["Loader"]["dynamicSdkLoaderOptions"]["hasReplay"])
        self.assertEqual(len(project["detectors"]), 1)
        self.assertEqual(project["detectors"][0]["type"], "metric_issue")
        self.assertTrue(project["detectors"][0]["owner"].startswith("team:"))
        workflow = dest.workflows[0]
        actions = workflow["actionFilters"][0]["actions"]
        self.assertTrue(actions)
        self.assertTrue(all(action["type"] == "email" for action in actions))
        team_action = next(action for action in actions if action["config"]["targetType"] == "team")
        self.assertEqual(team_action["config"]["targetIdentifier"], dest.teams["backend"]["id"])
        self.assertEqual(len(project["rules"]), 1)
        self.assertEqual(project["rules"][0]["name"], "After hours")
        self.assertEqual(dest.alert_rules[0]["projects"], ["api"])
        self.assertNotIn("slack", json.dumps(dest.alert_rules[0]["triggers"]).lower())
        self.assertEqual(dest.monitors[0]["slug"], "nightly")
        self.assertEqual(dest.dashboards[0]["title"], "Overview")
        self.assertEqual(dest.dashboards[0]["projects"], [int(project["id"])])
        self.assertEqual(len(dest.dashboards), 1)
        self.assertEqual(dest.queries[0]["projects"], [int(project["id"])])
        self.assertEqual([view["name"] for view in dest.views], ["Prod errors"])
        self.assertEqual(dest.forwarders[0]["config"]["token"], "super-secret-splunk-token")
        self.assertEqual(dest.forwarders[0]["project_ids"], [int(project["id"])])
        invited = [member for member in dest.members if member["email"] == "other@example.com"]
        self.assertEqual(len(invited), 1)
        self.assertEqual(invited[0]["orgRole"], "manager")
        dsn_map = json.loads(Path("dsn-map.json").read_text())
        self.assertEqual({item["key"] for item in dsn_map}, {"Production", "Loader"})
        self.assertTrue(all(item["dsn"].startswith("https://") for item in dsn_map))
        self.assertTrue(all("ingest.sentry.io" not in item["dsn"] or "de.sentry.io" in item["dsn"] for item in dsn_map))


def _run(args: list[str], stdout: StringIO | None = None) -> int:
    out = stdout or StringIO()
    err = StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        return main(args)


if __name__ == "__main__":
    unittest.main()
