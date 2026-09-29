"""Manual checklist for settings the API cannot copy."""

from __future__ import annotations

from typing import Any

from org_copy.remap import PROJECT_OPTION_KEYS, member_email


def render_checklist(
    snapshot: dict[str, Any],
    *,
    dest_org: str | None = None,
    actions: list[str] | None = None,
    failures: list[dict[str, Any]] | None = None,
    dropped_actions: list[dict[str, str]] | None = None,
    dsn_map: list[dict[str, str]] | None = None,
    rejected_org_fields: list[str] | None = None,
    rejected_project_options: list[dict[str, str]] | None = None,
    notes: list[str] | None = None,
) -> str:
    source = snapshot.get("source") or {}
    organization = snapshot.get("organization") or {}
    lines: list[str] = [
        "# Manual settings checklist",
        "",
        f"Source org: `{source.get('org')}` ({source.get('host')})",
        f"Destination org: `{dest_org}`" if dest_org else "Destination org: created by hand before apply.",
        "",
        "Switch SDK DSNs last, after alerts in the destination org are working.",
        "",
        "## Does not move",
        "",
        "- Past events, issue history and state, replays, logs, audit logs, and usage.",
        "- Billing stays on the new org.",
        "- Releases, source maps, and debug files have to be uploaded again from CI.",
        "",
    ]
    _section_sso(lines, organization, snapshot.get("authProvider"))
    _section_integrations(lines, snapshot)
    _section_code(lines, snapshot)
    _section_uptime(lines, snapshot)
    _section_tokens(lines, snapshot)
    _section_apps(lines, snapshot)
    _section_releases(lines, snapshot)
    _section_dsn(lines, dsn_map or [])
    _section_hidden(lines, snapshot)
    _section_members(lines, snapshot)
    _section_replay(lines, snapshot)
    _section_alerts(lines, dropped_actions or [])
    _section_rejected(lines, rejected_org_fields or [], rejected_project_options or [])
    _section_forwarders(lines, snapshot)
    if organization.get("require2FA"):
        lines.extend(
            [
                "## 2FA",
                "",
                "- Source org requires 2FA. Applying org settings turns that requirement on for the destination org.",
                "",
            ]
        )
    if notes:
        lines.extend(["## Notes", ""])
        lines.extend(f"- {note}" for note in notes)
        lines.append("")
    if failures or snapshot.get("exportErrors"):
        lines.extend(["## Failures", ""])
        for item in snapshot.get("exportErrors") or []:
            lines.append(f"- Export `{item.get('step')}`: {item.get('detail')}")
        for item in failures or []:
            lines.append(f"- {item.get('step')}: {item.get('detail')}")
        lines.append("")
    if actions:
        lines.extend(["## Apply log", ""])
        lines.extend(f"- {action}" for action in actions)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _section_sso(lines: list[str], organization: dict[str, Any], provider: Any) -> None:
    lines.extend(["## SSO, SAML, and SCIM", ""])
    if organization.get("hasAuthProvider") or provider:
        name = ""
        if isinstance(provider, dict):
            name = provider.get("provider") or provider.get("name") or ""
        lines.append(
            f"- Reconfigure the IdP app for the new org (source provider: {name or 'configured'}). "
            "ACS and SCIM endpoints change with the org."
        )
    else:
        lines.append("- No auth provider was listed on the source org.")
    lines.append("")


def _section_integrations(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Integrations", ""])
    integrations = snapshot.get("integrations") or []
    if not integrations:
        lines.append("- No integrations were listed. Reconnect Slack, PagerDuty, source control, Jira, and the rest by hand.")
    else:
        lines.append("- Reconnect each integration, including code mappings and team or user mappings:")
        for item in integrations:
            lines.append(f"  - {item.get('provider') or item.get('name')}: {item.get('name')} ({item.get('status') or 'installed'})")
    lines.append("")


def _section_code(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Code mappings and code owners", ""])
    mappings = snapshot.get("codeMappings") or []
    if mappings:
        for item in mappings:
            lines.append(
                f"- Mapping `{item.get('project')}` -> `{item.get('repo')}` "
                f"(stack `{item.get('stackRoot')}`, source `{item.get('sourceRoot')}`)."
            )
    else:
        lines.append("- No code mappings were listed.")
    found = False
    for project in snapshot.get("projects") or []:
        for owner in project.get("codeowners") or []:
            found = True
            lines.append(f"- Re-import code owners on `{project.get('slug')}` after source control is connected.")
            break
        for hook in project.get("serviceHooks") or []:
            lines.append(f"- Recreate webhook on `{project.get('slug')}`: {hook.get('url')} events={hook.get('events')}")
    if not found:
        lines.append("- No code owners were listed.")
    lines.append("")


def _section_uptime(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Uptime monitors", ""])
    found = False
    for project in snapshot.get("projects") or []:
        for detector in project.get("detectors") or []:
            if not str(detector.get("type") or "").startswith("uptime"):
                if detector.get("type") not in (None, "", "metric_issue"):
                    lines.append(
                        f"- Unsupported detector `{detector.get('name')}` ({detector.get('type')}) on `{project.get('slug')}`."
                    )
                continue
            found = True
            url = _uptime_url(detector)
            lines.append(f"- Recreate uptime monitor `{detector.get('name')}` on `{project.get('slug')}` ({url}).")
    if not found:
        lines.append("- No uptime monitors were listed.")
    lines.append("")


def _section_tokens(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Org auth tokens", ""])
    tokens = snapshot.get("authTokens") or []
    if not tokens:
        lines.append("- Create new org auth tokens in the destination UI. Token secrets are not copied.")
    else:
        lines.append("- Create new tokens with the same names and scopes. The old secret is not copied:")
        for token in tokens:
            scopes = ", ".join(str(scope) for scope in (token.get("scopes") or []))
            lines.append(f"  - {token.get('name') or token.get('id')} ({scopes})")
    lines.append("")


def _section_apps(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Custom Sentry apps", ""])
    installs = snapshot.get("sentryAppInstallations") or []
    if not installs:
        lines.append("- Reinstall custom Sentry apps on the destination org.")
    else:
        for item in installs:
            lines.append(f"- Reinstall app `{item.get('app')}`.")
    lines.append("")


def _section_releases(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Releases and debug files", ""])
    lines.append("- Re-upload releases, source maps, and debug symbols from the pipeline.")
    lines.append("- Release thresholds are not copied.")
    for project in snapshot.get("projects") or []:
        if project.get("latestRelease"):
            lines.append(f"- `{project.get('slug')}` last saw release `{project.get('latestRelease')}`.")
    lines.append("")


def _section_dsn(lines: list[str], dsn_map: list[dict[str, str]]) -> None:
    lines.extend(["## DSN cutover", ""])
    if not dsn_map:
        lines.append("- New DSNs are written to `dsn-map.json` on apply. Point SDKs at them only after the destination is ready.")
    else:
        lines.append("- Update SDK config to these DSNs:")
        for item in dsn_map:
            lines.append(f"  - `{item.get('project')}` / `{item.get('key')}`: `{item.get('dsn')}`")
    lines.append("")


def _section_hidden(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Hidden environments", ""])
    found = False
    for project in snapshot.get("projects") or []:
        names = project.get("hiddenEnvironments") or []
        if names:
            found = True
            joined = ", ".join(names)
            lines.append(
                f"- `{project.get('slug')}` hides {joined}. "
                "Re-run apply with `--hide-environments` after those environments exist."
            )
    if not found:
        lines.append("- No hidden environments were listed.")
    lines.append("")


def _section_members(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## People", ""])
    lines.append("- Invites are not sent unless apply is run with `--send-invites`.")
    for member in snapshot.get("members") or []:
        teams = ", ".join(member.get("teamSlugs") or []) or "no teams"
        lines.append(f"- {member_email(member)} role `{member.get('orgRole')}` teams: {teams}")
    lines.append("")


def _section_replay(lines: list[str], snapshot: dict[str, Any]) -> None:
    emails = snapshot.get("replayAccessEmails") or []
    if not emails:
        return
    lines.extend(
        [
            "## Replay access",
            "",
            "- After these members accept their invites, re-run apply with `--apply-replay-access`:",
        ]
    )
    lines.extend(f"  - {email}" for email in emails)
    lines.append("")


def _section_alerts(lines: list[str], dropped: list[dict[str, str]]) -> None:
    lines.extend(["## Alert actions to recreate after integrations", ""])
    if not dropped:
        lines.append("- No integration alert actions were dropped.")
    else:
        for item in dropped:
            lines.append(f"- `{item.get('rule')}`: {item.get('action')}")
    lines.append("")


def _section_rejected(
    lines: list[str], org_fields: list[str], project_options: list[dict[str, str]]
) -> None:
    if not org_fields and not project_options:
        return
    lines.extend(["## Settings the API rejected", ""])
    for field in org_fields:
        lines.append(f"- Org field `{field}` was not accepted. Set it in the UI.")
    for item in project_options:
        if item.get("field") in PROJECT_OPTION_KEYS or True:
            lines.append(
                f"- Project `{item.get('project')}` field `{item.get('field')}` was not accepted. Set it in the UI."
            )
    lines.append("")


def _section_forwarders(lines: list[str], snapshot: dict[str, Any]) -> None:
    lines.extend(["## Data forwarders", ""])
    forwarders = snapshot.get("forwarders") or []
    if not forwarders:
        lines.append("- No data forwarders were listed.")
    else:
        lines.append("- Forwarder credentials stay in `snapshot.json` and are not printed here.")
        for item in forwarders:
            projects = ", ".join(
                project.get("slug") or ""
                for project in item.get("enrolledProjects") or []
                if isinstance(project, dict)
            )
            lines.append(f"- Provider `{item.get('provider')}` enrolled projects: {projects or '(none)'}")
    lines.append("")


def _uptime_url(detector: dict[str, Any]) -> str:
    for source in detector.get("dataSources") or []:
        query = source.get("queryObj") if isinstance(source, dict) else None
        if isinstance(query, dict) and query.get("url"):
            return str(query["url"])
    return "url not listed"
