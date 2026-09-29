"""Create destination resources from a snapshot."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from org_copy.client import ApiError, SentryClient
from org_copy.files import write_json
from org_copy.redact import error_text
from org_copy.remap import (
    PROJECT_OPTION_KEYS,
    build_user_map,
    classic_rule_body,
    dashboard_body,
    detector_create_body,
    fields_to_drop,
    issue_view_body,
    member_email,
    metric_rule_body,
    optional_org_body,
    org_settings_body,
    project_settings_body,
    public_key_settings,
    remap_owner,
    saved_query_body,
    workflow_create_body,
)

LIST_PARAMS = {"per_page": "100"}


@dataclass
class ApplyOptions:
    dry_run: bool = False
    send_invites: bool = False
    include_forwarders: bool = True
    hide_environments: bool = False
    apply_replay_access: bool = False


@dataclass
class ApplyReport:
    actions: list[str] = field(default_factory=list)
    failures: list[dict[str, str]] = field(default_factory=list)
    dropped_actions: list[dict[str, str]] = field(default_factory=list)
    dsn_map: list[dict[str, str]] = field(default_factory=list)
    rejected_org_fields: list[str] = field(default_factory=list)
    rejected_project_options: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures


class Sink:
    def __init__(self, client: SentryClient, report: ApplyReport, dry_run: bool):
        self.client = client
        self.report = report
        self.dry_run = dry_run
        self._seq = 0

    def post(self, path: str, body: dict[str, Any], summary: str) -> dict[str, Any]:
        if self.dry_run:
            self.report.actions.append(f"create {summary}")
            self._seq += 1
            echoed: dict[str, Any] = {
                "id": f"plan-{self._seq}",
                "slug": body.get("slug") or body.get("name") or body.get("title"),
                "name": body.get("name") or body.get("title"),
            }
            if path.endswith("/keys/"):
                echoed["dsn"] = {"public": "<assigned on apply>"}
            return echoed
        result = self.client.post(path, json=body)
        self.report.actions.append(f"created {summary}")
        return result if isinstance(result, dict) else {}

    def put(self, path: str, body: dict[str, Any], summary: str) -> Any:
        if self.dry_run:
            self.report.actions.append(f"update {summary}")
            return body
        result = self.client.put(path, json=body)
        self.report.actions.append(f"updated {summary}")
        return result

    def skip(self, summary: str) -> None:
        self.report.actions.append(f"skip {summary}")


def apply_snapshot(
    snapshot: dict[str, Any],
    client: SentryClient,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
) -> ApplyReport:
    report = ApplyReport()
    sink = Sink(client, report, options.dry_run)
    dest = _DestIndex.load(client, report)
    if dest is None:
        return report
    user_map = build_user_map(snapshot.get("members") or [], dest.members)
    team_map: dict[str, str] = {}
    project_map: dict[str, str] = {}
    detector_map: dict[str, str] = {}

    _apply_org(snapshot, sink, dest, report)
    _apply_teams(snapshot, sink, dest, state, state_path, options, team_map)
    _apply_projects(snapshot, client, sink, dest, state, state_path, options, report, team_map, project_map)
    _apply_forwarders(snapshot, sink, dest, state, state_path, options, project_map, report)
    _apply_detectors(snapshot, sink, dest, state, state_path, options, team_map, user_map, project_map, detector_map, report)
    _apply_workflows(snapshot, sink, dest, state, state_path, options, team_map, user_map, detector_map, report)
    names = {workflow.get("name") for workflow in snapshot.get("workflows") or []}
    _apply_legacy_rules(snapshot, sink, dest, state, state_path, options, team_map, user_map, names, report)
    _apply_metric_rules(snapshot, sink, dest, state, state_path, options, team_map, user_map, names, report)
    _apply_monitors(snapshot, sink, dest, state, state_path, options, team_map, user_map, project_map, report)
    _apply_dashboards(snapshot, sink, dest, state, state_path, options, team_map, project_map, report)
    _apply_queries(snapshot, sink, dest, state, state_path, options, project_map, report)
    _apply_views(snapshot, sink, dest, state, state_path, options, project_map, report)
    if options.send_invites:
        _apply_invites(snapshot, sink, dest, report)
    else:
        report.notes.append("Member invites were not sent. Re-run apply with --send-invites.")
    if options.hide_environments:
        _apply_hidden_environments(snapshot, sink, report)
    if options.apply_replay_access:
        _apply_replay(snapshot, sink, dest, report)
    return report


class _DestIndex:
    def __init__(self) -> None:
        self.org: dict[str, Any] = {}
        self.teams_by_slug: dict[str, dict[str, Any]] = {}
        self.projects_by_slug: dict[str, dict[str, Any]] = {}
        self.members: list[dict[str, Any]] = []
        self.members_by_email: dict[str, dict[str, Any]] = {}
        self.workflows_by_name: dict[str, dict[str, Any]] = {}
        self.monitors_by_slug: dict[str, dict[str, Any]] = {}
        self.dashboards_by_title: dict[str, dict[str, Any]] = {}
        self.queries_by_name: dict[str, dict[str, Any]] = {}
        self.views_by_name: dict[str, dict[str, Any]] = {}
        self.forwarders_by_provider: dict[str, dict[str, Any]] = {}
        self.alert_rules_by_name: dict[str, dict[str, Any]] = {}
        self.detectors_by_key: dict[str, dict[str, Any]] = {}
        self.rules_by_key: dict[str, dict[str, Any]] = {}

    @classmethod
    def load(cls, client: SentryClient, report: ApplyReport) -> _DestIndex | None:
        index = cls()
        try:
            org = client.get_json(f"/organizations/{client.org}/")
        except ApiError as exc:
            report.failures.append({"step": "load destination org", "detail": error_text(exc)})
            return None
        if not isinstance(org, dict):
            report.failures.append({"step": "load destination org", "detail": "organization response was empty"})
            return None
        index.org = org
        index.teams_by_slug = _by(client, f"/organizations/{client.org}/teams/", "slug", report, "teams")
        index.projects_by_slug = _by(client, f"/organizations/{client.org}/projects/", "slug", report, "projects")
        members, error = client.get_optional_list(f"/organizations/{client.org}/members/", LIST_PARAMS)
        if error and error.status != 404:
            report.failures.append({"step": "list destination members", "detail": error_text(error)})
        index.members = members
        index.members_by_email = {member_email(member): member for member in members if member_email(member)}
        index.workflows_by_name = _by(client, f"/organizations/{client.org}/workflows/", "name", report, "workflows")
        index.monitors_by_slug = _by(client, f"/organizations/{client.org}/monitors/", "slug", report, "monitors")
        index.dashboards_by_title = _by(client, f"/organizations/{client.org}/dashboards/", "title", report, "dashboards")
        index.queries_by_name = _by(client, f"/organizations/{client.org}/discover/saved/", "name", report, "saved queries")
        views, view_error = client.get_optional_list(
            f"/organizations/{client.org}/group-search-views/",
            {"createdBy": "me", **LIST_PARAMS},
        )
        if view_error and view_error.status != 404:
            report.failures.append({"step": "list destination issue views", "detail": error_text(view_error)})
        index.views_by_name = {item.get("name"): item for item in views if item.get("name")}
        forwarders, forward_error = client.get_optional_list(f"/organizations/{client.org}/forwarding/")
        if forward_error and forward_error.status != 404:
            report.failures.append({"step": "list destination forwarders", "detail": error_text(forward_error)})
        index.forwarders_by_provider = {item.get("provider"): item for item in forwarders if item.get("provider")}
        index.alert_rules_by_name = _by(client, f"/organizations/{client.org}/alert-rules/", "name", report, "metric alerts")
        detectors, detector_error = client.get_optional_list(f"/organizations/{client.org}/detectors/", LIST_PARAMS)
        if detector_error and detector_error.status != 404:
            report.failures.append({"step": "list destination detectors", "detail": error_text(detector_error)})
        for detector in detectors:
            project_id = str(detector.get("projectId") or "")
            name = detector.get("name")
            if project_id and name:
                index.detectors_by_key[f"{project_id}:{name}"] = detector
        for project in index.projects_by_slug.values():
            slug = project.get("slug")
            rules, rule_error = client.get_optional_list(f"/projects/{client.org}/{slug}/rules/")
            if rule_error and rule_error.status != 404:
                report.failures.append({"step": f"list rules {slug}", "detail": error_text(rule_error)})
            for rule in rules:
                if rule.get("name"):
                    index.rules_by_key[f"{slug}:{rule['name']}"] = rule
        return index


def _by(
    client: SentryClient, path: str, key: str, report: ApplyReport, label: str
) -> dict[str, dict[str, Any]]:
    rows, error = client.get_optional_list(path, LIST_PARAMS)
    if error and error.status != 404:
        report.failures.append({"step": f"list destination {label}", "detail": error_text(error)})
    return {row[key]: row for row in rows if isinstance(row, dict) and row.get(key)}


def _remember(state: dict[str, Any], bucket: str, source_id: Any, dest_id: Any, path: str, dry_run: bool) -> None:
    if dry_run or source_id in (None, "") or dest_id in (None, ""):
        return
    state.setdefault(bucket, {})[str(source_id)] = str(dest_id)
    write_json(path, state, secret=True)


def _fail(report: ApplyReport, step: str, exc: Exception) -> None:
    report.failures.append({"step": step, "detail": error_text(exc)})


def _put_dropping(sink: Sink, path: str, body: dict[str, Any], summary: str) -> tuple[Any, list[str]]:
    if sink.dry_run:
        sink.put(path, body, summary)
        return body, []
    current = dict(body)
    dropped: list[str] = []
    for _ in range(12):
        try:
            result = sink.client.put(path, json=current)
            sink.report.actions.append(f"updated {summary}")
            return result, dropped
        except ApiError as exc:
            keys = fields_to_drop(exc.body, current)
            if exc.status != 400 or not keys:
                raise
            for key in keys:
                dropped.append(key)
                current.pop(key, None)
            if not current:
                raise
    raise ApiError("PUT", path, 400, {"detail": "too many rejected fields"})


def _apply_org(snapshot: dict[str, Any], sink: Sink, dest: _DestIndex, report: ApplyReport) -> None:
    organization = snapshot.get("organization") or {}
    body = org_settings_body(organization)
    if not body:
        sink.skip("org settings (nothing to copy)")
        return
    try:
        _put_dropping(sink, f"/organizations/{sink.client.org}/", body, "org settings")
    except ApiError as exc:
        _fail(report, "org settings", exc)
    for field, value in optional_org_body(organization).items():
        try:
            sink.put(f"/organizations/{sink.client.org}/", {field: value}, f"org {field}")
        except ApiError as exc:
            if exc.status == 400:
                report.rejected_org_fields.append(field)
                report.notes.append(f"Org field {field} was rejected and left for the UI.")
            else:
                _fail(report, f"org {field}", exc)


def _apply_teams(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    team_map: dict[str, str],
) -> None:
    org = sink.client.org
    for team in snapshot.get("teams") or []:
        slug = team.get("slug")
        if not slug:
            continue
        existing = dest.teams_by_slug.get(slug)
        if existing:
            sink.skip(f"team {slug}")
            team_map[str(team.get("id"))] = str(existing.get("id"))
            continue
        try:
            created = sink.post(
                f"/organizations/{org}/teams/",
                {"name": team.get("name") or slug, "slug": slug},
                f"team {slug}",
            )
        except ApiError as exc:
            _fail(sink.report, f"team {slug}", exc)
            continue
        dest_id = str(created.get("id"))
        team_map[str(team.get("id"))] = dest_id
        dest.teams_by_slug[slug] = created
        _remember(state, "teams", team.get("id"), dest_id, state_path, options.dry_run)


def _apply_projects(
    snapshot: dict[str, Any],
    client: SentryClient,
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    report: ApplyReport,
    team_map: dict[str, str],
    project_map: dict[str, str],
) -> None:
    org = client.org
    for project in snapshot.get("projects") or []:
        slug = project.get("slug")
        if not slug:
            continue
        existing = dest.projects_by_slug.get(slug)
        if existing:
            sink.skip(f"project {slug}")
            created = existing
        else:
            team_slug = _primary_team_slug(project)
            if not team_slug:
                report.failures.append({"step": f"project {slug}", "detail": "project has no team"})
                continue
            body: dict[str, Any] = {
                "name": project.get("name") or slug,
                "slug": slug,
                "default_rules": False,
            }
            if project.get("platform"):
                body["platform"] = project["platform"]
            try:
                created = sink.post(f"/teams/{org}/{team_slug}/projects/", body, f"project {slug}")
            except ApiError as exc:
                _fail(report, f"project {slug}", exc)
                continue
            dest.projects_by_slug[slug] = created
        dest_id = str(created.get("id"))
        project_map[str(project.get("id"))] = dest_id
        _remember(state, "projects", project.get("id"), dest_id, state_path, options.dry_run)
        _attach_extra_teams(project, sink, org, slug, report)
        _apply_project_settings(project, sink, org, report)
        _apply_filters(project, sink, org, report)
        _apply_ownership(project, sink, org, report)
        _apply_keys(project, client, sink, org, report, options)


def _primary_team_slug(project: dict[str, Any]) -> str | None:
    detail = project.get("detail") or {}
    team = detail.get("team") if isinstance(detail.get("team"), dict) else None
    if team and team.get("slug"):
        return team["slug"]
    teams = project.get("teams") or []
    if teams:
        return teams[0].get("slug")
    return None


def _attach_extra_teams(project: dict[str, Any], sink: Sink, org: str, slug: str, report: ApplyReport) -> None:
    primary = _primary_team_slug(project)
    for team in project.get("teams") or []:
        team_slug = team.get("slug")
        if not team_slug or team_slug == primary:
            continue
        try:
            sink.post(f"/projects/{org}/{slug}/teams/{team_slug}/", {}, f"team {team_slug} on {slug}")
        except ApiError as exc:
            if exc.status == 409:
                sink.skip(f"team {team_slug} on {slug}")
            else:
                _fail(report, f"team {team_slug} on {slug}", exc)


def _apply_project_settings(project: dict[str, Any], sink: Sink, org: str, report: ApplyReport) -> None:
    detail = project.get("detail") or {}
    body = project_settings_body(detail)
    if not body:
        return
    slug = project["slug"]
    try:
        _result, dropped = _put_dropping(sink, f"/projects/{org}/{slug}/", body, f"settings on {slug}")
    except ApiError as exc:
        _fail(report, f"settings on {slug}", exc)
        return
    for field in dropped:
        if field in PROJECT_OPTION_KEYS or field in body:
            report.rejected_project_options.append({"project": slug, "field": field})


def _apply_filters(project: dict[str, Any], sink: Sink, org: str, report: ApplyReport) -> None:
    slug = project["slug"]
    for item in project.get("filters") or []:
        filter_id = item.get("id")
        if not filter_id:
            continue
        if isinstance(item.get("active"), list):
            body: dict[str, Any] = {"subfilters": item["active"]}
            candidates = [filter_id]
            if filter_id == "legacy-browsers":
                candidates.append("legacy-browser")
        else:
            body = {"active": bool(item.get("active"))}
            candidates = [filter_id]
        last_error: ApiError | None = None
        for candidate in candidates:
            try:
                sink.put(
                    f"/projects/{org}/{slug}/filters/{candidate}/",
                    body,
                    f"filter {filter_id} on {slug}",
                )
                last_error = None
                break
            except ApiError as exc:
                last_error = exc
                if exc.status != 404:
                    break
        if last_error is not None:
            _fail(report, f"filter {filter_id} on {slug}", last_error)


def _apply_ownership(project: dict[str, Any], sink: Sink, org: str, report: ApplyReport) -> None:
    ownership = project.get("ownership")
    if not isinstance(ownership, dict):
        return
    slug = project["slug"]
    body = {
        "raw": ownership.get("raw") or "",
        "fallthrough": ownership.get("fallthrough", True),
        "autoAssignment": ownership.get("autoAssignment"),
        "codeownersAutoSync": False,
    }
    try:
        sink.put(f"/projects/{org}/{slug}/ownership/", body, f"ownership on {slug}")
    except ApiError as exc:
        _fail(report, f"ownership on {slug}", exc)


def _apply_keys(
    project: dict[str, Any],
    client: SentryClient,
    sink: Sink,
    org: str,
    report: ApplyReport,
    options: ApplyOptions,
) -> None:
    slug = project["slug"]
    source_keys = project.get("keys") or []
    if not source_keys:
        return
    dest_keys: list[dict[str, Any]] = []
    try:
        dest_keys = client.get_all(f"/projects/{org}/{slug}/keys/")
    except ApiError as exc:
        if exc.status != 404:
            _fail(report, f"keys on {slug}", exc)
            return
    unused = list(dest_keys)
    for source in source_keys:
        settings = public_key_settings(source)
        name = settings["name"]
        match = next((key for key in unused if (key.get("name") or key.get("label")) == name), None)
        if match is None and unused:
            match = unused[0]
        if match is not None:
            unused.remove(match)
            try:
                updated = sink.put(
                    f"/projects/{org}/{slug}/keys/{match.get('id')}/",
                    settings,
                    f"key {name} on {slug}",
                )
            except ApiError as exc:
                _fail(report, f"key {name} on {slug}", exc)
                continue
            dsn = _public_dsn(updated) or _public_dsn(match)
        else:
            try:
                created = sink.post(f"/projects/{org}/{slug}/keys/", {"name": name}, f"key {name} on {slug}")
                updated = sink.put(
                    f"/projects/{org}/{slug}/keys/{created.get('id')}/",
                    settings,
                    f"key settings {name} on {slug}",
                )
            except ApiError as exc:
                _fail(report, f"key {name} on {slug}", exc)
                continue
            dsn = _public_dsn(updated) or _public_dsn(created)
        report.dsn_map.append({"project": slug, "key": name, "dsn": dsn or "<assigned on apply>"})


def _public_dsn(key: Any) -> str | None:
    if not isinstance(key, dict):
        return None
    dsn = key.get("dsn")
    if isinstance(dsn, dict):
        return dsn.get("public")
    return None


def _apply_forwarders(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    project_map: dict[str, str],
    report: ApplyReport,
) -> None:
    if not options.include_forwarders:
        report.notes.append("Data forwarders were not copied. Re-run apply with --include-forwarders.")
        return
    org = sink.client.org
    org_id = dest.org.get("id")
    for forwarder in snapshot.get("forwarders") or []:
        provider = forwarder.get("provider")
        if not provider:
            continue
        project_ids = []
        for project in forwarder.get("enrolledProjects") or []:
            if not isinstance(project, dict):
                continue
            dest_id = project_map.get(str(project.get("id")))
            if dest_id and str(dest_id).isdigit():
                project_ids.append(int(dest_id))
        body = {
            "organization_id": int(org_id) if str(org_id).isdigit() else org_id,
            "provider": provider,
            "is_enabled": forwarder.get("isEnabled", True),
            "enroll_new_projects": forwarder.get("enrollNewProjects", False),
            "config": forwarder.get("config") or {},
            "project_ids": project_ids,
        }
        existing = dest.forwarders_by_provider.get(provider)
        try:
            if existing:
                sink.put(
                    f"/organizations/{org}/forwarding/{existing.get('id')}/",
                    body,
                    f"forwarder {provider}",
                )
                dest_id = existing.get("id")
            else:
                created = sink.post(f"/organizations/{org}/forwarding/", body, f"forwarder {provider}")
                dest_id = created.get("id")
                dest.forwarders_by_provider[provider] = created
        except ApiError as exc:
            _fail(report, f"forwarder {provider}", exc)
            continue
        _remember(state, "forwarders", forwarder.get("id"), dest_id, state_path, options.dry_run)


def _project_slug_for_detector(snapshot: dict[str, Any], detector: dict[str, Any]) -> str | None:
    project_id = str(detector.get("projectId") or "")
    for project in snapshot.get("projects") or []:
        if str(project.get("id")) == project_id:
            return project.get("slug")
        for owned in project.get("detectors") or []:
            if str(owned.get("id")) == str(detector.get("id")):
                return project.get("slug")
    return None


def _iter_detectors(snapshot: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    found: list[tuple[str, dict[str, Any]]] = []
    seen: set[str] = set()
    for project in snapshot.get("projects") or []:
        for detector in project.get("detectors") or []:
            ident = str(detector.get("id") or "") + ":" + str(detector.get("name"))
            if ident in seen:
                continue
            seen.add(ident)
            found.append((project.get("slug"), detector))
    return found


def _apply_detectors(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    team_map: dict[str, str],
    user_map: dict[str, str],
    project_map: dict[str, str],
    detector_map: dict[str, str],
    report: ApplyReport,
) -> None:
    org = sink.client.org
    for slug, detector in _iter_detectors(snapshot):
        name = detector.get("name") or "monitor"
        kind = str(detector.get("type") or "")
        if kind.startswith("uptime"):
            report.notes.append(f"Uptime monitor {name} on {slug} must be recreated by hand.")
            continue
        if kind != "metric_issue":
            report.notes.append(f"Detector {name} ({kind}) on {slug} is not created by this script.")
            continue
        dest_project = project_map.get(str(detector.get("projectId") or ""))
        existing = None
        if dest_project:
            existing = dest.detectors_by_key.get(f"{dest_project}:{name}")
        if existing:
            sink.skip(f"detector {name} on {slug}")
            detector_map[str(detector.get("id"))] = str(existing.get("id"))
            continue
        owner = remap_owner(detector.get("owner"), team_map, user_map)
        body = detector_create_body(detector, owner)
        try:
            created = sink.post(
                f"/organizations/{org}/projects/{slug}/detectors/",
                body,
                f"detector {name} on {slug}",
            )
        except ApiError as exc:
            _fail(report, f"detector {name} on {slug}", exc)
            continue
        detector_map[str(detector.get("id"))] = str(created.get("id"))
        _remember(state, "detectors", detector.get("id"), created.get("id"), state_path, options.dry_run)


def _apply_workflows(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    team_map: dict[str, str],
    user_map: dict[str, str],
    detector_map: dict[str, str],
    report: ApplyReport,
) -> None:
    org = sink.client.org
    for workflow in snapshot.get("workflows") or []:
        name = workflow.get("name")
        if not name:
            continue
        existing = dest.workflows_by_name.get(name)
        if existing:
            sink.skip(f"workflow {name}")
            continue
        owner = remap_owner(workflow.get("owner"), team_map, user_map)
        body, dropped = workflow_create_body(workflow, detector_map, owner, user_map, team_map)
        for action in dropped:
            report.dropped_actions.append({"rule": name, "action": action})
        try:
            created = sink.post(f"/organizations/{org}/workflows/", body, f"workflow {name}")
        except ApiError as exc:
            _fail(report, f"workflow {name}", exc)
            continue
        dest.workflows_by_name[name] = created
        _remember(state, "workflows", workflow.get("id"), created.get("id"), state_path, options.dry_run)


def _apply_legacy_rules(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    team_map: dict[str, str],
    user_map: dict[str, str],
    workflow_names: set[Any],
    report: ApplyReport,
) -> None:
    org = sink.client.org
    for project in snapshot.get("projects") or []:
        slug = project.get("slug")
        for rule in project.get("rules") or []:
            name = rule.get("name")
            if not name or not slug:
                continue
            if name in workflow_names:
                sink.skip(f"issue rule {name} on {slug} (workflow with the same name)")
                continue
            if dest.rules_by_key.get(f"{slug}:{name}"):
                sink.skip(f"issue rule {name} on {slug}")
                continue
            owner = remap_owner(rule.get("owner"), team_map, user_map)
            body, dropped = classic_rule_body(rule, owner, user_map, team_map)
            for action in dropped:
                report.dropped_actions.append({"rule": name, "action": action})
            try:
                created = sink.post(f"/projects/{org}/{slug}/rules/", body, f"issue rule {name} on {slug}")
            except ApiError as exc:
                _fail(report, f"issue rule {name} on {slug}", exc)
                continue
            dest.rules_by_key[f"{slug}:{name}"] = created
            _remember(state, "rules", rule.get("id"), created.get("id"), state_path, options.dry_run)


def _metric_project_slugs(rule: dict[str, Any], snapshot: dict[str, Any]) -> list[str]:
    wanted = {str(project_id) for project_id in rule.get("projects") or []}
    slugs = []
    for project in snapshot.get("projects") or []:
        if str(project.get("id")) in wanted or project.get("slug") in wanted:
            slugs.append(project["slug"])
    return slugs


def _apply_metric_rules(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    team_map: dict[str, str],
    user_map: dict[str, str],
    workflow_names: set[Any],
    report: ApplyReport,
) -> None:
    org = sink.client.org
    for rule in snapshot.get("alertRules") or []:
        name = rule.get("name")
        if not name:
            continue
        if name in workflow_names:
            sink.skip(f"metric alert {name} (workflow with the same name)")
            continue
        if dest.alert_rules_by_name.get(name):
            sink.skip(f"metric alert {name}")
            continue
        owner = remap_owner(rule.get("owner"), team_map, user_map)
        body, dropped = metric_rule_body(rule, _metric_project_slugs(rule, snapshot), owner, user_map, team_map)
        for action in dropped:
            report.dropped_actions.append({"rule": name, "action": action})
        try:
            created = sink.post(f"/organizations/{org}/alert-rules/", body, f"metric alert {name}")
        except ApiError as exc:
            _fail(report, f"metric alert {name}", exc)
            continue
        dest.alert_rules_by_name[name] = created
        _remember(state, "alertRules", rule.get("id"), created.get("id"), state_path, options.dry_run)


def _apply_monitors(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    team_map: dict[str, str],
    user_map: dict[str, str],
    project_map: dict[str, str],
    report: ApplyReport,
) -> None:
    org = sink.client.org
    slug_by_id = {str(project.get("id")): project.get("slug") for project in snapshot.get("projects") or []}
    for monitor in snapshot.get("monitors") or []:
        slug = monitor.get("slug")
        name = monitor.get("name") or slug
        if not slug:
            continue
        if dest.monitors_by_slug.get(slug):
            sink.skip(f"cron monitor {slug}")
            continue
        project_slug = monitor.get("project") or slug_by_id.get(str(monitor.get("projectId") or ""))
        if isinstance(project_slug, dict):
            project_slug = project_slug.get("slug")
        owner = remap_owner(monitor.get("owner"), team_map, user_map)
        body: dict[str, Any] = {
            "project": project_slug,
            "name": name,
            "slug": slug,
            "status": monitor.get("status") or "active",
            "config": monitor.get("config"),
            "is_muted": monitor.get("isMuted", monitor.get("is_muted", False)),
        }
        if owner:
            body["owner"] = owner
        try:
            created = sink.post(f"/organizations/{org}/monitors/", body, f"cron monitor {slug}")
        except ApiError as exc:
            _fail(report, f"cron monitor {slug}", exc)
            continue
        dest.monitors_by_slug[slug] = created
        _remember(state, "monitors", monitor.get("id"), created.get("id"), state_path, options.dry_run)


def _apply_dashboards(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    team_map: dict[str, str],
    project_map: dict[str, str],
    report: ApplyReport,
) -> None:
    org = sink.client.org
    for dashboard in snapshot.get("dashboards") or []:
        if dashboard.get("prebuiltId"):
            sink.skip(f"prebuilt dashboard {dashboard.get('title')}")
            continue
        title = dashboard.get("title")
        if not title:
            continue
        if dest.dashboards_by_title.get(title):
            sink.skip(f"dashboard {title}")
            continue
        body = dashboard_body(dashboard, project_map, team_map)
        try:
            created = sink.post(f"/organizations/{org}/dashboards/", body, f"dashboard {title}")
        except ApiError as exc:
            _fail(report, f"dashboard {title}", exc)
            continue
        dest.dashboards_by_title[title] = created
        _remember(state, "dashboards", dashboard.get("id"), created.get("id"), state_path, options.dry_run)


def _apply_queries(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    project_map: dict[str, str],
    report: ApplyReport,
) -> None:
    org = sink.client.org
    for query in snapshot.get("savedQueries") or []:
        name = query.get("name")
        if not name:
            continue
        if dest.queries_by_name.get(name):
            sink.skip(f"saved query {name}")
            continue
        try:
            created = sink.post(
                f"/organizations/{org}/discover/saved/",
                saved_query_body(query, project_map),
                f"saved query {name}",
            )
        except ApiError as exc:
            _fail(report, f"saved query {name}", exc)
            continue
        dest.queries_by_name[name] = created
        _remember(state, "queries", query.get("id"), created.get("id"), state_path, options.dry_run)


def _apply_views(
    snapshot: dict[str, Any],
    sink: Sink,
    dest: _DestIndex,
    state: dict[str, Any],
    state_path: str,
    options: ApplyOptions,
    project_map: dict[str, str],
    report: ApplyReport,
) -> None:
    org = sink.client.org
    views = (snapshot.get("issueViews") or {}).get("mine") or []
    for view in views:
        name = view.get("name")
        if not name:
            continue
        if dest.views_by_name.get(name):
            sink.skip(f"issue view {name}")
            continue
        try:
            created = sink.post(
                f"/organizations/{org}/group-search-views/",
                issue_view_body(view, project_map),
                f"issue view {name}",
            )
        except ApiError as exc:
            _fail(report, f"issue view {name}", exc)
            continue
        dest.views_by_name[name] = created
        _remember(state, "views", view.get("id"), created.get("id"), state_path, options.dry_run)
    others = (snapshot.get("issueViews") or {}).get("others") or []
    if others:
        report.notes.append(
            f"{len(others)} issue views belong to other members and were listed, not copied."
        )


def _apply_invites(snapshot: dict[str, Any], sink: Sink, dest: _DestIndex, report: ApplyReport) -> None:
    org = sink.client.org
    for member in snapshot.get("members") or []:
        email = member_email(member)
        if not email:
            continue
        if email in dest.members_by_email:
            sink.skip(f"invite {email}")
            continue
        body: dict[str, Any] = {
            "email": email,
            "role": member.get("orgRole") or "member",
            "teams": member.get("teamSlugs") or [],
            "sendInvite": True,
        }
        if member.get("teamRoles"):
            body["teamRoles"] = member["teamRoles"]
        try:
            sink.post(f"/organizations/{org}/members/", body, f"invite {email}")
        except ApiError as exc:
            _fail(report, f"invite {email}", exc)


def _apply_hidden_environments(snapshot: dict[str, Any], sink: Sink, report: ApplyReport) -> None:
    org = sink.client.org
    for project in snapshot.get("projects") or []:
        names = [name for name in project.get("hiddenEnvironments") or [] if name]
        if not names:
            continue
        slug = project.get("slug")
        try:
            sink.put(
                f"/projects/{org}/{slug}/environments/",
                {"environmentNames": names, "isHidden": True},
                f"hidden environments on {slug}",
            )
        except ApiError as exc:
            report.notes.append(
                f"Could not hide environments on {slug} yet ({error_text(exc)}). Re-run after events create them."
            )


def _apply_replay(snapshot: dict[str, Any], sink: Sink, dest: _DestIndex, report: ApplyReport) -> None:
    emails = snapshot.get("replayAccessEmails") or []
    if not emails:
        return
    dest_ids = []
    missing = []
    for email in emails:
        member = dest.members_by_email.get(email)
        user_id = ""
        if member and not member.get("pending"):
            user = member.get("user") if isinstance(member.get("user"), dict) else {}
            user_id = str(user.get("id") or "")
        if user_id:
            dest_ids.append(int(user_id) if user_id.isdigit() else user_id)
        else:
            missing.append(email)
    if missing:
        report.notes.append("Replay access waiting on members: " + ", ".join(missing))
    if not dest_ids and not (snapshot.get("organization") or {}).get("hasGranularReplayPermissions"):
        return
    body = {
        "hasGranularReplayPermissions": True,
        "replayAccessMembers": dest_ids,
    }
    try:
        sink.put(f"/organizations/{sink.client.org}/", body, "replay access")
    except ApiError as exc:
        _fail(report, "replay access", exc)
