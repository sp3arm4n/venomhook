"""Tests for jadx_runner — discovery, subprocess invocation, and native-method extraction.

Lives under sample/tests/ (gitignored) to honor the project's source-only commit
policy. Synthetic Java files exercise the regex-based extractor in isolation;
the subprocess path is covered with a stub jadx binary written into a tmp dir.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _subproc_stub import make_stub_executable

from venomhook.jadx_runner import (
    JADX_ENV_VAR,
    JadxConfig,
    JadxError,
    JadxNotFoundError,
    JadxResult,
    JadxRunError,
    _extract_from_text,
    _parse_class_fqn,
    _split_params,
    _strip_noise,
    decompile_apk,
    extract_native_methods,
    find_jadx,
    run_jadx,
)
from venomhook.models import JavaNativeMethod


def _write_executable(path: Path, body: str) -> Path:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


# ---------- find_jadx ----------


class TestFindJadx(unittest.TestCase):
    def setUp(self):
        self.saved_env = os.environ.pop(JADX_ENV_VAR, None)

    def tearDown(self):
        if self.saved_env is not None:
            os.environ[JADX_ENV_VAR] = self.saved_env
        else:
            os.environ.pop(JADX_ENV_VAR, None)

    def test_explicit_env_var_wins(self):
        with tempfile.TemporaryDirectory() as td:
            stub = _write_executable(Path(td) / "my-jadx", "#!/bin/sh\nexit 0\n")
            os.environ[JADX_ENV_VAR] = str(stub)
            self.assertEqual(find_jadx(), str(stub))

    def test_env_var_pointing_to_nonexistent_raises(self):
        os.environ[JADX_ENV_VAR] = "/nonexistent/jadx-binary"
        with self.assertRaises(JadxNotFoundError):
            find_jadx()

    def test_env_var_pointing_to_directory_raises(self):
        with tempfile.TemporaryDirectory() as td:
            os.environ[JADX_ENV_VAR] = td
            with self.assertRaises(JadxNotFoundError):
                find_jadx()

    def test_path_lookup_falls_back_when_no_env(self):
        with mock.patch("venomhook.jadx_runner.shutil.which") as m:
            m.side_effect = lambda name: f"/usr/local/bin/{name}" if name == "jadx" else None
            self.assertEqual(find_jadx(), "/usr/local/bin/jadx")

    def test_jadx_cli_alias_is_tried(self):
        with mock.patch("venomhook.jadx_runner.shutil.which") as m:
            m.side_effect = lambda name: f"/opt/{name}" if name == "jadx-cli" else None
            self.assertEqual(find_jadx(), "/opt/jadx-cli")

    def test_not_found_raises(self):
        with mock.patch("venomhook.jadx_runner.shutil.which", return_value=None):
            with self.assertRaises(JadxNotFoundError) as ctx:
                find_jadx()
            self.assertIn("VENOMHOOK_JADX", str(ctx.exception))


# ---------- _split_params ----------


class TestSplitParams(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(_split_params(""), [])
        self.assertEqual(_split_params("   "), [])

    def test_single_primitive(self):
        self.assertEqual(_split_params("int n"), ["int"])

    def test_multiple_primitives(self):
        self.assertEqual(_split_params("int n, long m, byte b"), ["int", "long", "byte"])

    def test_array(self):
        self.assertEqual(_split_params("byte[] data, int len"), ["byte[]", "int"])

    def test_generic_with_inner_comma(self):
        # Whitespace inside generics is preserved verbatim — only top-level
        # commas split parameters, which is what matters for JNI signature
        # conversion downstream.
        self.assertEqual(
            _split_params("Map<String, String> m, int n"),
            ["Map<String, String>", "int"],
        )

    def test_nested_generic(self):
        self.assertEqual(
            _split_params("List<Map<String, Integer>> data"),
            ["List<Map<String, Integer>>"],
        )

    def test_final_qualifier_dropped(self):
        self.assertEqual(_split_params("final int n, final String s"), ["int", "String"])

    def test_varargs_converted_to_array(self):
        self.assertEqual(_split_params("String... names"), ["String[]"])

    def test_fully_qualified_type(self):
        self.assertEqual(_split_params("java.lang.String s"), ["java.lang.String"])


# ---------- _strip_noise ----------


class TestStripNoise(unittest.TestCase):
    def test_strips_block_comments(self):
        self.assertEqual(_strip_noise("a /* native xxx */ b"), "a  b")

    def test_strips_line_comments(self):
        self.assertEqual(_strip_noise("a // native fake\nb"), "a \nb")

    def test_strips_strings(self):
        self.assertEqual(_strip_noise('"public native int evil()"'), '""')

    def test_strips_annotations(self):
        result = _strip_noise("@Override public native void foo();")
        self.assertNotIn("@Override", result)
        self.assertIn("native", result)

    def test_string_with_escaped_quote(self):
        # Escaped quote should not terminate the string match prematurely.
        self.assertEqual(_strip_noise(r'"a\"b" x'), '"" x')


# ---------- _parse_class_fqn ----------


class TestParseClassFqn(unittest.TestCase):
    def test_with_package(self):
        text = "package com.foo.bar;\npublic class Baz {}"
        self.assertEqual(_parse_class_fqn(text, "Baz"), "com.foo.bar.Baz")

    def test_no_package(self):
        text = "public class Baz {}"
        self.assertEqual(_parse_class_fqn(text, "Baz"), "Baz")

    def test_interface(self):
        text = "package x;\npublic interface Bar {}"
        self.assertEqual(_parse_class_fqn(text, "fallback"), "x.Bar")

    def test_falls_back_to_filename_stem(self):
        text = "package z;\n// no recognizable type\n"
        self.assertEqual(_parse_class_fqn(text, "Stem"), "z.Stem")


# ---------- _extract_from_text ----------


class TestExtractFromText(unittest.TestCase):
    def test_basic_native(self):
        src = textwrap.dedent("""
            package com.example;
            public class Foo {
                public native String getToken(String key);
            }
        """)
        out = _extract_from_text(src, "Foo.java", "Foo")
        self.assertEqual(len(out), 1)
        m = out[0]
        self.assertEqual(m.class_fqn, "com.example.Foo")
        self.assertEqual(m.method_name, "getToken")
        self.assertEqual(m.return_type, "String")
        self.assertEqual(m.arg_types, ["String"])
        self.assertFalse(m.is_static)
        self.assertEqual(m.source_file, "Foo.java")

    def test_static_native(self):
        src = """
            package p;
            class C { public static native int foo(); }
        """
        out = _extract_from_text(src, None, "C")
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].is_static)
        self.assertEqual(out[0].method_name, "foo")
        self.assertEqual(out[0].return_type, "int")
        self.assertIsNone(out[0].source_file)

    def test_byte_array_signature(self):
        src = """
            package p;
            class C { native byte[] encrypt(byte[] data, int len); }
        """
        out = _extract_from_text(src, "p/C.java", "C")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].return_type, "byte[]")
        self.assertEqual(out[0].arg_types, ["byte[]", "int"])

    def test_generics_in_return_and_args(self):
        src = """
            package p;
            class C { public native Map<String, String> dump(List<Integer> ids); }
        """
        out = _extract_from_text(src, None, "C")
        self.assertEqual(len(out), 1)
        # Whitespace inside generics is collapsed by the cleaner
        self.assertTrue(out[0].return_type.startswith("Map<"))
        self.assertEqual(out[0].arg_types, ["List<Integer>"])

    def test_multiple_modifiers_and_throws(self):
        src = """
            package p;
            class C {
                public final synchronized native void doIt(int x) throws java.io.IOException;
            }
        """
        out = _extract_from_text(src, None, "C")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].method_name, "doIt")
        self.assertEqual(out[0].return_type, "void")
        self.assertEqual(out[0].arg_types, ["int"])

    def test_no_modifier_other_than_native(self):
        src = """
            package p;
            class C { native void bare(); }
        """
        out = _extract_from_text(src, None, "C")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].method_name, "bare")

    def test_ignores_non_native_methods(self):
        src = """
            package p;
            class C {
                public String regular() { return ""; }
                public native String real();
            }
        """
        out = _extract_from_text(src, None, "C")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].method_name, "real")

    def test_native_in_string_literal_ignored(self):
        src = '''
            package p;
            class C {
                String msg = "public native String trap();";
                public native int actual();
            }
        '''
        out = _extract_from_text(src, None, "C")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].method_name, "actual")

    def test_native_in_block_comment_ignored(self):
        src = """
            package p;
            class C {
                /* example: public native int trap(); */
                public native int real();
            }
        """
        out = _extract_from_text(src, None, "C")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].method_name, "real")

    def test_annotated_native_method(self):
        src = """
            package p;
            class C {
                @Override
                @SuppressWarnings("foo")
                public native String annotated();
            }
        """
        out = _extract_from_text(src, None, "C")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].method_name, "annotated")

    def test_variable_named_native_handle_not_matched(self):
        # `nativeHandle` field shouldn't be misread as a `native` method.
        src = """
            package p;
            class C {
                private long nativeHandle;
                public int getHandle() { return (int) nativeHandle; }
            }
        """
        out = _extract_from_text(src, None, "C")
        self.assertEqual(out, [])

    def test_kotlin_external_decompiled_form(self):
        # jadx renders Kotlin `external fun` as Java `native`.
        src = """
            package com.k;
            public final class K {
                public static final native long openSession();
            }
        """
        out = _extract_from_text(src, None, "K")
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].is_static)
        self.assertEqual(out[0].class_fqn, "com.k.K")

    def test_varargs_param(self):
        src = """
            package p;
            class C { public native void log(String tag, Object... args); }
        """
        out = _extract_from_text(src, None, "C")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].arg_types, ["String", "Object[]"])

    def test_multiple_natives_in_one_class(self):
        src = """
            package p;
            class C {
                public native int a();
                public native int b(int x);
                public static native String c();
            }
        """
        out = _extract_from_text(src, None, "C")
        self.assertEqual([m.method_name for m in out], ["a", "b", "c"])
        self.assertEqual([m.is_static for m in out], [False, False, True])


# ---------- extract_native_methods ----------


class TestExtractNativeMethods(unittest.TestCase):
    def _make_jadx_tree(self, root: Path) -> None:
        sources = root / "sources"
        (sources / "com" / "ex" / "a").mkdir(parents=True)
        (sources / "com" / "ex" / "b").mkdir(parents=True)
        (sources / "com" / "ex" / "a" / "Alpha.java").write_text(textwrap.dedent("""
            package com.ex.a;
            public class Alpha {
                public native int alpha(byte[] data);
            }
        """))
        (sources / "com" / "ex" / "b" / "Beta.java").write_text(textwrap.dedent("""
            package com.ex.b;
            class Beta {
                public static native String beta();
            }
        """))
        # Empty class — should yield nothing.
        (sources / "Empty.java").write_text("public class Empty {}")
        # Non-Java file — should be ignored by rglob filter.
        (sources / "README.txt").write_text("not java")

    def test_walks_tree_and_collects(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._make_jadx_tree(root)
            results = extract_native_methods(root)
            names = [(r.class_fqn, r.method_name) for r in results]
            self.assertIn(("com.ex.a.Alpha", "alpha"), names)
            self.assertIn(("com.ex.b.Beta", "beta"), names)
            self.assertEqual(len(results), 2)

    def test_missing_root_raises(self):
        with self.assertRaises(JadxError):
            extract_native_methods("/no/such/path/here/__deep")

    def test_root_is_file_raises(self):
        with tempfile.NamedTemporaryFile(suffix=".java") as tmp:
            with self.assertRaises(JadxError):
                extract_native_methods(tmp.name)

    def test_empty_tree_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(extract_native_methods(td), [])


# ---------- run_jadx ----------


class TestRunJadx(unittest.TestCase):
    def test_missing_apk_raises(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = JadxConfig(jadx_path="/bin/true")
            with self.assertRaises(JadxRunError):
                run_jadx("/nonexistent/file.apk", Path(td) / "out", config=cfg)

    def test_directory_apk_raises(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = JadxConfig(jadx_path="/bin/true")
            with self.assertRaises(JadxRunError):
                run_jadx(td, Path(td) / "out", config=cfg)

    def test_successful_invocation_with_stub(self):
        # Build a stub jadx that produces one .java file and exits 0.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "fake.apk"
            apk.write_bytes(b"PK\x03\x04stub")  # any non-empty file
            stub = make_stub_executable(
                tdp / "stub-jadx",
                out_flag="-d",
                files={
                    "sources/com/x/Stub.java": (
                        "package com.x;\n"
                        "public class Stub {\n"
                        "    public native int stub();\n"
                        "}\n"
                    )
                },
            )

            cfg = JadxConfig(jadx_path=str(stub))
            result = run_jadx(apk, tdp / "out", config=cfg)
            self.assertEqual(result.returncode, 0)
            self.assertGreaterEqual(result.java_files, 1)
            self.assertEqual(result.apk_path, str(apk.resolve()))

    def test_failed_invocation_with_no_output_raises(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "fake.apk"
            apk.write_bytes(b"PK\x03\x04stub")
            failing = make_stub_executable(
                tdp / "fail-jadx", exit_code=5, stderr_text="boom\n"
            )

            cfg = JadxConfig(jadx_path=str(failing))
            with self.assertRaises(JadxRunError) as ctx:
                run_jadx(apk, tdp / "out", config=cfg)
            self.assertIn("exit=5", str(ctx.exception))

    def test_launch_os_error_is_wrapped(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "fake.apk"
            apk.write_bytes(b"PK")
            with mock.patch(
                "venomhook.jadx_runner.subprocess.run",
                side_effect=PermissionError("permission denied"),
            ):
                with self.assertRaises(JadxRunError) as ctx:
                    run_jadx(
                        apk, tdp / "out", config=JadxConfig(jadx_path="/bad/jadx")
                    )
            self.assertIn("could not exec jadx binary", str(ctx.exception))

    def test_partial_failure_with_output_is_accepted(self):
        # jadx returns non-zero on partial decompile; if .java exists, succeed.
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "fake.apk"
            apk.write_bytes(b"PK")
            partial = make_stub_executable(
                tdp / "partial-jadx",
                out_flag="-d",
                files={"X.java": "package x;\nclass X {}\n"},
                exit_code=1,
            )
            cfg = JadxConfig(jadx_path=str(partial))
            result = run_jadx(apk, tdp / "out", config=cfg)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.java_files, 1)
            self.assertFalse(result.partial)  # non-zero != timeout

    def test_timeout_with_partial_output_returns_partial_result(self):
        """Phase 10-3: jadx timeout that already wrote .java files
        returns JadxResult(partial=True) instead of raising.

        KakaoTalk-scale APKs hit the timeout but typically have 30K+
        decompiled .java files on disk by then — that's audit-grade
        input. Discarding it as the old behavior did was a defect.
        """
        import subprocess as sp
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "x.apk"
            apk.write_bytes(b"PK")
            out_dir = tdp / "out"

            def fake_run(cmd, **kw):
                # Simulate jadx writing some .java then being killed.
                target_dir = Path(cmd[cmd.index("-d") + 1])
                target_dir.mkdir(parents=True, exist_ok=True)
                for i in range(3):
                    (target_dir / f"Foo{i}.java").write_text("class F {}")
                raise sp.TimeoutExpired(cmd, timeout=kw.get("timeout"),
                                         output=b"", stderr=b"")

            with mock.patch("subprocess.run", side_effect=fake_run):
                cfg = JadxConfig(jadx_path="/fake/jadx", timeout_sec=1)
                result = run_jadx(apk, out_dir, config=cfg)

            self.assertTrue(result.partial)
            self.assertEqual(result.returncode, -1)
            self.assertEqual(result.java_files, 3)
            self.assertIn("timed out", result.stderr_tail)

    def test_timeout_with_no_output_still_raises(self):
        """Empty disk on timeout means nothing for code_audit — propagate
        the failure rather than pretending the run was partial.
        """
        import subprocess as sp
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "x.apk"
            apk.write_bytes(b"PK")

            def fake_run(cmd, **kw):
                raise sp.TimeoutExpired(cmd, timeout=kw.get("timeout"),
                                         output=b"", stderr=b"")

            with mock.patch("subprocess.run", side_effect=fake_run):
                cfg = JadxConfig(jadx_path="/fake/jadx", timeout_sec=1)
                with self.assertRaises(JadxRunError) as ctx:
                    run_jadx(apk, tdp / "out", config=cfg)
            self.assertIn("timed out", str(ctx.exception))

    def test_command_line_includes_default_flags(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "x.apk"
            apk.write_bytes(b"PK")
            seen: dict[str, list[str]] = {}

            class FakeCompleted:
                returncode = 0
                stdout = ""
                stderr = ""

            def fake_run(cmd, **kw):
                seen["cmd"] = list(cmd)
                # Write a marker .java so we count >0 files.
                out_dir = Path(cmd[cmd.index("-d") + 1])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "x.java").write_text("class X {}")
                return FakeCompleted()

            with mock.patch("venomhook.jadx_runner.subprocess.run", side_effect=fake_run):
                run_jadx(apk, tdp / "o", config=JadxConfig(jadx_path="/usr/bin/jadx"))
            cmd = seen["cmd"]
            self.assertEqual(cmd[0], "/usr/bin/jadx")
            self.assertIn("--no-res", cmd)
            self.assertIn("--no-imports", cmd)
            self.assertIn("--no-debug-info", cmd)
            self.assertIn(str(apk.resolve()), cmd)

    def test_threads_and_extra_args_passed(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "x.apk"
            apk.write_bytes(b"PK")
            seen: dict[str, list[str]] = {}

            class FakeCompleted:
                returncode = 0
                stdout = ""
                stderr = ""

            def fake_run(cmd, **kw):
                seen["cmd"] = list(cmd)
                out_dir = Path(cmd[cmd.index("-d") + 1])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "x.java").write_text("class X {}")
                return FakeCompleted()

            cfg = JadxConfig(
                jadx_path="/usr/bin/jadx",
                threads=4,
                extra_args=["--decompilation-mode", "simple"],
            )
            with mock.patch("venomhook.jadx_runner.subprocess.run", side_effect=fake_run):
                run_jadx(apk, tdp / "o", config=cfg)
            cmd = seen["cmd"]
            self.assertIn("-j", cmd)
            self.assertIn("4", cmd)
            self.assertIn("--decompilation-mode", cmd)
            self.assertIn("simple", cmd)

    def test_fast_mode_appends_simple_mode_flag(self):
        """Phase 10-5: fast_mode=True adds '-m simple' to the command."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "x.apk"
            apk.write_bytes(b"PK")
            seen: dict[str, list[str]] = {}

            class FakeCompleted:
                returncode = 0
                stdout = ""
                stderr = ""

            def fake_run(cmd, **kw):
                seen["cmd"] = list(cmd)
                out_dir = Path(cmd[cmd.index("-d") + 1])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "x.java").write_text("class X {}")
                return FakeCompleted()

            cfg = JadxConfig(jadx_path="/usr/bin/jadx", fast_mode=True)
            with mock.patch("venomhook.jadx_runner.subprocess.run", side_effect=fake_run):
                run_jadx(apk, tdp / "o", config=cfg)
            cmd = seen["cmd"]
            # -m simple must be present
            self.assertIn("-m", cmd)
            self.assertEqual(cmd[cmd.index("-m") + 1], "simple")

    def test_fast_mode_default_false_does_not_emit_m_flag(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "x.apk"
            apk.write_bytes(b"PK")
            seen: dict[str, list[str]] = {}

            class FakeCompleted:
                returncode = 0
                stdout = ""
                stderr = ""

            def fake_run(cmd, **kw):
                seen["cmd"] = list(cmd)
                out_dir = Path(cmd[cmd.index("-d") + 1])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "x.java").write_text("class X {}")
                return FakeCompleted()

            cfg = JadxConfig(jadx_path="/usr/bin/jadx")
            with mock.patch("venomhook.jadx_runner.subprocess.run", side_effect=fake_run):
                run_jadx(apk, tdp / "o", config=cfg)
            # -m must not appear because fast_mode defaults to False
            self.assertNotIn("-m", seen["cmd"])


# ---------- decompile_apk ----------


class TestDecompileApk(unittest.TestCase):
    def test_pipeline_returns_result_and_findings(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            apk = tdp / "fake.apk"
            apk.write_bytes(b"PK")

            stub = make_stub_executable(
                tdp / "stub-jadx",
                out_flag="-d",
                files={
                    "sources/com/p/A.java": (
                        "package com.p;\n"
                        "public class A {\n"
                        "    public native String tok();\n"
                        "    public native byte[] enc(byte[] x, int n);\n"
                        "}\n"
                    )
                },
            )

            result, natives = decompile_apk(apk, tdp / "o", config=JadxConfig(jadx_path=str(stub)))
            self.assertEqual(result.returncode, 0)
            self.assertEqual(len(natives), 2)
            self.assertEqual({n.method_name for n in natives}, {"tok", "enc"})
            enc = next(n for n in natives if n.method_name == "enc")
            self.assertEqual(enc.return_type, "byte[]")
            self.assertEqual(enc.arg_types, ["byte[]", "int"])
            self.assertEqual(enc.class_fqn, "com.p.A")


# ---------- JavaNativeMethod model round-trip ----------


class TestJavaNativeMethodModel(unittest.TestCase):
    def test_to_dict_and_from_dict(self):
        m = JavaNativeMethod(
            class_fqn="com.x.Y",
            method_name="z",
            return_type="String",
            arg_types=["int", "byte[]"],
            is_static=True,
            source_file="com/x/Y.java",
        )
        d = m.to_dict()
        self.assertEqual(
            d,
            {
                "class_fqn": "com.x.Y",
                "method_name": "z",
                "return_type": "String",
                "arg_types": ["int", "byte[]"],
                "is_static": True,
                "source_file": "com/x/Y.java",
            },
        )
        round = JavaNativeMethod.from_dict(d)
        self.assertEqual(round, m)

    def test_to_dict_omits_source_file_when_none(self):
        m = JavaNativeMethod(class_fqn="X", method_name="y", return_type="void")
        d = m.to_dict()
        self.assertNotIn("source_file", d)


if __name__ == "__main__":
    unittest.main()
