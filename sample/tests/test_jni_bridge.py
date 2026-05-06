"""Tests for jni_bridge — JNI mangling, type conversion, prediction, correlation.

Reference points for expected mangled forms:
- JNI specification §11.1 (Resolving Native Method Names)
- Cross-checked against `javac -h` output for trivial cases

All tests are pure-Python and do not invoke jadx or any binary tool.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from venomhook.jni_bridge import (
    JNI_SYMBOL_PREFIX,
    PRIMITIVE_JNI,
    WELL_KNOWN_OBJECT_FQNS,
    build_bridges,
    correlate_symbols,
    java_type_to_jni_sig,
    mangle_jni_identifier,
    predict_args_signature,
    predict_long,
    predict_short,
)
from venomhook.models import JavaNativeMethod, JniBridge


def _m(class_fqn: str, name: str, args=(), ret: str = "void", is_static: bool = False) -> JavaNativeMethod:
    return JavaNativeMethod(
        class_fqn=class_fqn,
        method_name=name,
        return_type=ret,
        arg_types=list(args),
        is_static=is_static,
    )


# ---------- mangle_jni_identifier ----------


class TestMangleIdentifier(unittest.TestCase):
    def test_alphanumeric_unchanged(self):
        self.assertEqual(mangle_jni_identifier("AbcXYZ123"), "AbcXYZ123")

    def test_underscore_escaped(self):
        self.assertEqual(mangle_jni_identifier("foo_bar"), "foo_1bar")
        self.assertEqual(mangle_jni_identifier("My_Class_Name"), "My_1Class_1Name")

    def test_dot_to_underscore(self):
        self.assertEqual(mangle_jni_identifier("com.foo.Bar"), "com_foo_Bar")

    def test_slash_to_underscore(self):
        self.assertEqual(mangle_jni_identifier("com/foo/Bar"), "com_foo_Bar")

    def test_dollar_for_inner_class(self):
        self.assertEqual(mangle_jni_identifier("Outer$Inner"), "Outer_00024Inner")

    def test_semicolon_and_bracket(self):
        self.assertEqual(mangle_jni_identifier(";"), "_2")
        self.assertEqual(mangle_jni_identifier("["), "_3")

    def test_mixed_signature_chars(self):
        # Args sig: Ljava/lang/String;I -> Ljava_lang_String_2I
        self.assertEqual(
            mangle_jni_identifier("Ljava/lang/String;I"),
            "Ljava_lang_String_2I",
        )

    def test_array_signature(self):
        # [B (byte array) -> _3B
        self.assertEqual(mangle_jni_identifier("[B"), "_3B")
        # [[I -> _3_3I
        self.assertEqual(mangle_jni_identifier("[[I"), "_3_3I")

    def test_non_ascii_escaped_4_hex(self):
        # Korean character -> _0xxxx
        self.assertEqual(mangle_jni_identifier("한"), "_0d55c")

    def test_underscore_and_dollar_combined(self):
        self.assertEqual(
            mangle_jni_identifier("foo_bar$Baz"),
            "foo_1bar_00024Baz",
        )


# ---------- java_type_to_jni_sig ----------


class TestJavaTypeToJniSig(unittest.TestCase):
    def test_primitives(self):
        for java, jni in PRIMITIVE_JNI.items():
            self.assertEqual(java_type_to_jni_sig(java), jni)

    def test_well_known_objects(self):
        self.assertEqual(java_type_to_jni_sig("String"), "Ljava/lang/String;")
        self.assertEqual(java_type_to_jni_sig("Object"), "Ljava/lang/Object;")
        self.assertEqual(java_type_to_jni_sig("HashMap"), "Ljava/util/HashMap;")

    def test_fully_qualified(self):
        self.assertEqual(
            java_type_to_jni_sig("java.util.Date"),
            "Ljava/util/Date;",
        )
        self.assertEqual(
            java_type_to_jni_sig("com.example.Foo"),
            "Lcom/example/Foo;",
        )

    def test_array_primitive(self):
        self.assertEqual(java_type_to_jni_sig("byte[]"), "[B")
        self.assertEqual(java_type_to_jni_sig("int[][]"), "[[I")

    def test_array_object(self):
        self.assertEqual(java_type_to_jni_sig("String[]"), "[Ljava/lang/String;")
        self.assertEqual(
            java_type_to_jni_sig("java.util.Date[]"),
            "[Ljava/util/Date;",
        )

    def test_generics_erased(self):
        self.assertEqual(java_type_to_jni_sig("List<String>"), "Ljava/util/List;")
        self.assertEqual(
            java_type_to_jni_sig("Map<String, Integer>"),
            "Ljava/util/Map;",
        )

    def test_nested_generics_erased(self):
        self.assertEqual(
            java_type_to_jni_sig("List<Map<String, Integer>>"),
            "Ljava/util/List;",
        )

    def test_unknown_short_class_no_default_package(self):
        self.assertIsNone(java_type_to_jni_sig("MyCustomType"))

    def test_default_package_heuristic(self):
        self.assertEqual(
            java_type_to_jni_sig("MyType", default_package="com.foo"),
            "Lcom/foo/MyType;",
        )

    def test_default_package_with_array(self):
        self.assertEqual(
            java_type_to_jni_sig("MyType[]", default_package="com.foo"),
            "[Lcom/foo/MyType;",
        )

    def test_default_package_does_not_clobber_known(self):
        # String is well-known; default_package shouldn't redirect it
        self.assertEqual(
            java_type_to_jni_sig("String", default_package="com.foo"),
            "Ljava/lang/String;",
        )

    def test_lowercase_short_name_not_treated_as_class(self):
        # 'foo' isn't PascalCase so heuristic doesn't fire.
        self.assertIsNone(
            java_type_to_jni_sig("myField", default_package="com.foo")
        )

    def test_empty_returns_none(self):
        self.assertIsNone(java_type_to_jni_sig(""))
        self.assertIsNone(java_type_to_jni_sig("   "))


# ---------- predict_short / predict_long ----------


class TestPredictShort(unittest.TestCase):
    def test_basic(self):
        m = _m("com.foo.Bar", "doStuff")
        self.assertEqual(predict_short(m), "Java_com_foo_Bar_doStuff")

    def test_inner_class(self):
        m = _m("com.foo.Outer$Inner", "tick")
        self.assertEqual(predict_short(m), "Java_com_foo_Outer_00024Inner_tick")

    def test_underscore_in_method(self):
        m = _m("com.foo.Bar", "do_thing")
        self.assertEqual(predict_short(m), "Java_com_foo_Bar_do_1thing")

    def test_underscore_in_class_name(self):
        m = _m("com.foo.My_Class", "go")
        self.assertEqual(predict_short(m), "Java_com_foo_My_1Class_go")

    def test_default_package(self):
        # No '.' in FQN -> unpackaged class
        m = _m("Foo", "bar")
        self.assertEqual(predict_short(m), "Java_Foo_bar")


class TestPredictArgsSignature(unittest.TestCase):
    def test_no_args(self):
        m = _m("com.foo.Bar", "noop")
        sig, unresolved = predict_args_signature(m)
        self.assertEqual(sig, "")
        self.assertEqual(unresolved, [])

    def test_primitives_only(self):
        m = _m("com.foo.Bar", "f", args=["int", "long", "boolean"])
        sig, unresolved = predict_args_signature(m)
        self.assertEqual(sig, "IJZ")
        self.assertEqual(unresolved, [])

    def test_string_arg(self):
        m = _m("com.foo.Bar", "f", args=["String"])
        sig, unresolved = predict_args_signature(m)
        self.assertEqual(sig, "Ljava/lang/String;")

    def test_array_arg(self):
        m = _m("com.foo.Bar", "f", args=["byte[]", "int"])
        sig, unresolved = predict_args_signature(m)
        self.assertEqual(sig, "[BI")

    def test_default_package_inferred_from_class_fqn(self):
        # `Helper` is not well-known but lives in com.foo (same as class)
        m = _m("com.foo.Bar", "use", args=["Helper", "int"])
        sig, unresolved = predict_args_signature(m)
        self.assertEqual(sig, "Lcom/foo/Helper;I")
        self.assertEqual(unresolved, [])

    def test_unknown_type_marks_unresolved(self):
        # Unpackaged class + unknown short type -> unresolved
        m = _m("Bar", "use", args=["Mystery"])
        sig, unresolved = predict_args_signature(m)
        self.assertIsNone(sig)
        self.assertEqual(unresolved, ["Mystery"])

    def test_partial_resolution(self):
        m = _m("Bar", "f", args=["int", "Mystery", "String"])
        sig, unresolved = predict_args_signature(m)
        self.assertIsNone(sig)
        self.assertEqual(unresolved, ["Mystery"])


class TestPredictLong(unittest.TestCase):
    def test_no_args(self):
        m = _m("com.foo.Bar", "noop")
        long_sym, unresolved = predict_long(m)
        self.assertEqual(long_sym, "Java_com_foo_Bar_noop__")
        self.assertEqual(unresolved, [])

    def test_string_arg_mangled(self):
        # Sig: (Ljava/lang/String;)V
        # args (no parens, no return): Ljava/lang/String;
        # mangled: Ljava_lang_String_2
        m = _m("com.foo.Bar", "tok", args=["String"])
        long_sym, _ = predict_long(m)
        self.assertEqual(long_sym, "Java_com_foo_Bar_tok__Ljava_lang_String_2")

    def test_byte_array_arg_mangled(self):
        # arg: byte[] -> [B -> _3B
        m = _m("com.foo.Bar", "enc", args=["byte[]", "int"])
        long_sym, _ = predict_long(m)
        self.assertEqual(long_sym, "Java_com_foo_Bar_enc___3BI")

    def test_unresolved_blocks_long_form(self):
        m = _m("Bar", "f", args=["Mystery"])
        long_sym, unresolved = predict_long(m)
        self.assertIsNone(long_sym)
        self.assertEqual(unresolved, ["Mystery"])


# ---------- build_bridges ----------


class TestBuildBridges(unittest.TestCase):
    def test_single_method_no_overload(self):
        ms = [_m("com.foo.Bar", "go", args=["int"])]
        bridges = build_bridges(ms)
        self.assertEqual(len(bridges), 1)
        b = bridges[0]
        self.assertEqual(b.predicted_short, "Java_com_foo_Bar_go")
        self.assertIsNone(b.predicted_long)
        self.assertFalse(b.is_overloaded)
        self.assertFalse(b.is_matched)

    def test_overload_detected_and_long_form_set_for_all(self):
        ms = [
            _m("com.foo.Bar", "go", args=["int"]),
            _m("com.foo.Bar", "go", args=["String"]),
        ]
        bridges = build_bridges(ms)
        self.assertEqual(len(bridges), 2)
        self.assertTrue(all(b.is_overloaded for b in bridges))
        self.assertEqual(bridges[0].predicted_long, "Java_com_foo_Bar_go__I")
        self.assertEqual(
            bridges[1].predicted_long,
            "Java_com_foo_Bar_go__Ljava_lang_String_2",
        )

    def test_different_classes_same_method_not_overloaded(self):
        ms = [
            _m("com.foo.A", "go", args=["int"]),
            _m("com.foo.B", "go", args=["int"]),
        ]
        bridges = build_bridges(ms)
        self.assertFalse(any(b.is_overloaded for b in bridges))

    def test_always_long_form_flag(self):
        ms = [_m("com.foo.Bar", "f", args=["int"])]
        bridges = build_bridges(ms, always_long_form=True)
        self.assertEqual(bridges[0].predicted_long, "Java_com_foo_Bar_f__I")

    def test_unresolved_args_recorded(self):
        ms = [_m("Bar", "f", args=["Mystery"]), _m("Bar", "f", args=["int"])]
        bridges = build_bridges(ms)  # overloaded
        self.assertEqual(bridges[0].unresolved_arg_types, ["Mystery"])
        self.assertIsNone(bridges[0].predicted_long)
        self.assertEqual(bridges[1].predicted_long, "Java_Bar_f__I")
        self.assertEqual(bridges[1].unresolved_arg_types, [])

    def test_input_order_preserved(self):
        ms = [
            _m("com.x.A", "z"),
            _m("com.x.A", "a"),
            _m("com.x.A", "m"),
        ]
        bridges = build_bridges(ms)
        self.assertEqual(
            [b.java_method.method_name for b in bridges],
            ["z", "a", "m"],
        )


# ---------- correlate_symbols ----------


class TestCorrelateSymbols(unittest.TestCase):
    def test_short_form_match(self):
        ms = [_m("com.foo.Bar", "go")]
        bridges = build_bridges(ms)
        symbols = ["JNI_OnLoad", "Java_com_foo_Bar_go", "irrelevant_sym"]
        out = correlate_symbols(bridges, symbols)
        self.assertEqual(out[0].matched_symbol, "Java_com_foo_Bar_go")

    def test_long_form_match_when_overloaded(self):
        ms = [
            _m("com.foo.Bar", "go", args=["int"]),
            _m("com.foo.Bar", "go", args=["String"]),
        ]
        bridges = build_bridges(ms)
        symbols = [
            "Java_com_foo_Bar_go__I",
            "Java_com_foo_Bar_go__Ljava_lang_String_2",
        ]
        out = correlate_symbols(bridges, symbols)
        self.assertEqual(out[0].matched_symbol, "Java_com_foo_Bar_go__I")
        self.assertEqual(
            out[1].matched_symbol,
            "Java_com_foo_Bar_go__Ljava_lang_String_2",
        )

    def test_no_match_leaves_matched_symbol_none(self):
        ms = [_m("com.foo.Bar", "go")]
        bridges = build_bridges(ms)
        out = correlate_symbols(bridges, ["unrelated_symbol"])
        self.assertIsNone(out[0].matched_symbol)

    def test_non_jni_symbols_filtered(self):
        ms = [_m("com.foo.Bar", "go")]
        bridges = build_bridges(ms)
        # A symbol like "foo_Java_com_foo_Bar_go_extra" should NOT match
        out = correlate_symbols(bridges, ["foo_Java_com_foo_Bar_go_extra"])
        self.assertIsNone(out[0].matched_symbol)

    def test_long_preferred_over_short_when_both_present(self):
        ms = [
            _m("com.foo.Bar", "go", args=["int"]),
            _m("com.foo.Bar", "go", args=["String"]),
        ]
        bridges = build_bridges(ms)
        # Pathological case: both forms exported. Long should win for overloads.
        symbols = [
            "Java_com_foo_Bar_go",
            "Java_com_foo_Bar_go__I",
        ]
        out = correlate_symbols(bridges, symbols)
        self.assertEqual(out[0].matched_symbol, "Java_com_foo_Bar_go__I")

    def test_partial_match_some_resolved(self):
        ms = [_m("com.foo.A", "x"), _m("com.foo.B", "y")]
        bridges = build_bridges(ms)
        out = correlate_symbols(bridges, ["Java_com_foo_A_x"])
        self.assertEqual(out[0].matched_symbol, "Java_com_foo_A_x")
        self.assertIsNone(out[1].matched_symbol)


# ---------- JniBridge model ----------


class TestJniBridgeModel(unittest.TestCase):
    def test_round_trip_full(self):
        b = JniBridge(
            java_method=_m("com.foo.Bar", "f", args=["int"], ret="String"),
            predicted_short="Java_com_foo_Bar_f",
            predicted_long="Java_com_foo_Bar_f__I",
            matched_symbol="Java_com_foo_Bar_f__I",
            unresolved_arg_types=["Custom"],
        )
        d = b.to_dict()
        round_tripped = JniBridge.from_dict(d)
        self.assertEqual(round_tripped, b)

    def test_to_dict_omits_optional_when_unset(self):
        b = JniBridge(
            java_method=_m("com.foo.Bar", "f"),
            predicted_short="Java_com_foo_Bar_f",
        )
        d = b.to_dict()
        self.assertNotIn("predicted_long", d)
        self.assertNotIn("matched_symbol", d)
        self.assertNotIn("unresolved_arg_types", d)

    def test_is_matched_property(self):
        b = JniBridge(
            java_method=_m("X", "y"),
            predicted_short="Java_X_y",
        )
        self.assertFalse(b.is_matched)
        b.matched_symbol = "Java_X_y"
        self.assertTrue(b.is_matched)


# ---------- end-to-end realistic sample ----------


class TestRealisticBridgeFlow(unittest.TestCase):
    def test_apk_native_to_so_correlation(self):
        # Hypothetical APK with two native methods, one overloaded
        java_methods = [
            _m("com.app.Crypto", "encrypt", args=["byte[]", "int"], ret="byte[]"),
            _m("com.app.Crypto", "encrypt", args=["String"], ret="String"),
            _m("com.app.NetworkClient", "send", args=["String"], ret="int"),
        ]
        # Pretend the .so exports these symbols (long form for overloads)
        so_symbols = [
            "Java_com_app_Crypto_encrypt___3BI",
            "Java_com_app_Crypto_encrypt__Ljava_lang_String_2",
            "Java_com_app_NetworkClient_send",
            "JNI_OnLoad",
            "_init",
        ]

        bridges = build_bridges(java_methods)
        correlate_symbols(bridges, so_symbols)

        # All three should match
        self.assertTrue(all(b.is_matched for b in bridges))
        self.assertEqual(
            bridges[0].matched_symbol, "Java_com_app_Crypto_encrypt___3BI"
        )
        self.assertEqual(
            bridges[1].matched_symbol,
            "Java_com_app_Crypto_encrypt__Ljava_lang_String_2",
        )
        self.assertEqual(
            bridges[2].matched_symbol, "Java_com_app_NetworkClient_send"
        )


if __name__ == "__main__":
    unittest.main()
