"""JNI bridge — Java native method ↔ C symbol prediction & correlation.

Implements the static half of VenomHook's Phase 2 Java↔Native correlation:
predict the JNI C symbol that the JVM will look up for a given native method
following JNI specification §11.1 mangling, then match those predictions
against the actual exported symbols of an .so binary.

  Java_<mangled_class>_<mangled_method>                    # short form
  Java_<mangled_class>_<mangled_method>__<mangled_argsig>  # long form (overloaded only)

Mangling rules (per char of each Java identifier):
  alphanumeric ASCII -> unchanged
  '_'                -> '_1'
  ';'                -> '_2'
  '['                -> '_3'
  '$'                -> '_00024'
  '/' or '.'         -> '_'           (path separator, no escape)
  non-ASCII          -> '_0xxxx'      (4-digit hex)

Dynamic registration via ``JNIEnv->RegisterNatives`` requires smali/DEX
inspection and is deferred. The current implementation captures dynamic
registrations indirectly when the registered functions are also exported
in the .so symbol table (the common case for unstripped libraries).

Pure-Python; depends on models.{JavaNativeMethod, JniBridge}.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable, Optional

from venomhook.models import JavaNativeMethod, JniBridge


__all__ = [
    "java_type_to_jni_sig",
    "mangle_jni_identifier",
    "predict_short",
    "predict_long",
    "predict_args_signature",
    "build_bridges",
    "correlate_symbols",
    "JNI_SYMBOL_PREFIX",
    "PRIMITIVE_JNI",
    "WELL_KNOWN_OBJECT_FQNS",
]


JNI_SYMBOL_PREFIX = "Java_"


# ---------- type tables ----------


PRIMITIVE_JNI: dict[str, str] = {
    "void": "V",
    "boolean": "Z",
    "byte": "B",
    "char": "C",
    "short": "S",
    "int": "I",
    "long": "J",
    "float": "F",
    "double": "D",
}

# Map short class names commonly seen in Java sources to their fully qualified
# JVM-internal paths. Covers java.lang & java.util defaults that jadx emits as
# bare names because of `import` statements (which jadx_runner strips with
# --no-imports for speed). Anything outside this table requires either an FQN
# or the default-package heuristic.
WELL_KNOWN_OBJECT_FQNS: dict[str, str] = {
    "Object": "java/lang/Object",
    "String": "java/lang/String",
    "Class": "java/lang/Class",
    "Throwable": "java/lang/Throwable",
    "Exception": "java/lang/Exception",
    "RuntimeException": "java/lang/RuntimeException",
    "Error": "java/lang/Error",
    "Integer": "java/lang/Integer",
    "Long": "java/lang/Long",
    "Boolean": "java/lang/Boolean",
    "Byte": "java/lang/Byte",
    "Character": "java/lang/Character",
    "Short": "java/lang/Short",
    "Float": "java/lang/Float",
    "Double": "java/lang/Double",
    "Number": "java/lang/Number",
    "CharSequence": "java/lang/CharSequence",
    "StringBuilder": "java/lang/StringBuilder",
    "StringBuffer": "java/lang/StringBuffer",
    "List": "java/util/List",
    "Map": "java/util/Map",
    "Set": "java/util/Set",
    "Collection": "java/util/Collection",
    "ArrayList": "java/util/ArrayList",
    "HashMap": "java/util/HashMap",
    "HashSet": "java/util/HashSet",
    "Iterator": "java/util/Iterator",
    "Date": "java/util/Date",
    "ByteBuffer": "java/nio/ByteBuffer",
    "InputStream": "java/io/InputStream",
    "OutputStream": "java/io/OutputStream",
    "File": "java/io/File",
}


# ---------- mangling ----------


def _escape_char(c: str) -> str:
    """Per-char JNI escape (§11.1).

    Note: '/' and '.' both collapse to '_' (separator). Callers that pass
    a class FQN with '.' separators get the same result as if they passed
    the JVM-internal '/' form.
    """
    if c.isalnum() and ord(c) < 128:
        return c
    if c == "_":
        return "_1"
    if c == ";":
        return "_2"
    if c == "[":
        return "_3"
    if c == "$":
        return "_00024"
    if c == "/" or c == ".":
        return "_"
    # Non-ASCII / unsupported character: 4-digit hex Unicode escape.
    return f"_0{ord(c):04x}"


def mangle_jni_identifier(name: str) -> str:
    """Mangle a Java identifier or path segment per JNI §11.1.

    Suitable for class FQNs (with '.' or '/' separators), method names, and
    JNI signature fragments.
    """
    return "".join(_escape_char(c) for c in name)


# ---------- type conversion ----------


_GENERIC_RE = re.compile(r"<[^<>]*>")


def _strip_generics(java_type: str) -> str:
    """Remove generic type parameters (Java erasure)."""
    prev = None
    cur = java_type
    # Repeat to handle nested generics: List<Map<String, Integer>> -> List
    while prev != cur:
        prev = cur
        cur = _GENERIC_RE.sub("", cur)
    return cur.strip()


def java_type_to_jni_sig(
    java_type: str,
    *,
    default_package: Optional[str] = None,
) -> Optional[str]:
    """Convert a Java type expression to its JNI signature string.

    Returns None when the type cannot be resolved (unknown short class name
    with no default-package fallback). Strips generics (erasure), handles
    arrays of any dimension, and accepts both fully-qualified (``java.util.Date``)
    and short-form (``String``, ``HashMap``) names.

    `default_package` is used as a heuristic for short PascalCase names not in
    WELL_KNOWN_OBJECT_FQNS — assumes the type lives in the same package as
    the calling Java class. Pass ``None`` to disable the heuristic.
    """
    s = _strip_generics(java_type)
    if not s:
        return None

    # Array dimensions: count trailing []s
    array_dims = 0
    while s.endswith("[]"):
        array_dims += 1
        s = s[:-2].strip()

    array_prefix = "[" * array_dims

    # Primitive
    if s in PRIMITIVE_JNI:
        return array_prefix + PRIMITIVE_JNI[s]

    # Fully qualified (contains '.')
    if "." in s:
        return array_prefix + "L" + s.replace(".", "/") + ";"

    # Well-known short class
    if s in WELL_KNOWN_OBJECT_FQNS:
        return array_prefix + "L" + WELL_KNOWN_OBJECT_FQNS[s] + ";"

    # Default-package heuristic: short name that looks like a class identifier
    # (PascalCase, no path separators). Assume same package as the caller.
    if default_package and re.match(r"^[A-Z][A-Za-z0-9_$]*$", s):
        return array_prefix + "L" + default_package.replace(".", "/") + "/" + s + ";"

    return None


# ---------- prediction ----------


def _default_package_for(class_fqn: str) -> Optional[str]:
    """Extract the package portion of a class FQN, or None if unpackaged."""
    if "." not in class_fqn:
        return None
    return class_fqn.rsplit(".", 1)[0]


def predict_short(method: JavaNativeMethod) -> str:
    """Predict the short-form JNI symbol for a native method.

    This is the canonical form when the method is NOT overloaded within its
    class. Always succeeds (mangling is total over Java identifiers).
    """
    return (
        JNI_SYMBOL_PREFIX
        + mangle_jni_identifier(method.class_fqn)
        + "_"
        + mangle_jni_identifier(method.method_name)
    )


def predict_args_signature(
    method: JavaNativeMethod,
    *,
    default_package: Optional[str] = None,
) -> tuple[Optional[str], list[str]]:
    """Build the JNI args signature (without parens or return) for a method.

    Returns ``(args_sig, unresolved)``. ``args_sig`` is None when any argument
    cannot be resolved; ``unresolved`` lists the offending raw Java type
    strings so callers can surface them for diagnostics.

    `default_package` defaults to the method's own class package if None.
    """
    if default_package is None:
        default_package = _default_package_for(method.class_fqn)

    parts: list[str] = []
    unresolved: list[str] = []
    for arg in method.arg_types:
        sig = java_type_to_jni_sig(arg, default_package=default_package)
        if sig is None:
            unresolved.append(arg)
            parts.append("?")  # placeholder; only used when unresolved
        else:
            parts.append(sig)

    if unresolved:
        return None, unresolved
    return "".join(parts), unresolved


def predict_long(
    method: JavaNativeMethod,
    *,
    default_package: Optional[str] = None,
) -> tuple[Optional[str], list[str]]:
    """Predict the long-form (overload-disambiguating) JNI symbol.

    Returns ``(symbol_or_none, unresolved_arg_types)``. The symbol is None
    when at least one argument type couldn't be resolved.
    """
    args_sig, unresolved = predict_args_signature(method, default_package=default_package)
    if args_sig is None:
        return None, unresolved
    short = predict_short(method)
    return f"{short}__{mangle_jni_identifier(args_sig)}", unresolved


# ---------- bridge building & correlation ----------


def build_bridges(
    methods: Iterable[JavaNativeMethod],
    *,
    always_long_form: bool = False,
) -> list[JniBridge]:
    """Build JniBridge records from JavaNativeMethod inputs.

    Auto-detects overloads (same class+method appearing more than once) and
    populates ``predicted_long`` for ALL members of an overloaded group,
    matching JNI's mangling requirement that overloaded natives use long form.

    `always_long_form` forces long-form prediction even for non-overloaded
    methods — useful when the caller wants to match against a binary that
    happens to use long form throughout.

    Output order matches input order; the only per-element observation is
    overload status, so this preserves caller iteration semantics.
    """
    methods_list = list(methods)

    # Group by (class_fqn, method_name) to detect overloads
    groups: dict[tuple[str, str], int] = defaultdict(int)
    for m in methods_list:
        groups[(m.class_fqn, m.method_name)] += 1

    bridges: list[JniBridge] = []
    for m in methods_list:
        short = predict_short(m)
        is_overloaded = groups[(m.class_fqn, m.method_name)] > 1
        if is_overloaded or always_long_form:
            long_sym, unresolved = predict_long(m)
        else:
            long_sym, unresolved = None, []
        bridges.append(
            JniBridge(
                java_method=m,
                predicted_short=short,
                predicted_long=long_sym,
                unresolved_arg_types=unresolved,
            )
        )
    return bridges


def correlate_symbols(
    bridges: Iterable[JniBridge],
    symbols: Iterable[str],
) -> list[JniBridge]:
    """Match each bridge against an actual exported-symbol list.

    Mutates and returns the bridges (also returns them as a list for chaining).
    Match precedence per bridge:
      1. predicted_long, if set, exact match against a symbol
      2. predicted_short, exact match against a symbol

    Symbols not starting with ``Java_`` are ignored. Callers passing a full
    symbol table can include them — the prefix filter happens internally.

    Note: a long-form symbol typically also satisfies short-form pattern matches
    (the JVM does dynamic resolution). We deliberately match LITERAL exported
    names — the binary either exports the long form or the short form, not both,
    and the JVM picks the right one at runtime. Correlation here just records
    which form the binary actually exports.
    """
    bridge_list = list(bridges)
    sym_set = {s for s in symbols if s.startswith(JNI_SYMBOL_PREFIX)}

    for b in bridge_list:
        if b.predicted_long and b.predicted_long in sym_set:
            b.matched_symbol = b.predicted_long
        elif b.predicted_short in sym_set:
            b.matched_symbol = b.predicted_short
        # else: leave matched_symbol as None
    return bridge_list
