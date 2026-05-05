from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Tuple

from venomhook.models import EndpointMeta, FunctionMeta, StaticMeta


# ===== Network APIs (OS-specific sets) =====
WIN_NETWORK = {
    "WSAStartup", "WSACleanup", "WSASocketA", "WSASocketW",
    "InternetOpen", "InternetOpenA", "InternetOpenW",
    "InternetReadFile", "InternetConnect", "InternetConnectA", "InternetConnectW",
    "HttpSendRequest", "HttpSendRequestA", "HttpSendRequestW",
    "HttpOpenRequest", "HttpOpenRequestA", "HttpOpenRequestW",
    "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "WinHttpReceiveResponse",
}
POSIX_NETWORK = {
    "socket", "bind", "listen", "accept",
    "connect", "send", "recv", "sendto", "recvfrom", "sendmsg", "recvmsg",
    "setsockopt", "getsockopt", "getaddrinfo", "freeaddrinfo", "gethostbyname",
    "select", "poll", "epoll_wait", "epoll_create", "epoll_ctl",
}
DARWIN_NETWORK = {
    "CFReadStreamCreateWithBytesNoCopy", "CFWriteStreamCreateWithAllocatedBuffers",
    "kqueue", "kevent",
}
# Aggregate (legacy / convenience for callers who want OS-agnostic match)
NETWORK_IMPORTS = WIN_NETWORK | POSIX_NETWORK | DARWIN_NETWORK


# ===== File APIs (OS-specific sets) =====
WIN_FILE = {
    "CreateFile", "CreateFileA", "CreateFileW",
    "ReadFile", "WriteFile",
    "DeleteFile", "DeleteFileA", "DeleteFileW",
    "MapViewOfFile", "CreateFileMapping", "CreateFileMappingA", "CreateFileMappingW",
    "MoveFile", "MoveFileA", "MoveFileW",
    "CopyFile", "CopyFileA", "CopyFileW",
    "GetFileSize", "GetFileSizeEx",
}
POSIX_FILE = {
    "open", "openat", "creat", "close",
    "read", "write", "pread", "pwrite", "lseek",
    "fopen", "fread", "fwrite", "fclose", "fseek",
    "stat", "fstat", "lstat",
    "mmap", "munmap",
    "unlink", "rename",
}
DARWIN_FILE: set[str] = set()  # Mach-O typically reaches files via POSIX or NSFileManager (ObjC runtime)
FILE_IMPORTS = WIN_FILE | POSIX_FILE | DARWIN_FILE


# ===== Android JNI (1st-class category) =====
JNI_IMPORTS = {
    "JNI_OnLoad", "JNI_OnUnload",
    "RegisterNatives", "GetEnv", "GetJavaVM",
    "FindClass", "GetMethodID", "GetStaticMethodID", "GetFieldID", "GetStaticFieldID",
    "CallObjectMethod", "CallVoidMethod", "CallIntMethod", "CallBooleanMethod",
    "CallStaticObjectMethod", "CallStaticVoidMethod", "CallStaticIntMethod",
    "GetStringUTFChars", "ReleaseStringUTFChars",
    "GetStringChars", "ReleaseStringChars",
    "NewStringUTF", "NewString",
    "GetByteArrayElements", "ReleaseByteArrayElements",
    "GetArrayLength", "NewByteArray",
}
JNI_SYMBOL_PATTERN = re.compile(r"^Java_[A-Za-z0-9_]+")
ANDROID_LOG_IMPORTS = {
    "__android_log_print", "__android_log_write", "__android_log_buf_write",
    "__android_log_assert", "__android_log_vprint",
}


# ===== Crypto (OS-specific + portable) =====
WIN_CRYPTO = {
    "CryptAcquireContext", "CryptAcquireContextA", "CryptAcquireContextW",
    "CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptCreateHash",
    "BCryptEncrypt", "BCryptDecrypt", "BCryptHashData",
}
DARWIN_CRYPTO = {
    "CCCrypt", "CCCryptorCreate", "CCCryptorUpdate",
    "CC_SHA256_Init", "CC_SHA256_Update", "CC_SHA256_Final",
    "CC_MD5_Init", "CC_MD5_Update", "CC_MD5_Final",
    "SecKeyCreate", "SecKeyEncrypt", "SecKeyDecrypt",
}
# OpenSSL/BoringSSL — common on Android and Linux native libs
SSL_IMPORTS = {
    "SSL_new", "SSL_read", "SSL_write", "SSL_connect", "SSL_accept",
    "EVP_EncryptInit_ex", "EVP_EncryptUpdate", "EVP_EncryptFinal_ex",
    "EVP_DecryptInit_ex", "EVP_DecryptUpdate", "EVP_DecryptFinal_ex",
    "EVP_DigestInit_ex", "EVP_DigestUpdate", "EVP_DigestFinal_ex",
    "AES_encrypt", "AES_decrypt", "AES_set_encrypt_key", "AES_set_decrypt_key",
    "BIO_new", "BIO_read", "BIO_write",
    "RAND_bytes",
}
CRYPTO_IMPORTS = WIN_CRYPTO | DARWIN_CRYPTO | SSL_IMPORTS


# ===== String-level keywords (OS-neutral) =====
CRYPTO_WORDS = {"encrypt", "decrypt", "aes", "rsa", "crypto", "sha", "md5", "hmac"}
AUTH_WORDS = {"auth", "token", "login", "session", "password", "cookie", "credential"}
URL_WORDS = {"http", "https", "://"}


@dataclass
class ScoreConfig:
    network_weight: int = 30
    file_weight: int = 20
    auth_weight: int = 15  # multiplied by distinct auth keywords count
    url_weight: int = 10
    crypto_weight: int = 10
    jni_weight: int = 30  # Android JNI bridge / 1st-class, on par with network
    callers_per: int = 2
    callers_cap: int = 10
    callees_per: int = 1
    callees_cap: int = 5
    basic_blocks_bonus: int = 5
    basic_blocks_threshold: int = 10


def _match_lower(haystack_lower: set[str], needles: set[str]) -> set[str]:
    """Case-insensitive intersection. `haystack_lower` MUST already be lowercased."""
    if not needles:
        return set()
    return haystack_lower & {n.lower() for n in needles}


# Design note: _score_function intentionally matches against ALL OS-specific sets
# simultaneously rather than auto-selecting from BinaryInfo.arch. Cross-compiled
# binaries (Cygwin/MinGW, Qt apps, Android with Bionic + OpenSSL, etc.) routinely
# mix POSIX-style and OS-native names, so "match all" avoids false negatives. The
# OS-suffix tags (network:posix vs network:windows, etc.) preserve the OS context
# for downstream filtering. Future ScoreConfig.os_filter (PR #2 territory once
# lief gives us authoritative binary OS) can narrow this when a user wants strict
# single-OS scoring.


def _score_function(fn: FunctionMeta, cfg: ScoreConfig) -> Tuple[int, list[str], list[str]]:
    score = 0
    tags: list[str] = []
    reasons: list[str] = []

    imports_lower = {imp.lower() for imp in fn.imports}
    strings_lower = [s.lower() for s in fn.strings]
    fn_name = fn.name or ""

    # ---- Network imports (OS-split) ----
    win_net = _match_lower(imports_lower, WIN_NETWORK)
    posix_net = _match_lower(imports_lower, POSIX_NETWORK)
    darwin_net = _match_lower(imports_lower, DARWIN_NETWORK)
    if win_net or posix_net or darwin_net:
        tags.append("network")
        if win_net:
            tags.append("network:windows")
        if posix_net:
            tags.append("network:posix")
        if darwin_net:
            tags.append("network:darwin")
        all_matches = sorted(win_net | posix_net | darwin_net)
        reasons.append(f"imports: {', '.join(all_matches)}")
        score += cfg.network_weight

    # ---- File imports (OS-split) ----
    win_file = _match_lower(imports_lower, WIN_FILE)
    posix_file = _match_lower(imports_lower, POSIX_FILE)
    darwin_file = _match_lower(imports_lower, DARWIN_FILE)
    if win_file or posix_file or darwin_file:
        tags.append("file")
        if win_file:
            tags.append("file:windows")
        if posix_file:
            tags.append("file:posix")
        if darwin_file:
            tags.append("file:darwin")
        all_matches = sorted(win_file | posix_file | darwin_file)
        reasons.append(f"imports: {', '.join(all_matches)}")
        score += cfg.file_weight

    # ---- Crypto imports (OS-split + SSL/BoringSSL) ----
    win_crypto = _match_lower(imports_lower, WIN_CRYPTO)
    darwin_crypto = _match_lower(imports_lower, DARWIN_CRYPTO)
    ssl_imports = _match_lower(imports_lower, SSL_IMPORTS)
    if win_crypto or darwin_crypto or ssl_imports:
        tags.append("crypto")
        if win_crypto:
            tags.append("crypto:windows")
        if darwin_crypto:
            tags.append("crypto:darwin")
        if ssl_imports:
            tags.append("crypto:ssl")
        all_matches = sorted(win_crypto | darwin_crypto | ssl_imports)
        reasons.append(f"crypto imports: {', '.join(all_matches)}")
        score += cfg.crypto_weight

    # ---- JNI / Android (1st-class) ----
    jni_imports = _match_lower(imports_lower, JNI_IMPORTS)
    android_log = _match_lower(imports_lower, ANDROID_LOG_IMPORTS)
    is_jni_symbol = bool(JNI_SYMBOL_PATTERN.match(fn_name))
    if jni_imports or is_jni_symbol or android_log:
        tags.append("android")
        if is_jni_symbol or jni_imports:
            tags.append("jni")
        if android_log:
            tags.append("android:log")
        if is_jni_symbol:
            reasons.append(f"jni: symbol {fn_name}")
        if jni_imports:
            reasons.append(f"jni imports: {', '.join(sorted(jni_imports))}")
        if android_log:
            reasons.append(f"android log: {', '.join(sorted(android_log))}")
        score += cfg.jni_weight

    # ---- String-based: AUTH ----
    if any(word in s for s in strings_lower for word in AUTH_WORDS):
        tags.append("auth")
        counts = Counter(word for s in strings_lower for word in AUTH_WORDS if word in s)
        reasons.append("strings: " + ", ".join(f"{k}({v})" for k, v in counts.items()))
        score += cfg.auth_weight * len(counts)

    # ---- String-based: URL ----
    if any(word in s for s in strings_lower for word in URL_WORDS):
        if "network" not in tags:
            tags.append("network")
        score += cfg.url_weight
        reasons.append("strings: url/http")

    # ---- String-based: CRYPTO keywords ----
    if any(word in s for s in strings_lower for word in CRYPTO_WORDS):
        if "crypto" not in tags:
            tags.append("crypto")
        score += cfg.crypto_weight
        reasons.append("strings: crypto keyword")

    # ---- Caller / callee fan-in / fan-out ----
    if fn.callers:
        score += min(len(fn.callers) * cfg.callers_per, cfg.callers_cap)
        reasons.append(f"callers: {len(fn.callers)}")

    if fn.callees:
        score += min(len(fn.callees) * cfg.callees_per, cfg.callees_cap)
        reasons.append(f"callees: {len(fn.callees)}")

    # ---- Function complexity ----
    if fn.basic_blocks and fn.basic_blocks > cfg.basic_blocks_threshold:
        score += cfg.basic_blocks_bonus
        reasons.append(f"basic_blocks: {fn.basic_blocks}")

    return score, sorted(set(tags)), reasons


def score_endpoints(meta: StaticMeta, top_n: int = 10, config: ScoreConfig | None = None) -> list[EndpointMeta]:
    cfg = config or ScoreConfig()
    endpoints: list[EndpointMeta] = []
    for fn in meta.functions:
        if fn.rva is None:
            continue
        score, tags, reasons = _score_function(fn, cfg)
        if score == 0:
            continue
        endpoints.append(
            EndpointMeta(
                module=meta.binary.name,
                arch=meta.binary.arch or "unknown",
                rva=fn.rva,
                score=score,
                tags=tags,
                reason=reasons,
            )
        )
    endpoints.sort(key=lambda item: item.score, reverse=True)
    return endpoints[:top_n]
