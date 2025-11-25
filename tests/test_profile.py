from types import SimpleNamespace

from venomhook.cli import apply_static_profile, apply_dynamic_profile, STATIC_DEFAULTS, DYNAMIC_DEFAULTS


def test_apply_static_profile_overrides_defaults():
    args = SimpleNamespace(**STATIC_DEFAULTS)
    profile = {
        "static": {
            "sig_max_bytes": 16,
            "score": {
                "network_weight": 99,
                "file_weight": 42,
            },
        }
    }
    apply_static_profile(args, profile)
    assert args.sig_max_bytes == 16
    assert args.score_network == 99
    assert args.score_file == 42


def test_apply_dynamic_profile_overrides_defaults():
    args = SimpleNamespace(**DYNAMIC_DEFAULTS)
    profile = {
        "dynamic": {
            "hexdump_len": 16,
            "string_arg": [1],
            "string_ret": True,
            "string_len": 200,
            "scan_size": 4096,
            "retry_attach": 3,
        }
    }
    apply_dynamic_profile(args, profile)
    assert args.hexdump_len == 16
    assert args.string_arg == [1]
    assert args.string_ret is True
    assert args.string_len == 200
    assert args.scan_size == 4096
    assert args.retry_attach == 3
