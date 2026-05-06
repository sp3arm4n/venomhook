import unittest
from types import SimpleNamespace

from venomhook.cli import apply_static_profile, apply_dynamic_profile, STATIC_DEFAULTS, DYNAMIC_DEFAULTS


class ProfileTests(unittest.TestCase):
    def test_apply_static_profile_overrides_defaults(self):
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
        self.assertEqual(args.sig_max_bytes, 16)
        self.assertEqual(args.score_network, 99)
        self.assertEqual(args.score_file, 42)


    def test_apply_dynamic_profile_overrides_defaults(self):
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
        self.assertEqual(args.hexdump_len, 16)
        self.assertEqual(args.string_arg, [1])
        self.assertIs(args.string_ret, True)
        self.assertEqual(args.string_len, 200)
        self.assertEqual(args.scan_size, 4096)
        self.assertEqual(args.retry_attach, 3)


if __name__ == "__main__":
    unittest.main()
