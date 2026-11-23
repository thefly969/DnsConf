import unittest
from unittest.mock import patch

import scripts.generate_dns_hosts as generator


class ResolverCountryFilterTests(unittest.TestCase):
    @patch.object(generator, "resolver_country", return_value="UA")
    @patch.object(generator, "resolver_ips", return_value=["203.0.113.10"])
    def test_excludes_ukrainian_resolver(self, _ips, _country):
        self.assertEqual([], generator.filter_resolvers([("ua.example", "ua.example")]))

    @patch.object(generator, "resolver_country", side_effect=["CH", "UA"])
    @patch.object(generator, "resolver_ips", return_value=["203.0.113.10", "203.0.113.11"])
    def test_excludes_resolver_if_any_endpoint_is_ukrainian(self, _ips, _country):
        self.assertEqual([], generator.filter_resolvers([("mixed.example", "mixed.example")]))

    @patch.object(generator, "resolver_country", side_effect=RuntimeError("geo lookup unavailable"))
    @patch.object(generator, "resolver_ips", return_value=["203.0.113.12"])
    def test_fails_closed_when_country_is_unknown(self, _ips, _country):
        self.assertEqual([], generator.filter_resolvers([("unknown.example", "unknown.example")]))

    @patch.object(generator, "resolver_country", return_value="CH")
    @patch.object(generator, "resolver_ips", return_value=["203.0.113.13"])
    def test_keeps_non_ukrainian_resolver(self, _ips, _country):
        self.assertEqual([("ch.example", "ch.example")],
                         generator.filter_resolvers([("ch.example", "ch.example")]))

    def test_refuses_to_run_without_any_verified_resolver(self):
        with self.assertRaises(RuntimeError):
            generator.filter_resolvers([])


if __name__ == "__main__":
    unittest.main()
