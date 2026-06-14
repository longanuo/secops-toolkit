import unittest
import sys
import os
import tempfile
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secops_cli.main import print_logo, show_main_menu
from secops_cli.secopsctl import cmd_init, cmd_validate, cmd_deploy, DEMO_YAML


class TestMain(unittest.TestCase):
    def test_print_logo(self):
        print_logo()

    def test_show_main_menu(self):
        show_main_menu()


class TestSecopsctl(unittest.TestCase):
    def test_cmd_init_demo(self):
        class Args:
            demo = True

        cmd_init(Args())

    def test_cmd_init_default(self):
        class Args:
            demo = False

        cmd_init(Args())

    def test_cmd_validate_valid(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"tenant_name": "test", "environment": "dev"}, f)
            f.flush()

            class Args:
                file = f.name

            cmd_validate(Args())
            os.unlink(f.name)

    def test_cmd_validate_missing_tenant(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"environment": "dev"}, f)
            f.flush()

            class Args:
                file = f.name

            with self.assertRaises(SystemExit):
                cmd_validate(Args())
            os.unlink(f.name)

    def test_cmd_validate_file_not_found(self):
        class Args:
            file = "/nonexistent/file.yaml"

        with self.assertRaises(SystemExit):
            cmd_validate(Args())

    def test_cmd_validate_invalid_yaml(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("{{{{invalid yaml")
            f.flush()

            class Args:
                file = f.name

            with self.assertRaises(SystemExit):
                cmd_validate(Args())
            os.unlink(f.name)

    def test_cmd_deploy(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({
                "tenant_name": "test",
                "environment": "dev",
                "defense": {"firewall": {"enabled": True}},
                "offense": {"auto_scan": {"enabled": True}},
            }, f)
            f.flush()

            class Args:
                file = f.name

            cmd_deploy(Args())
            os.unlink(f.name)

    def test_demo_yaml_is_valid(self):
        config = yaml.safe_load(DEMO_YAML)
        self.assertEqual(config["tenant_name"], "demo-corp")
        self.assertIn("defense", config)
        self.assertIn("offense", config)


if __name__ == "__main__":
    unittest.main()
