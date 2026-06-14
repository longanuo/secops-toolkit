"""logger 模块单元测试"""
import unittest
from secops_core.logger import get_logger


class TestLogger(unittest.TestCase):

    def test_get_logger_returns_logger(self):
        logger = get_logger("test_module")
        self.assertIsNotNone(logger)

    def test_logger_has_name(self):
        logger = get_logger("my_module")
        self.assertEqual(logger.name, "secops.my_module")

    def test_logger_has_handlers(self):
        logger = get_logger("test_handlers")
        self.assertGreater(len(logger.handlers), 0)

    def test_logger_is_not_none(self):
        logger = get_logger("test")
        self.assertTrue(hasattr(logger, "info"))
        self.assertTrue(hasattr(logger, "error"))
        self.assertTrue(hasattr(logger, "warning"))


if __name__ == "__main__":
    unittest.main()
