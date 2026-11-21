"""Static check that the Tier C JSC embed reference sets JIT options first."""

from __future__ import annotations

import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "ra" / "lanes" / "ios" / "jsc_embed_main.m"


class JscEmbedSourceTest(unittest.TestCase):
    def test_dlopen_and_setenv_precede_first_context_init(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        self.assertIn('setenv("JSC_useConcurrentJIT", "1", 1)', text)
        self.assertIn("dlopen(", text)
        self.assertIn("JSGlobalContextCreate", text)

        dlopen_idx = text.index("dlopen(")
        setenv_idx = text.index('setenv("JSC_useConcurrentJIT"')
        context_idx = text.index("JSGlobalContextCreate")
        init_idx = text.index("RAInitializeJavaScriptCore(void)")

        # The embed helper must dlopen JSC, set JIT options, and only then let
        # a caller create the first JSGlobalContext.
        self.assertLess(init_idx, context_idx)
        self.assertLess(setenv_idx, context_idx)
        self.assertLess(dlopen_idx, context_idx)


if __name__ == "__main__":
    unittest.main()
