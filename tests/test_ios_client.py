"""LibimobiledeviceIosAttachClient tests with scripted command results."""

from __future__ import annotations

import plistlib
import unittest

from ra.lanes.base import LaneError, LaneErrorCode, Thermal
from ra.lanes.commands import CommandResult
from ra.lanes.ios.client import IosDeviceInfo, LibimobiledeviceIosAttachClient


def res(argv, *, rc: int = 0, out: str = "", err: str = "") -> CommandResult:
    return CommandResult(tuple(argv), rc, out, err, 1)


class ScriptedRunner:
    def __init__(self, responses: dict[tuple[str, ...], CommandResult] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[str, ...]] = []
        self.raise_oserror_for: set[str] = set()

    async def run(self, argv, **kwargs) -> CommandResult:
        argv = tuple(str(part) for part in argv)
        self.calls.append(argv)
        if argv and argv[0] in self.raise_oserror_for:
            raise OSError("missing tool")
        return self.responses.get(argv, res(argv))


def plist_bytes(**extra) -> str:
    data = {
        "Trusted": True,
        "DeveloperModeStatus": "enabled",
        "BuildVersion": "22A3354",
        "ProductType": "iPhone15,2",
        "ProductVersion": "18.0",
        **extra,
    }
    return plistlib.dumps(data, fmt=plistlib.FMT_XML).decode()


class LibimobiledeviceIosAttachClientTest(unittest.IsolatedAsyncioTestCase):
    async def test_identify_success_and_failures(self) -> None:
        runner = ScriptedRunner(
            {
                ("idevice_id", "-l"): res(["idevice_id"], out="udid\nother\n"),
                ("ideviceinfo", "-u", "udid", "-x"): res(
                    ["ideviceinfo"], out=plist_bytes(bundle_id="com.example", harness_app="/tmp/app")
                ),
            }
        )
        client = LibimobiledeviceIosAttachClient(runner=runner)
        info = await client.identify("udid")
        self.assertEqual(info.udid, "udid")
        self.assertEqual(info.build, "22A3354")
        self.assertEqual(info.product_type, "iPhone15,2")
        self.assertIs(info.trusted, True)
        self.assertIs(info.developer_mode, True)
        self.assertEqual(info.raw["bundle_id"], "com.example")

        missing = ScriptedRunner({("idevice_id", "-l"): res(["idevice_id"], out="other\n")})
        with self.assertRaises(LaneError) as cm:
            await LibimobiledeviceIosAttachClient(runner=missing).identify("udid")
        self.assertIs(cm.exception.code, LaneErrorCode.DEVICE_LOST)

        bad_info = ScriptedRunner(
            {
                ("idevice_id", "-l"): res(["idevice_id"], out="udid\n"),
                ("ideviceinfo", "-u", "udid", "-x"): res(["ideviceinfo"], rc=1),
            }
        )
        with self.assertRaises(LaneError):
            await LibimobiledeviceIosAttachClient(runner=bad_info).identify("udid")

        invalid = ScriptedRunner(
            {
                ("idevice_id", "-l"): res(["idevice_id"], out="udid\n"),
                ("ideviceinfo", "-u", "udid", "-x"): res(["ideviceinfo"], out="not a plist"),
            }
        )
        with self.assertRaises(LaneError):
            await LibimobiledeviceIosAttachClient(runner=invalid).identify("udid")

    async def test_check_trust_dev_mode(self) -> None:
        info = IosDeviceInfo(udid="udid")
        runner = ScriptedRunner(
            {
                ("idevicepair", "validate", "-u", "udid"): res(["idevicepair"]),
                ("ideviceinfo", "-u", "udid", "-k", "DeveloperModeStatus"): res(
                    ["ideviceinfo"], out="enabled\n"
                ),
            }
        )
        checked = await LibimobiledeviceIosAttachClient(runner=runner).check_trust_dev_mode(info)
        self.assertIs(checked.trusted, True)
        self.assertIs(checked.developer_mode, True)

        runner = ScriptedRunner(
            {
                ("idevicepair", "validate", "-u", "udid"): res(["idevicepair"], rc=1),
                ("ideviceinfo", "-u", "udid", "-k", "DeveloperModeStatus"): res(
                    ["ideviceinfo"], out="disabled\n"
                ),
            }
        )
        checked = await LibimobiledeviceIosAttachClient(runner=runner).check_trust_dev_mode(info)
        self.assertIs(checked.trusted, False)
        self.assertIs(checked.developer_mode, False)

    async def test_dev_mode_status_parsing(self) -> None:
        cases = [
            ("enabled", True),
            ("Enabled", True),
            ("Developer Mode is enabled", True),
            ("1", True),
            ("true", True),
            ("disabled", False),
            ("Disabled", False),
            ("Developer Mode is disabled", False),
            ("0", False),
            ("false", False),
            ("not enabled", False),
            ("Developer Mode is not enabled", False),
            ("isn't enabled", False),
            ("cannot be enabled", False),
            ("unknown", None),
            ("maybe enabled", None),
            ("enabled disabled", None),
            ("", None),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                runner = ScriptedRunner(
                    {
                        ("idevicepair", "validate", "-u", "udid"): res(["idevicepair"]),
                        ("ideviceinfo", "-u", "udid", "-k", "DeveloperModeStatus"): res(
                            ["ideviceinfo"], out=f"{raw}\n"
                        ),
                    }
                )
                checked = await LibimobiledeviceIosAttachClient(runner=runner).check_trust_dev_mode(
                    IosDeviceInfo(udid="udid")
                )
                self.assertIs(checked.developer_mode, expected)

        runner = ScriptedRunner(
            {
                ("idevicepair", "validate", "-u", "udid"): res(["idevicepair"]),
                ("ideviceinfo", "-u", "udid", "-k", "DeveloperModeStatus"): res(
                    ["ideviceinfo"], rc=1
                ),
            }
        )
        checked = await LibimobiledeviceIosAttachClient(runner=runner).check_trust_dev_mode(
            IosDeviceInfo(udid="udid")
        )
        self.assertIs(checked.developer_mode, None)

    async def test_mount_ddi_success_and_failure(self) -> None:
        info = IosDeviceInfo(udid="udid")
        runner = ScriptedRunner(
            {
                ("pymobiledevice3", "mounter", "auto-mount", "--udid", "udid"): res(
                    ["pymobiledevice3"], out="mounted\n"
                )
            }
        )
        mounted = await LibimobiledeviceIosAttachClient(runner=runner).mount_ddi(info)
        self.assertTrue(mounted.ddi_mounted)
        self.assertIn("mounted", mounted.raw["ddi_mount"])

        runner = ScriptedRunner(
            {
                ("pymobiledevice3", "mounter", "auto-mount", "--udid", "udid"): res(
                    ["pymobiledevice3"], rc=1, err="no ddi"
                )
            }
        )
        failed = await LibimobiledeviceIosAttachClient(runner=runner).mount_ddi(info)
        self.assertFalse(failed.ddi_mounted)

    async def test_sign_install_paths(self) -> None:
        info = IosDeviceInfo(udid="udid", raw={"bundle_id": "com.example"})
        unconfigured = LibimobiledeviceIosAttachClient(runner=ScriptedRunner())
        result = await unconfigured.sign_install(info)
        self.assertFalse(result.ok)
        self.assertIs(result.error_code, LaneErrorCode.NOT_PROVISIONED)

        runner = ScriptedRunner({("install", "udid", "com.example"): res(["install"], out="ok")})
        client = LibimobiledeviceIosAttachClient(
            runner=runner, install_command=["install", "{udid}", "{bundle_id}"]
        )
        result = await client.sign_install(info)
        self.assertTrue(result.ok)
        self.assertIsNotNone(result.signing_expires_ms)
        self.assertIn(("install", "udid", "com.example"), runner.calls)

        expired = ScriptedRunner(
            {("install", "udid"): res(["install"], rc=1, err="signing certificate expired")}
        )
        client = LibimobiledeviceIosAttachClient(runner=expired, install_command=["install", "{udid}"])
        result = await client.sign_install(info)
        self.assertFalse(result.ok)
        self.assertIs(result.error_code, LaneErrorCode.SIGNING_EXPIRED)

        failed = ScriptedRunner({("install", "udid"): res(["install"], rc=1, err="boom")})
        client = LibimobiledeviceIosAttachClient(runner=failed, install_command=["install", "{udid}"])
        result = await client.sign_install(info)
        self.assertIs(result.error_code, LaneErrorCode.INSTALL_FAILED)

        missing_tool = ScriptedRunner()
        missing_tool.raise_oserror_for.add("install")
        client = LibimobiledeviceIosAttachClient(runner=missing_tool, install_command=["install", "{udid}"])
        with self.assertRaises(LaneError) as cm:
            await client.sign_install(info)
        self.assertIs(cm.exception.code, LaneErrorCode.NOT_PROVISIONED)

    async def test_probe_collect_thermal_reset_renew_release(self) -> None:
        info = IosDeviceInfo(udid="udid", raw={"harness_app": "/tmp/app"})
        assert (await LibimobiledeviceIosAttachClient(runner=ScriptedRunner()).probe_capabilities(info)) == frozenset()

        runner = ScriptedRunner(
            {
                ("probe", "udid"): res(["probe"], out="capability: javascriptcore\nCAP: dlopen\nnoise\n"),
                ("crashes", "udid"): res(
                    ["crashes"], out="/a.ips\nnoise\n/b.crash\n/c.panic\n/other.txt\n"
                ),
                ("reset", "udid"): res(["reset"]),
                ("renew", "udid"): res(["renew"], out="ok"),
            }
        )
        client = LibimobiledeviceIosAttachClient(
            runner=runner,
            probe_command=["probe", "{udid}"],
            crash_command=["crashes", "{udid}"],
            reset_command=["reset", "{udid}"],
            sign_command=["renew", "{udid}"],
            thermal_reader=lambda: "critical",
        )
        self.assertEqual(await client.probe_capabilities(info), frozenset({"javascriptcore", "dlopen"}))
        crashes = await client.collect_crashes(info)
        self.assertEqual(len(crashes), 3)
        self.assertEqual({ref.path for ref in crashes}, {"/a.ips", "/b.crash", "/c.panic"})
        self.assertIs(await client.read_thermal(info), Thermal.CRITICAL)
        await client.reset_device(info)
        renewed = await client.renew_signing(info)
        self.assertTrue(renewed.ok)
        self.assertIsNotNone(renewed.signing_expires_ms)
        self.assertIsNone(await client.release_udid(info, "test"))

    async def test_failure_paths(self) -> None:
        info = IosDeviceInfo(udid="udid")
        runner = ScriptedRunner(
            {
                ("crashes", "udid"): res(["crashes"], rc=1, err="lost"),
                ("reset", "udid"): res(["reset"], rc=1, err="reset failed"),
                ("renew", "udid"): res(["renew"], rc=1, err="renew failed"),
                ("probe", "udid"): res(["probe"], rc=1),
            }
        )
        client = LibimobiledeviceIosAttachClient(
            runner=runner,
            crash_command=["crashes", "{udid}"],
            reset_command=["reset", "{udid}"],
            sign_command=["renew", "{udid}"],
            probe_command=["probe", "{udid}"],
        )
        with self.assertRaises(LaneError) as cm:
            await client.collect_crashes(info)
        self.assertIs(cm.exception.code, LaneErrorCode.DEVICE_LOST)
        with self.assertRaises(LaneError):
            await client.reset_device(info)
        renewed = await client.renew_signing(info)
        self.assertFalse(renewed.ok)
        self.assertIs(renewed.error_code, LaneErrorCode.SIGNING_EXPIRED)
        self.assertEqual(await client.probe_capabilities(info), frozenset())

        unconfigured = LibimobiledeviceIosAttachClient(runner=ScriptedRunner())
        renew = await unconfigured.renew_signing(info)
        self.assertFalse(renew.ok)
        self.assertIs(renew.error_code, LaneErrorCode.SIGNING_EXPIRED)


if __name__ == "__main__":
    unittest.main()
