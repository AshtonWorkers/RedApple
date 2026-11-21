"""Unit tests for the iOS Tier C lane automaton (device boundary faked)."""

from __future__ import annotations

import time
import unittest
from dataclasses import replace

from ra.lanes.base import (
    CrashRef,
    DeviceProfile,
    FeedResult,
    FeedStatus,
    HarnessRef,
    HumanCard,
    LaneError,
    LaneErrorCode,
    ProvisionState,
    Thermal,
    Tier,
)
from ra.lanes.ios.client import IosDeviceInfo, IosInstallResult
from ra.lanes.ios.lane import IOSTierCLane


class FakeRing:
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.calls: list[tuple[str, str | None]] = []

    def allows(self, ring_node: str, build: str | None) -> bool:
        self.calls.append((ring_node, build))
        return self.allowed


class FakeAttachClient:
    def __init__(
        self,
        *,
        identify_error: LaneError | None = None,
        trusted: bool | None = True,
        developer_mode: bool | None = True,
        ddi_mounted: bool = True,
        install_ok: bool = True,
        install_error: LaneErrorCode | None = None,
        sign_install_error: LaneError | None = None,
        renew_error: LaneError | None = None,
        check_error: LaneError | None = None,
        mount_error: LaneError | None = None,
        probe_error: LaneError | None = None,
        release_error: LaneError | None = None,
        renew_no_expiry: bool = False,
        capabilities=frozenset({"javascriptcore"}),
        signing_expires_ms: int | None = None,
        signing_renewals: int = 0,
        renew_ok: bool = True,
        crashes: list[CrashRef] | None = None,
        thermal: Thermal = Thermal.NOMINAL,
    ) -> None:
        self.identify_error = identify_error
        self.trusted = trusted
        self.developer_mode = developer_mode
        self.ddi_mounted = ddi_mounted
        self.install_ok = install_ok
        self.install_error = install_error
        self.sign_install_error = sign_install_error
        self.renew_error = renew_error
        self.check_error = check_error
        self.mount_error = mount_error
        self.probe_error = probe_error
        self.release_error = release_error
        self.renew_no_expiry = renew_no_expiry
        self.capabilities = frozenset(capabilities)
        self.signing_expires_ms = signing_expires_ms
        self.signing_renewals = signing_renewals
        self.renew_ok = renew_ok
        self.crashes = crashes if crashes is not None else []
        self.thermal = thermal
        self.calls: list[str] = []
        self.renew_calls = 0
        self.release_reasons: list[str] = []

    async def identify(self, udid: str) -> IosDeviceInfo:
        self.calls.append("identify")
        if self.identify_error is not None:
            raise self.identify_error
        return IosDeviceInfo(
            udid=udid,
            build="22A3354",
            product_type="iPhone15,2",
            product_version="18.0",
            trusted=self.trusted,
            developer_mode=self.developer_mode,
            ddi_mounted=False,
            signing_expires_ms=self.signing_expires_ms,
            signing_renewals=self.signing_renewals,
            ring_node="node-ios",
        )

    async def check_trust_dev_mode(self, info: IosDeviceInfo) -> IosDeviceInfo:
        self.calls.append("check_trust_dev_mode")
        if self.check_error is not None:
            raise self.check_error
        return replace(info, trusted=self.trusted, developer_mode=self.developer_mode)

    async def mount_ddi(self, info: IosDeviceInfo) -> IosDeviceInfo:
        self.calls.append("mount_ddi")
        if self.mount_error is not None:
            raise self.mount_error
        return replace(info, ddi_mounted=self.ddi_mounted)

    async def sign_install(self, info: IosDeviceInfo) -> IosInstallResult:
        self.calls.append("sign_install")
        if self.sign_install_error is not None:
            raise self.sign_install_error
        if not self.install_ok:
            return IosInstallResult(
                ok=False,
                error_code=self.install_error or LaneErrorCode.INSTALL_FAILED,
                message="install failed",
            )
        return IosInstallResult(ok=True, signing_expires_ms=self.signing_expires_ms)

    async def probe_capabilities(self, info: IosDeviceInfo) -> frozenset[str]:
        self.calls.append("probe_capabilities")
        if self.probe_error is not None:
            raise self.probe_error
        return self.capabilities

    async def collect_crashes(self, info: IosDeviceInfo) -> list[CrashRef]:
        self.calls.append("collect_crashes")
        return list(self.crashes)

    async def read_thermal(self, info: IosDeviceInfo) -> Thermal:
        return self.thermal

    async def reset_device(self, info: IosDeviceInfo) -> None:
        self.calls.append("reset_device")

    async def renew_signing(self, info: IosDeviceInfo) -> IosInstallResult:
        self.calls.append("renew_signing")
        self.renew_calls += 1
        if self.renew_error is not None:
            raise self.renew_error
        if not self.renew_ok:
            return IosInstallResult(ok=False, error_code=LaneErrorCode.SIGNING_EXPIRED, message="renew failed")
        if self.renew_no_expiry:
            return IosInstallResult(ok=True, signing_expires_ms=None)
        return IosInstallResult(
            ok=True,
            signing_expires_ms=int(time.time() * 1000) + 7 * 24 * 60 * 60 * 1000,
        )

    async def release_udid(self, info: IosDeviceInfo, reason: str) -> None:
        self.calls.append("release_udid")
        self.release_reasons.append(reason)
        if self.release_error is not None:
            raise self.release_error


class FakeJscTransport:
    def __init__(
        self,
        result: FeedResult | FeedStatus | str = FeedStatus.ACCEPTED,
        *,
        close_error: LaneError | None = None,
    ) -> None:
        self.result = result
        self.close_error = close_error
        self.opened: list[str] = []
        self.closed: list[str] = []
        self.evals: list[bytes] = []

    async def open(self, handle) -> None:
        self.opened.append(handle.handle_id)

    async def eval(self, handle, data: bytes) -> FeedResult | FeedStatus | str:
        self.evals.append(data)
        return self.result

    async def close(self, handle) -> None:
        self.closed.append(handle.handle_id)
        if self.close_error is not None:
            raise self.close_error


class IOSTierCLaneTest(unittest.IsolatedAsyncioTestCase):
    def make_profile(self) -> DeviceProfile:
        return DeviceProfile(
            udid="00008101-TEST", ring_node="node-ios", state="attached", tier=Tier.C, build="22A3354"
        )

    def make_lane(self, client: FakeAttachClient, **kwargs) -> tuple[IOSTierCLane, list[HumanCard], FakeJscTransport]:
        cards: list[HumanCard] = []
        transport = FakeJscTransport()
        lane = IOSTierCLane(
            attach_client=client,
            jsc_transport=transport,
            card_sink=cards.append,
            **kwargs,
        )
        return lane, cards, transport

    async def test_ready_provision_follows_attach_automaton_order(self) -> None:
        client = FakeAttachClient()
        lane, cards, _ = self.make_lane(client)
        profile = self.make_profile()
        result = await lane.provision(profile)

        self.assertIs(result.state, ProvisionState.READY)
        self.assertIs(result.tier, Tier.C)
        self.assertEqual(profile.state, "ready")
        self.assertIs(profile.tier, Tier.C)
        self.assertEqual(cards, [])
        self.assertEqual(
            client.calls,
            ["identify", "check_trust_dev_mode", "mount_ddi", "sign_install", "probe_capabilities"],
        )
        tier, caps = lane.capability()
        self.assertIs(tier, Tier.C)
        self.assertIn("javascriptcore", caps)

    async def test_provisioning_gaps_emit_one_card_and_park_needs_hand(self) -> None:
        scenarios = [
            (FakeAttachClient(identify_error=LaneError(LaneErrorCode.DEVICE_LOST, "gone")), "connect_ios_device"),
            (FakeAttachClient(trusted=False), "trust_enable_developer_mode"),
            (FakeAttachClient(developer_mode=False), "trust_enable_developer_mode"),
            (FakeAttachClient(ddi_mounted=False), "mount_personalized_ddi"),
            (
                FakeAttachClient(install_ok=False, install_error=LaneErrorCode.SIGNING_EXPIRED),
                "renew_ios_signing",
            ),
            (FakeAttachClient(capabilities=frozenset()), "probe_ios_capability"),
        ]
        for client, action in scenarios:
            with self.subTest(action=action):
                lane, cards, _ = self.make_lane(client)
                profile = self.make_profile()
                result = await lane.provision(profile)
                self.assertIs(result.state, ProvisionState.NEEDS_HAND)
                self.assertEqual(profile.state, "needs_hand")
                self.assertEqual(len(cards), 1)
                self.assertIs(result.human_card, cards[0])
                self.assertEqual(cards[0].action, action)
                self.assertEqual(cards[0].device_udid, profile.udid)

    async def test_unknown_trust_or_dev_mode_is_not_ready(self) -> None:
        scenarios = [
            {"trusted": None},
            {"developer_mode": None},
            {"trusted": None, "developer_mode": None},
        ]
        for kwargs in scenarios:
            with self.subTest(kwargs=kwargs):
                client = FakeAttachClient(**kwargs)
                lane, cards, _ = self.make_lane(client)
                profile = self.make_profile()
                result = await lane.provision(profile)

                self.assertIs(result.state, ProvisionState.NEEDS_HAND)
                self.assertEqual(profile.state, "needs_hand")
                self.assertEqual(len(cards), 1)
                self.assertEqual(cards[0].action, "trust_enable_developer_mode")
                self.assertEqual(client.calls, ["identify", "check_trust_dev_mode"])

    async def test_sign_install_exception_parks_needs_hand(self) -> None:
        client = FakeAttachClient(
            sign_install_error=LaneError(LaneErrorCode.NOT_PROVISIONED, "missing sign tool")
        )
        lane, cards, _ = self.make_lane(client)
        profile = self.make_profile()
        result = await lane.provision(profile)
        self.assertIs(result.state, ProvisionState.NEEDS_HAND)
        self.assertEqual(profile.state, "needs_hand")
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0].action, "renew_ios_signing")
        self.assertEqual(cards[0].blocker, LaneErrorCode.NOT_PROVISIONED.value.lower())

    async def test_ring_gate_blocks_before_identify(self) -> None:
        client = FakeAttachClient()
        cards: list[HumanCard] = []
        lane = IOSTierCLane(attach_client=client, card_sink=cards.append, ring=FakeRing(allowed=False))
        profile = self.make_profile()
        with self.assertRaises(LaneError) as cm:
            await lane.provision(profile)
        self.assertIs(cm.exception.code, LaneErrorCode.OUT_OF_RING)
        self.assertEqual(client.calls, [])
        self.assertEqual(cards, [])

    async def test_launch_feed_collect_reset_with_jsc_transport(self) -> None:
        crashes = [CrashRef(id="crash_ios_1", kind="ios_crash", path="/private/var/mobile/x.ips")]
        client = FakeAttachClient(crashes=crashes)
        lane, _, transport = self.make_lane(client)
        await lane.provision(self.make_profile())

        handle = await lane.launch("javascriptcore", HarnessRef(name="jsc", argv=["jsc-harness"]))
        self.assertEqual(transport.opened, [handle.handle_id])

        result = await lane.feed(handle, b"print(1)")
        self.assertIs(result.status, FeedStatus.ACCEPTED)
        self.assertEqual(transport.evals, [b"print(1)"])

        collected = await lane.collect_crashes(handle)
        self.assertEqual(len(collected), 1)
        self.assertEqual(collected[0].id, "crash_ios_1")
        self.assertEqual(collected[0].kind, "ios_crash")
        self.assertEqual(collected[0].path, "/private/var/mobile/x.ips")
        self.assertEqual(collected[0].context, "app")
        self.assertEqual(collected[0].handle_id, handle.handle_id)

        await lane.reset(handle)
        self.assertEqual(transport.closed, [handle.handle_id])
        self.assertIn("reset_device", client.calls)

        with self.assertRaises(LaneError) as cm:
            await lane.collect_crashes(handle)
        self.assertIs(cm.exception.code, LaneErrorCode.FORMAT_FAIL)

    async def test_launch_without_jsc_transport_is_device_gated(self) -> None:
        client = FakeAttachClient()
        cards: list[HumanCard] = []
        lane = IOSTierCLane(attach_client=client, card_sink=cards.append)
        await lane.provision(self.make_profile())
        with self.assertRaises(LaneError) as cm:
            await lane.launch("javascriptcore", HarnessRef(name="jsc"))
        self.assertIs(cm.exception.code, LaneErrorCode.NOT_PROVISIONED)
        self.assertTrue(cm.exception.details.get("device_gated"))

    async def test_signing_renewal_runs_on_launch_when_near_expiry(self) -> None:
        now_ms = int(time.time() * 1000)
        client = FakeAttachClient(signing_expires_ms=now_ms + 1000)
        lane, _, transport = self.make_lane(client)
        await lane.provision(self.make_profile())
        handle = await lane.launch("javascriptcore", HarnessRef(name="jsc"))
        self.assertEqual(client.renew_calls, 1)
        self.assertIn("renew_signing", client.calls)
        self.assertEqual(transport.opened, [handle.handle_id])

    async def test_signing_renewal_budget_exhausted(self) -> None:
        now_ms = int(time.time() * 1000)
        client = FakeAttachClient(signing_expires_ms=now_ms + 1000, signing_renewals=3)
        lane, _, transport = self.make_lane(client, max_signing_renewals=3)
        await lane.provision(self.make_profile())
        with self.assertRaises(LaneError) as cm:
            await lane.launch("javascriptcore", HarnessRef(name="jsc"))
        self.assertIs(cm.exception.code, LaneErrorCode.SIGNING_EXPIRED)
        self.assertEqual(client.renew_calls, 0)
        self.assertEqual(transport.opened, [])

    async def test_renew_signing_exception_parks_device(self) -> None:
        now_ms = int(time.time() * 1000)
        client = FakeAttachClient(
            signing_expires_ms=now_ms + 1000,
            renew_error=LaneError(LaneErrorCode.NOT_PROVISIONED, "missing renew command"),
        )
        lane, cards, transport = self.make_lane(client)
        profile = self.make_profile()
        await lane.provision(profile)
        with self.assertRaises(LaneError) as cm:
            await lane.launch("javascriptcore", HarnessRef(name="jsc"))
        self.assertIs(cm.exception.code, LaneErrorCode.NOT_PROVISIONED)
        self.assertEqual(profile.state, "needs_hand")
        self.assertEqual(cards[-1].action, "renew_ios_signing")
        self.assertEqual(transport.opened, [])

    async def test_thermal_reading_flows_through_lane(self) -> None:
        client = FakeAttachClient(thermal=Thermal.SERIOUS)
        lane, _, _ = self.make_lane(client)
        await lane.provision(self.make_profile())
        self.assertIs(await lane.thermal(), Thermal.SERIOUS)
        self.assertTrue(lane.paused)

    async def test_attach_tool_exceptions_park_repair_ios_attach_tools(self) -> None:
        scenarios = [
            (FakeAttachClient(check_error=LaneError(LaneErrorCode.DEVICE_LOST, "pair failed")), "trust/dev-mode check"),
            (FakeAttachClient(mount_error=LaneError(LaneErrorCode.NOT_PROVISIONED, "mounter missing")), "DDI mount"),
            (FakeAttachClient(probe_error=LaneError(LaneErrorCode.DEVICE_LOST, "probe failed")), "capability probe"),
        ]
        for client, step in scenarios:
            with self.subTest(step=step):
                lane, cards, _ = self.make_lane(client)
                profile = self.make_profile()
                result = await lane.provision(profile)
                self.assertIs(result.state, ProvisionState.NEEDS_HAND)
                self.assertEqual(profile.state, "needs_hand")
                self.assertEqual(cards[0].action, "repair_ios_attach_tools")
                self.assertEqual(cards[0].metadata["step"], step)

    async def test_feed_after_transport_removed_requires_transport(self) -> None:
        client = FakeAttachClient()
        lane, _, transport = self.make_lane(client)
        await lane.provision(self.make_profile())
        handle = await lane.launch("javascriptcore", HarnessRef(name="jsc"))
        lane._jsc_transport = None
        with self.assertRaises(LaneError) as cm:
            await lane.feed(handle, b"x")
        self.assertIs(cm.exception.code, LaneErrorCode.NOT_PROVISIONED)
        self.assertEqual(transport.evals, [])

    async def test_teardown_closes_handles_and_suppresses_errors(self) -> None:
        client = FakeAttachClient(
            release_error=LaneError(LaneErrorCode.DEVICE_LOST, "release failed")
        )
        transport = FakeJscTransport(close_error=LaneError(LaneErrorCode.DEVICE_LOST, "close failed"))
        cards: list[HumanCard] = []
        lane = IOSTierCLane(attach_client=client, jsc_transport=transport, card_sink=cards.append)
        await lane.provision(self.make_profile())
        handle = await lane.launch("javascriptcore", HarnessRef(name="jsc"))
        await lane.teardown()
        self.assertEqual(transport.closed, [handle.handle_id])
        self.assertEqual(client.release_reasons, ["teardown"])

    async def test_thermal_before_provision_is_nominal(self) -> None:
        lane, _, _ = self.make_lane(FakeAttachClient())
        self.assertIs(await lane.thermal(), Thermal.NOMINAL)

    async def test_signing_renewal_failure_result_parks_device(self) -> None:
        now_ms = int(time.time() * 1000)
        client = FakeAttachClient(signing_expires_ms=now_ms + 1000, renew_ok=False)
        lane, cards, transport = self.make_lane(client)
        profile = self.make_profile()
        await lane.provision(profile)
        with self.assertRaises(LaneError) as cm:
            await lane.launch("javascriptcore", HarnessRef(name="jsc"))
        self.assertIs(cm.exception.code, LaneErrorCode.SIGNING_EXPIRED)
        self.assertEqual(profile.state, "needs_hand")
        self.assertEqual(cards[-1].action, "renew_ios_signing")
        self.assertEqual(transport.opened, [])

    async def test_signing_renewal_without_expiry_uses_fallback(self) -> None:
        now_ms = int(time.time() * 1000)
        client = FakeAttachClient(signing_expires_ms=now_ms + 1000, renew_no_expiry=True)
        lane, _, transport = self.make_lane(client)
        await lane.provision(self.make_profile())
        handle = await lane.launch("javascriptcore", HarnessRef(name="jsc"))
        self.assertEqual(client.renew_calls, 1)
        self.assertEqual(transport.opened, [handle.handle_id])


if __name__ == "__main__":
    unittest.main()
