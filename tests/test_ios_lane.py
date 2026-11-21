"""Unit tests for the iOS Tier C lane automaton (device boundary faked)."""

from __future__ import annotations

import time
import unittest
from dataclasses import replace

from ra.lanes.base import (
    CrashRef,
    DeviceProfile,
    FeedResult,
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
        return replace(info, trusted=self.trusted, developer_mode=self.developer_mode)

    async def mount_ddi(self, info: IosDeviceInfo) -> IosDeviceInfo:
        self.calls.append("mount_ddi")
        return replace(info, ddi_mounted=self.ddi_mounted)

    async def sign_install(self, info: IosDeviceInfo) -> IosInstallResult:
        self.calls.append("sign_install")
        if not self.install_ok:
            return IosInstallResult(
                ok=False,
                error_code=self.install_error or LaneErrorCode.INSTALL_FAILED,
                message="install failed",
            )
        return IosInstallResult(ok=True, signing_expires_ms=self.signing_expires_ms)

    async def probe_capabilities(self, info: IosDeviceInfo) -> frozenset[str]:
        self.calls.append("probe_capabilities")
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
        if not self.renew_ok:
            return IosInstallResult(ok=False, error_code=LaneErrorCode.SIGNING_EXPIRED, message="renew failed")
        return IosInstallResult(
            ok=True,
            signing_expires_ms=int(time.time() * 1000) + 7 * 24 * 60 * 60 * 1000,
        )

    async def release_udid(self, info: IosDeviceInfo, reason: str) -> None:
        self.calls.append("release_udid")
        self.release_reasons.append(reason)


class FakeJscTransport:
    def __init__(self, result: FeedResult | str = FeedResult.ACCEPTED) -> None:
        self.result = result
        self.opened: list[str] = []
        self.closed: list[str] = []
        self.evals: list[bytes] = []

    async def open(self, handle) -> None:
        self.opened.append(handle.handle_id)

    async def eval(self, handle, data: bytes) -> FeedResult | str:
        self.evals.append(data)
        return self.result

    async def close(self, handle) -> None:
        self.closed.append(handle.handle_id)


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
        self.assertIs(result, FeedResult.ACCEPTED)
        self.assertEqual(transport.evals, [b"print(1)"])

        collected = await lane.collect_crashes(handle)
        self.assertEqual(collected, crashes)
        self.assertEqual(collected[0].context, "app")

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

    async def test_thermal_reading_flows_through_lane(self) -> None:
        client = FakeAttachClient(thermal=Thermal.SERIOUS)
        lane, _, _ = self.make_lane(client)
        await lane.provision(self.make_profile())
        self.assertIs(await lane.thermal(), Thermal.SERIOUS)
        self.assertTrue(lane.paused)


if __name__ == "__main__":
    unittest.main()
