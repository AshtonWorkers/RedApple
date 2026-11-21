import pytest

from ra.config.settings import ConfigError, load_config, parse_config, validate_budget_usd
from ra.errors import ArmBlocked, FormatFail, OutOfRing
from ra.fleet.ring import RingManager, RingNodeSpec
from ra.ledger import Ledger
from tests.conftest import run


def valid_config(**overrides):
    data = {"station": {"external_mount": "/tmp/redapple"}}
    for key, value in overrides.items():
        data[key] = value
    return data


def test_parse_config_defaults_and_budget_payload():
    config = parse_config(valid_config())
    assert config.station.external_mount == "/tmp/redapple"
    assert config.budget.spend_usd == 40
    assert config.budget.spend_usd_micro == 40_000_000
    assert config.model.local_only is False
    assert config.ios_lane.tier == "C"
    payload = config.budget_payload()
    assert payload["spend_usd_micro"] == 40_000_000
    assert payload["local_only"] is False


def test_parse_config_rejects_invalid_documents():
    bad_docs = [
        [],
        {"station": {}},
        {"station": {"external_mount": "relative"}},
        {"station": {"external_mount": "/tmp", "max_vm_images": 3}},
        {"station": {"external_mount": "/tmp"}, "budget": {"spend_usd": 41}},
        {"station": {"external_mount": "/tmp"}, "budget": {"spend_usd": True}},
        {"station": {"external_mount": "/tmp"}, "model": {"local_only": "yes"}},
        {"station": {"external_mount": "/tmp"}, "lane": {"ios": {"tier": "D"}}},
        {"station": {"external_mount": "/tmp", "unknown": 1}},
    ]
    for data in bad_docs:
        with pytest.raises(ConfigError):
            parse_config(data)


def test_load_config_and_validate_budget(tmp_path):
    missing = tmp_path / "missing.toml"
    with pytest.raises(ConfigError):
        load_config(missing)

    bad_toml = tmp_path / "bad.toml"
    bad_toml.write_text("[station\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(bad_toml)

    good = tmp_path / "redapple.toml"
    good.write_text(
        "[station]\n"
        'external_mount = "/tmp/redapple"\n'
        "[budget]\n"
        "spend_usd = 10\n"
        "[model]\n"
        "local_only = true\n"
        "[lane.ios]\n"
        'tier = "B"\n',
        encoding="utf-8",
    )
    config = load_config(good)
    assert config.path == good
    assert config.model.local_only is True
    assert config.ios_lane.tier == "B"
    assert validate_budget_usd(5, config) == 5_000_000
    with pytest.raises(ConfigError):
        validate_budget_usd(11, config)
    with pytest.raises(ConfigError):
        validate_budget_usd(0, config)
    with pytest.raises(ConfigError):
        validate_budget_usd(True, config)


def ring_nodes() -> list[RingNodeSpec]:
    return [
        RingNodeSpec(
            node_id=f"node-{index}",
            ipsw_sha=f"ipsw-{index}",
            build=f"build-{index}",
            xcode="xcode",
            sdk="sdk",
            webkit_commit="webkit",
            current=index < 2,
        )
        for index in range(6)
    ]


def test_ring_manager_advance_assert_and_boot_failure():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            alerts = []
            ring = RingManager(ledger, on_alert=lambda kind, detail: alerts.append((kind, detail)))
            with pytest.raises(FormatFail):
                await ring.advance(ring_nodes()[:5])
            too_few_current = [RingNodeSpec(**{**node.__dict__, "current": index < 1}) for index, node in enumerate(ring_nodes())]
            with pytest.raises(FormatFail):
                await ring.advance(too_few_current)
            duplicate = ring_nodes()
            duplicate[1] = RingNodeSpec(**{**duplicate[1].__dict__, "node_id": duplicate[0].node_id})
            with pytest.raises(FormatFail):
                await ring.advance(duplicate)

            epoch = await ring.advance(ring_nodes())
            assert epoch == 1
            assert ring.current_epoch() == 1
            row = ring.assert_in_ring("build-0", xcode="xcode")
            assert row["state"] == "current"
            with pytest.raises(OutOfRing):
                ring.assert_in_ring("build-0", xcode="wrong")

            assert await ring.record_boot_failure("node-0") == "current"
            assert await ring.record_boot_failure("node-0") == "bad"
            assert alerts == [("ring_node_bad", "node-0")]
            assert ledger.ring_node("node-0")["state"] == "bad"
            with pytest.raises(OutOfRing):
                ring.assert_in_ring("build-0")
            assert ring.assert_in_ring("build-1")["state"] == "current"

            assert ring.assert_corpus_epoch(1) == "ring_1"
            with pytest.raises(ArmBlocked):
                ring.assert_corpus_epoch(0)
            assert ring.assert_corpus_epoch(0, cross_epoch_opt_in=True) == "ring_0"
        finally:
            await ledger.close()

    run(body())


def test_ring_manager_unknown_node_and_corpus_key():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            ring = RingManager(ledger)
            assert ring.current_epoch() == 0
            assert ring.corpus_key(3) == "ring_3"
            with pytest.raises(FormatFail):
                await ring.record_boot_failure("missing")
            with pytest.raises(ArmBlocked):
                ring.assert_corpus_epoch(1)
        finally:
            await ledger.close()

    run(body())
