import pytest

from ra.cli.main import COMMANDS, layout_check, main, worker_formula
from ra.config import ConfigError, load_config, validate_budget_usd


def test_RA_CFG_001_defaults_and_unknown_keys(tmp_path):
    path = tmp_path / "redapple.toml"
    path.write_text(
        '[station]\nexternal_mount = "/tmp"\n[budget]\nspend_usd = 40\n'
        '[model]\nprimary = "deepseek-v4.1-flash"\n',
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.model.primary == "deepseek-v4.1-flash"
    assert config.station.max_vm_images == 2
    assert validate_budget_usd(40, config) == 40_000_000
    with pytest.raises(ConfigError):
        validate_budget_usd(41, config)
    bad = tmp_path / "bad.toml"
    bad.write_text("[unknown]\nx = 1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(bad)


def test_RA_CLI_001_exact_command_vocabulary():
    assert COMMANDS == ("run", "attach", "replay", "golden", "doctor", "retain")
    assert worker_formula(ram_gb=32, cores=8)["workers"] == 6
    assert layout_check()[0:0] == []


def test_RA_CLI_001_golden_cli(tmp_path, capsys):
    assert main(["golden", "--type", "bug_class"]) == 0
    out = capsys.readouterr().out
    assert '"passed": true' in out


def test_RA_CLI_001_doctor_cli(tmp_path, capsys):
    assert main(["doctor", "--db", str(tmp_path / "ledger.sqlite")]) == 0
    assert '"layout"' in capsys.readouterr().out
