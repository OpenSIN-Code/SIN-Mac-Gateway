from pathlib import Path
from types import SimpleNamespace

from sin_mac_gateway.secret_loader import read_secret_file_or_infisical


def test_reads_existing_private_file(tmp_path: Path):
    source = tmp_path / "secret"
    source.write_text("x" * 40 + "\n", encoding="utf-8")
    assert read_secret_file_or_infisical(str(source)) == "x" * 40


def test_materializes_missing_source_via_sin_infisical(monkeypatch, tmp_path: Path):
    cli = tmp_path / "sin-infisical"
    cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    cli.chmod(0o700)
    monkeypatch.setenv("SIN_INFISICAL_BIN", str(cli))
    destinations = []

    def fake_run(argv, **kwargs):
        dest = Path(argv[argv.index("--dest") + 1])
        destinations.append(dest)
        dest.write_text("y" * 64 + "\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("sin_mac_gateway.secret_loader.subprocess.run", fake_run)
    missing = tmp_path / "legacy-secret"
    assert read_secret_file_or_infisical(str(missing)) == "y" * 64
    assert destinations and not destinations[0].exists()
