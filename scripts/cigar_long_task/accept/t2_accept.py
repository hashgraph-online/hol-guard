import pytest
import click
from click.testing import CliRunner

def test_option_deprecated_bool():
    @click.command()
    @click.option("--old", deprecated=True)
    def cli(old):
        click.echo(f"val={old}")
    r = CliRunner().invoke(cli, ["--old", "x"])
    assert r.exit_code == 0, r.output
    assert "val=x" in r.output and "deprecated" in r.output.lower()
    r = CliRunner().invoke(cli, [])
    assert r.exit_code == 0 and "deprecated" not in r.output.lower()
    r = CliRunner().invoke(cli, ["--help"])
    assert "DEPRECATED" in r.output

def test_option_deprecated_message():
    @click.command()
    @click.option("--old", deprecated="use --new instead")
    def cli(old):
        click.echo(f"val={old}")
    r = CliRunner().invoke(cli, ["--old", "x"])
    assert r.exit_code == 0 and "use --new instead" in r.output
    r = CliRunner().invoke(cli, ["--help"])
    assert "DEPRECATED" in r.output and "use --new instead" in r.output

def test_argument_deprecated():
    @click.command()
    @click.argument("x", required=False, deprecated=True)
    def cli(x):
        click.echo(f"val={x}")
    r = CliRunner().invoke(cli, ["v"])
    assert r.exit_code == 0 and "val=v" in r.output and "deprecated" in r.output.lower()

def test_required_rejected():
    with pytest.raises(ValueError):
        click.Option(["--a"], required=True, deprecated=True)
