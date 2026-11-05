import enum
import click
from click.testing import CliRunner

class Color(enum.Enum):
    RED = "r"
    GREEN = "g"

def make(**kw):
    @click.command()
    @click.option("--c", type=click.Choice(Color, **kw))
    def cli(c):
        click.echo(repr(c))
    return cli

def test_enum_member_by_name():
    r = CliRunner().invoke(make(), ["--c", "RED"])
    assert r.exit_code == 0, r.output
    assert "Color.RED" in r.output

def test_enum_help_and_error():
    r = CliRunner().invoke(make(), ["--help"])
    assert "RED" in r.output and "GREEN" in r.output
    r = CliRunner().invoke(make(), ["--c", "BLUE"])
    assert r.exit_code == 2 and "RED" in r.output

def test_enum_case_insensitive():
    r = CliRunner().invoke(make(case_sensitive=False), ["--c", "green"])
    assert r.exit_code == 0, r.output
    assert "Color.GREEN" in r.output

def test_strings_unchanged():
    @click.command()
    @click.option("--c", type=click.Choice(["a", "b"]))
    def cli(c):
        click.echo(repr(c))
    r = CliRunner().invoke(cli, ["--c", "a"])
    assert r.exit_code == 0 and "'a'" in r.output
