import click
from click.testing import CliRunner

def test_choice_suggests_closest():
    @click.command()
    @click.option("--c", type=click.Choice(["apple", "banana", "cherry"]))
    def cli(c):
        click.echo(c)
    r = CliRunner().invoke(cli, ["--c", "banan"])
    assert r.exit_code == 2
    assert "did you mean" in r.output.lower() and "banana" in r.output
    assert "apple" in r.output
