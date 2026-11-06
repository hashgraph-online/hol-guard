use super::scan;

fn modules(source: &str) -> Vec<String> {
    let mut found: Vec<String> = scan(source)
        .expect("readable")
        .imports
        .into_iter()
        .map(|import| {
            format!(
                "{}{}:{}",
                ".".repeat(import.level),
                import.module,
                import.names.join(",")
            )
        })
        .collect();
    found.sort();
    found
}

#[test]
fn imports_are_read_in_every_statement_form() {
    let source = "#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n\"\"\"Report on the file system; eval nothing.\"\"\"\nfrom __future__ import annotations\nimport json, os.path as osp\nfrom pathlib import Path\nfrom .helpers import (\n    total,  # sum\n    mean as average,\n)\nimport re\n\ndef main():\n    try:\n        import csv\n    except ImportError as error:\n        raise SystemExit(1) from error\n    pattern = re.compile(r'\\d+')\n    rows = {'a': 1}\n    print(f\"{rows['a']:>4} {{literal}} {osp.sep}\", json.dumps(rows), Path, total, average, pattern, csv)\n\nif __name__ == '__main__':\n    main()\n";
    assert_eq!(
        modules(source),
        [
            ".helpers:total,mean",
            "__future__:annotations",
            "csv:",
            "json:",
            "os.path:",
            "pathlib:Path",
            "re:",
        ]
    );
    assert!(!scan(source).unwrap().writes);
}

#[test]
fn code_the_imports_do_not_name_is_refused() {
    for source in [
        "exec(open('x.py').read())\n",
        "eval('1')\n",
        "code = compile('1', 'x', 'eval')\n",
        "m = __import__('os')\n",
        "f = getattr(os, 'sys' + 'tem')\n",
        "warnings._setoption('ignore::pkg.Cls')\n",
        "unittest.mock.patch('pkg.get').start()\n",
        "os.system('ls')\n",
        "from os import system\n",
        "from os import *\n",
        "os.execv('/bin/sh', ['sh'])\n",
        "sys.path.insert(0, 'plugins')\n",
        "x = ().__class__.__bases__[0].__subclasses__()\n",
        "print('{0.__class__}'.format(1))\n",
        "print(f'{os.popen(\"id\").read()}')\n",
        "frame = sys._getframe(1)\n",
        "# -*- coding: rot13 -*-\nimport os\n",
        "x = 1 + \\\n  2\n",
        "\u{ff45}\u{ff58}\u{ff45}\u{ff43}('1')\n",
        "print(f'{\u{ff45}\u{ff58}\u{ff45}\u{ff43}(1)}')\n",
        "s = 'unterminated\n",
        "# note\rimport hidden\n",
        "x = f\"{d[\"k\"]}\"\nimport hidden\n",
        "x = f'{1 # comment\n}'\n",
        "x = t'{y}'\n",
        "import json\nimport\n",
        "import typing\nhints = typing.get_type_hints(Row)\n",
        "from typing import ForwardRef\n",
        "value = typing.evaluate_forward_ref(ref)\n",
        "hints = Row.__annotations__\n",
        "hints = Row.__annotate__(1)\n",
    ] {
        assert!(scan(source).is_none(), "{source}");
    }
}

#[test]
fn ordinary_text_is_readable() {
    for source in [
        "pattern = re.compile(r'[a-z]+')\nvalue = ast.literal_eval('[1]')\n",
        "print('caf\u{e9} \u{2014} done')\n# r\u{e9}sum\u{e9}: the system will evaluate this\n",
        "cursor.execute('select 1')\n",
        "raise ValueError('bad') from None\n",
        "def gen():\n    yield from range(3)\n",
        "print(f\"\u{2713} {count} files\")\r\n",
        "message = f'{name!r:>10}'\n",
        "parser.add_argument('--out', help='where to write')\ntext = text.replace('a', 'b')\n",
    ] {
        assert!(scan(source).is_some(), "{source}");
    }
}

#[test]
fn writes_are_seen_in_code_only() {
    assert!(
        scan("with open('out.json', 'w') as f:\n    f.write('{}')\n")
            .unwrap()
            .writes
    );
    assert!(scan("Path('x').write_text('y')\n").unwrap().writes);
    assert!(
        scan("import io, mmap\nhandle = io.FileIO('helpers.py', 'r+')\nview = mmap.mmap(handle.fileno(), 0)\nview[0:1] = b'#'\n")
            .unwrap()
            .writes
    );
    assert!(scan("os.ftruncate(fd, 0)\n").unwrap().writes);
    for source in [
        "open('x', 'w')\n",
        "open('x', mode='a')\n",
        "open('x', 'r+')\n",
        "open('x', mode)\n",
        "open('x', *args)\n",
        "open('x', **options)\n",
        "open('x', 'r', opener=make)\n",
        "open('x', 'r' 'w')\n",
        "open('x', r'w')\n",
        "Path('x').open('w')\n",
        "gzip.open('t', 'w')\n",
        "os.open('x', os.O_RDONLY)\n",
        "with open('x') as a, open('y', 'wb') as b:\n    pass\n",
        "open('x', ('w'))\n",
        "open('x'\n",
        "Path('payload.py').replace('json.py')\n",
        "Path.replace(Path('payload.py'), 'json.py')\n",
        "a = parser.add_argument('--o', type=Path)\na.type.replace('payload.py', 'json.py')\n",
        "fields(C)[0].type.replace(src, dst)\n",
        "type(staged).replace(staged, target)\n",
        "staged.replace(target)\n",
        "Path(a).replace(*pair)\n",
        "Path(a).replace(\n",
        "os.rmdir('plugins')\n",
    ] {
        assert!(scan(source).is_none_or(|found| found.writes), "{source}");
    }
    for source in [
        "open('x')\n",
        "open('x', 'rb')\n",
        "open(path, encoding='utf-8', newline='')\n",
        "open(f'{name}.json', mode='rt')\n",
        "Path('x').open()\n",
        "Path('x').open('r', encoding='utf-8')\n",
        "if a == b:\n    open(p if a == b else q)\n",
        "line = line.replace('\\t', '    ', 1)\n",
        "data = blob.replace(b'a', b'b')\n",
        "name = str.replace(name, '-', '_')\n",
    ] {
        assert!(!scan(source).unwrap().writes, "{source}");
    }
    // A path class reached as a value makes a two-argument `replace` a move.
    for source in [
        "pathlib.Path.replace(Path('a'), 'json.py')\n",
        "PosixPath.replace(a, b)\n",
        "type(p).replace(p, t)\n",
        "t = type\nt(p).replace(p, q)\n",
        "from pathlib import Path as P\nP.replace(a, b)\n",
        "P = Path\nP.replace(a, b)\n",
        "cls = [Path][0]\ncls.replace(a, b)\n",
        "d = {'k': Path}\nd['k'].replace(a, b)\n",
        "f = lambda: Path\nf().replace(a, b)\n",
        "class M(Path):\n    pass\nM.replace(a, b)\n",
        "def g(c=Path):\n    return c.replace(a, b)\n",
        "for C in (Path,):\n    C.replace(a, b)\n",
        "m = p.replace\nm('json.py')\n",
        "isinstance(x, (Path, str))\nk.replace(a, b)\n",
    ] {
        assert!(
            scan(source).is_none_or(|found| found.writes || found.replaces.writes()),
            "{source}"
        );
    }
    for source in [
        "from pathlib import Path\nname = name.replace('-', '_')\nout = Path(__file__).parent / name\n",
        "from pathlib import Path\ndef f(p: Path, q: Optional[Path] = None) -> list[Path]:\n    return [p]\ns = s.replace('a', 'b')\n",
        "parser.add_argument('--out', type=Path)\nline = line.replace('x', ' ')\n",
        "out: Path = Path.home()\nif isinstance(out, Path):\n    t = t.replace('x', 'y')\n",
        "from pathlib import (\n    Path,\n    PurePath,\n)\nx = y.replace(a, b)\ndef h(a: dict[str, Path]) -> None: ...\n",
        "parser.add_argument('--n', type=int)\nv = v.replace(a, b)\n",
    ] {
        let found = scan(source).unwrap();
        assert!(!found.writes && !found.replaces.writes(), "{source}");
    }
    assert!(
        !scan("# open( the door\nprint('shutil.rmtree(x)')\ntext = text.replace('a', 'b')\n")
            .unwrap()
            .writes
    );
}
