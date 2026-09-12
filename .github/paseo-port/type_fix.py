from pathlib import Path
import json
p=Path('src/codex_plugin_scanner/guard/adapters/paseo_config.py')
s=p.read_text()
old='''    environment = _object_field(entry, "env")
    if any(not isinstance(value, str) for value in environment.values()):
        raise ValueError("Paseo provider environment values must be strings.")
'''
new='''    environment: dict[str, str] = {}
    for key, value in _object_field(entry, "env").items():
        if not isinstance(value, str):
            raise ValueError("Paseo provider environment values must be strings.")
        environment[key] = value
'''
assert s.count(old) == 1
p.write_text(s.replace(old,new,1))
expected_file=Path(__file__).with_name('expected.json')
expected=json.loads(expected_file.read_text())
assert expected[p.as_posix()]=='22321401500c0d7c0ab24d3c01f4bc4a0efb851206f94627a02b349d2ddf87be'
expected[p.as_posix()]='5a1a6a322fe63433cf3cc82b6f4f5a51765332b2e3e445ff0ef20a066d0d2e96'
expected_file.write_text(json.dumps(expected))
