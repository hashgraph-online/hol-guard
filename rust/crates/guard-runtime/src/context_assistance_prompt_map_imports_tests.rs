//! Import statements shown beside a function left to be written.
use super::project_tests::{project, prompt_map, ON};

const MORE: &str = "\"\"\"Helpers.\"\"\"
import operator
from functools import (
    partial,
    reduce,
)
from itertools import chain


def total(values):
    \"\"\"Add up *values*.\"\"\"
    raise NotImplementedError


def joined():
    \"\"\"Return the json module.\"\"\"
    import json
    return json
";

/// Writing a function again, the agent learns which names it may use from
/// the file's imports, each statement whole however many lines it takes; an
/// import inside a function is not one of them. A prompt about a function
/// that is already written gets no imports.
#[test]
fn a_function_left_to_be_written_comes_with_its_files_imports() {
    let (home, _project, root) = project(ON, &[("src/pkg/more.py", MORE)]);
    let prompt = "Tests fail because total is not implemented (src/pkg/more.py). Write the \
implementation; the docstring and tests describe the expected behavior.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(
        text.contains(
            "\n\nImports in src/pkg/more.py:\n```\nimport operator\nfrom functools import (\n    \
partial,\n    reduce,\n)\nfrom itertools import chain\n```"
        ),
        "{text}"
    );
    assert!(!text.contains("import json"), "{text}");
    let prompt = "Add a short usage example to the docstring of `joined` in src/pkg/more.py, \
written as a doctest.";
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(!text.contains("Imports in"), "{text}");
}
