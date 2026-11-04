"""Scope check for the search whose path argument is left empty."""

from __future__ import annotations

from typing import Any

# Oh My Pi's `glob` takes one `path` argument and spells "start where the
# project does" as the empty string. The blank spelling is the shape under
# test, so a run that names a folder instead never reaches it.
BLANK_SEARCH_PATH_CASE = "omp-native-glob-empty-path-argument"


def blank_search_path_error(calls: list[dict[str, Any]]) -> str | None:
    """Return why the run did not search only with an empty path argument.

    Every ``glob`` call must carry ``path`` as a blank string, and at least one
    must exist. A call that names a folder, or omits the argument, takes the
    ordinary route: if Guard denied that call, the run would be scored against
    a shape this case does not exercise.
    """
    searches = [call for call in calls if call["name"] == "glob"]
    if not searches:
        return "the run made no glob call"
    for call in searches:
        path = call["args"].get("path")
        if not isinstance(path, str) or path.strip():
            return "a glob call did not leave its path argument empty"
    return None
