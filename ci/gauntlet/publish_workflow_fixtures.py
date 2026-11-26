"""A package publish workflow that names its npm token only by reference.

Release workflows write ``//registry.npmjs.org/:_authToken=${NPM_TOKEN}``
into ``.npmrc`` inside a quoted ``echo`` and map the token in from
``${{ secrets.NPM_TOKEN }}``. The post-tool output scan used to stop agents
reading such a workflow as if it leaked an npm token. The file is synthetic
and holds no credential.
"""

from __future__ import annotations

WORKFLOW_PATH = "portal/.github/workflows/publish.yml"

WORKFLOW_SOURCE = """\
name: Publish
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          registry-url: https://registry.npmjs.org
      - run: npm ci
      - run: echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > ~/.npmrc
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
      - run: npm publish --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
"""

SOURCES = {WORKFLOW_PATH: WORKFLOW_SOURCE}
