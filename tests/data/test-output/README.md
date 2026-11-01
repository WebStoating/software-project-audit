Real tool output recorded by running `audit.py test` in the pinned runtime images (python 3.12 / node 22).
- pytest-junit.xml, coveragepy.json: scratch python project (pass, fail, skip, setup error; branchy code).
- coveragepy-nobranch.json: tests/fixtures/py-app (no branches present).
- vitest-junit.xml: scratch vitest project (pass, fail, skip). istanbul-summary.json: tests/fixtures/ts-app.
- jest.json: scratch jest project (no fixture uses jest): pass, fail, skip, todo, plus a suite that cannot load.
  The bulky `coverageMap` key was removed.
