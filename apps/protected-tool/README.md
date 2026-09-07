# apps/protected-tool — mandatory mediation demo

A protected resource reachable only through the real `FileBroker` mediation
point.

```bash
source env.sh
python apps/protected-tool/run.py
```

Shows: (1) a mediated write+read succeeds; (2) a path-traversal escape is refused
(`FILE_PATH_ESCAPE`); (3) a direct bypass with no Decision Token is refused by the
real `DecisionTokenValidator` (`DECISION_TOKEN_INVALID`). The mediated-success
step uses `apps/_refvalidator` (demo shim) to focus on the broker's own controls;
step (3) uses the real validator. See `docs/ENFORCEMENT_FABRIC.md`.
