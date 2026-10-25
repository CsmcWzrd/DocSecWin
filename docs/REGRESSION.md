# Regression scripts

Build with Make or CMake, then use any runner (Python 3 required for tests only):

```sh
sh tests/regression.sh --build --build-system make
python3 tests/run_regression.py --server ./DocSecWin --native-test ./zar-stream-test
python3 tests/run_regression.py --suite trigger --repeat 3
```

Windows cmd: `tests\regression.cmd --build`; PowerShell:
`tests\regression.ps1 -Build`. For CMake use `--build-system cmake` with the
Python or shell runner. `--server`, `--native-test`, `--report-dir`, `--timeout`
and `--repeat` select binaries, output and execution limits. Run `--help` for
all options. Nonzero exit status indicates failure. Make also provides
`make test` and `make regression`; CMake registers the tests with CTest.

The full runner executes native Zar streaming checks, 12 baseline integration
scenarios and 13 trigger scenarios. Tests create isolated temporary databases;
no existing user database is used. Optional IPv6 and curl tests report a skip
when those capabilities are unavailable. OpenSSL CLI is needed for baseline
HTTPS fixtures. JSON and JUnit XML reports plus captured suite logs are written
to test-results/ by default. Each JUnit case represents one suite invocation;
individual unittest results remain in its log. The server has no Python backend.

Trigger regression verifies that the initiating client receives no content,
metadata or query results, even for ranges and errors. It then makes separate
queries without the marker to check local content, metadata and isolation.
