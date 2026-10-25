#!/usr/bin/env python3
"""Portable DocSecWin regression runner with JSON/JUnit and captured suite logs."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

PROJECT = Path(__file__).resolve().parents[1]


def find_binary(name):
    suffix = '.exe' if os.name == 'nt' else ''
    for directory in (PROJECT, PROJECT/'build'/'Release', PROJECT/'build', PROJECT/'build'/'Debug'):
        candidate = directory/(name+suffix)
        if candidate.is_file():
            return candidate.resolve()
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', type=Path, help='existing DocSecWin executable')
    parser.add_argument('--native-test', type=Path, help='existing zar-stream-test executable')
    parser.add_argument('--suite', choices=('all', 'baseline', 'trigger'), default='all')
    parser.add_argument('--repeat', type=int, default=1)
    parser.add_argument('--report-dir', type=Path, default=PROJECT/'test-results')
    parser.add_argument('--timeout', type=int, default=600, help='seconds per command')
    parser.add_argument('--build', action='store_true')
    parser.add_argument('--build-system', choices=('auto','cmake','make'), default='auto')
    args = parser.parse_args()
    if not 1 <= args.repeat <= 100 or args.timeout < 1:
        parser.error('repeat must be 1-100 and timeout must be positive')
    report_dir = args.report_dir.resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    results = []

    def run(name, command):
        print('Running '+name+' ...', flush=True)
        start = time.monotonic()
        try:
            process = subprocess.run([str(x) for x in command], cwd=PROJECT,
                                     capture_output=True, text=True, errors='replace',
                                     timeout=args.timeout)
            text = process.stdout + process.stderr
            code = process.returncode
        except subprocess.TimeoutExpired as error:
            def decoded(value):
                return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
            text = decoded(error.stdout)+decoded(error.stderr)+'\nCommand timed out.\n'
            code = 124
        except OSError as error:
            text = str(error)+'\n'
            code = 127
        log = report_dir/(name+'.log')
        log.write_text(text, encoding='utf-8')
        tests = re.search(r'Ran (\d+) tests?', text)
        skipped = re.search(r'skipped=(\d+)', text)
        entry = {'suite':name, 'status':'passed' if code == 0 else 'failed',
                 'exit_code':code, 'seconds':round(time.monotonic()-start, 3),
                 'functional_tests':int(tests.group(1)) if tests else None,
                 'skipped':int(skipped.group(1)) if skipped else 0, 'log':log.name}
        results.append(entry)
        print(text, end='' if text.endswith('\n') else '\n', flush=True)
        return code == 0

    def report():
        document = {'project':'DocSecWin', 'version':'0.3.0',
                    'generated_at_utc':datetime.now(timezone.utc).isoformat(),
                    'status':'failed' if any(x['exit_code'] for x in results) else 'passed',
                    'functional_tests':sum(x['functional_tests'] or 0 for x in results),
                    'skipped':sum(x['skipped'] for x in results), 'suites':results}
        (report_dir/'regression-results.json').write_text(json.dumps(document, indent=2)+'\n')
        # Each JUnit testcase represents one executed suite/build command. Individual
        # unittest cases and subtest details remain in that testcase's captured log.
        junit = ET.Element('testsuite', name='DocSecWin regression', tests=str(len(results)),
                           failures=str(sum(bool(x['exit_code']) for x in results)),
                           time=str(round(sum(x['seconds'] for x in results), 3)))
        for result in results:
            case = ET.SubElement(junit, 'testcase', name=result['suite'], classname='DocSecWin', time=str(result['seconds']))
            text = (report_dir/result['log']).read_text(encoding='utf-8')
            if result['exit_code']:
                ET.SubElement(case, 'failure', message='Exit code '+str(result['exit_code'])).text = text
            ET.SubElement(case, 'system-out').text = text
        ET.ElementTree(junit).write(report_dir/'regression-results.xml', encoding='utf-8', xml_declaration=True)
        print('Regression '+document['status']+'. Reports: '+str(report_dir), flush=True)
        return 1 if document['status'] == 'failed' else 0

    if args.build:
        build_system = args.build_system
        if build_system == 'auto':
            build_system = 'cmake' if shutil.which('cmake') else 'make'
        if build_system == 'cmake':
            if not run('configure', ['cmake','-S',PROJECT,'-B',PROJECT/'build','-DBUILD_TESTING=ON']):
                return report()
            if not run('build', ['cmake','--build',PROJECT/'build','--config','Release']):
                return report()
        elif not run('build', ['make','DocSecWin','zar-stream-test']):
            return report()
    server = args.server.resolve() if args.server else find_binary('DocSecWin')
    native = args.native_test.resolve() if args.native_test else find_binary('zar-stream-test')
    if not server or not server.is_file():
        print('DocSecWin executable missing: pass --server or --build.', file=sys.stderr)
        return 2
    if args.suite == 'all' and (not native or not native.is_file()):
        print('Native test executable missing: pass --native-test or --build.', file=sys.stderr)
        return 2
    for repeat in range(1, args.repeat+1):
        suffix = '-'+str(repeat)
        if args.suite == 'all':
            run('zar-stream'+suffix, [native])
        if args.suite in ('all','baseline'):
            run('baseline'+suffix, [sys.executable, PROJECT/'tests'/'integration.py', server])
        if args.suite in ('all','trigger'):
            run('trigger'+suffix, [sys.executable, PROJECT/'tests'/'trigger_regression.py', server])
    return report()


if __name__ == '__main__':
    raise SystemExit(main())
