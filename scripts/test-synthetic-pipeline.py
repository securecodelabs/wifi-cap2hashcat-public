#!/usr/bin/env python3
"""Test real native executables with synthetic captures; no existing service is used."""
import argparse
import http.client
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def command(arguments, expected=0):
    result = subprocess.run(list(map(str, arguments)), capture_output=True, text=True,
                            encoding='utf-8', timeout=120)
    if result.returncode != expected:
        raise RuntimeError(f'{arguments[0]} exited {result.returncode}, expected {expected}: '
                           f'{result.stdout[-2000:]} {result.stderr[-2000:]}')
    return result


def client(args, url, *arguments, expected=0):
    result = command([args.client, '--server', url, '--json', *arguments], expected)
    return json.loads(result.stdout) if expected == 0 else result


def verified(result):
    if result['status'] != 'recovered' or not result['matches']:
        raise RuntimeError('Synthetic password was not recovered')
    for match in result['matches']:
        if not match['verified'] or match['password_hex'] != b'ABCDEF12'.hex():
            raise RuntimeError('Incorrect or unverified synthetic password')


def wait_ready(api, port):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if api.poll() is not None:
            raise RuntimeError('Isolated test API exited during startup')
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=1)
        try:
            connection.request('GET', '/readyz')
            if connection.getresponse().status == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(.1)
    raise RuntimeError('Isolated test API did not become ready')


def recover_api(args, url, hashes, info):
    preview = client(args, url, 'pattern', 'preview', info['pattern'])
    if preview['candidate_count'] != info['candidate_count']:
        raise RuntimeError('Generator and API candidate counts disagree')
    job = client(args, url, 'submit', hashes, '--pattern', info['pattern'], '--runtime', '90')
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        detail = client(args, url, 'status', job['id'])
        if detail['state'] == 'recovered':
            result = client(args, url, 'result', job['id'])
            verified(result['engine_result'])
            client(args, url, 'delete', job['id'], '--yes')
            return
        if detail['state'] not in ('queued', 'running'):
            raise RuntimeError(f'Unexpected synthetic job state: {detail["state"]}')
        time.sleep(.2)
    raise RuntimeError('Timed out waiting for synthetic API recovery')


def cases(args, directory, url):
    results = []
    backend = ['--cpu', '--threads', '2'] if args.backend == 'cpu' else ['--backend', 'hip']
    for format_name in ('pcap', 'pcapng'):
        for mode in ('full', 'm1-m2', 'm2-m3', 'm2-only'):
            name = f'{mode}-{format_name}'
            capture = directory / f'{name}.{format_name}'
            hashes = directory / f'{name}.hc22000'
            report = directory / f'{name}.conversion.json'
            info = json.loads(command([args.generator, '--output', capture, '--password', 'ABCDEF12',
                                      '--handshake', mode, '--unknown-suffix', args.unknown_suffix,
                                      '--json']).stdout)
            recoverable = mode != 'm2-only'
            command([args.converter, capture, '--output', hashes, '--report', report],
                    0 if recoverable else 2)
            if recoverable:
                output = directory / f'{name}.result.json'
                command([args.engine, 'recover', '--hashes', hashes, '--mask', info['pattern'],
                         '--output', output, '--runtime', '90', *backend])
                verified(json.loads(output.read_text()))
                recover_api(args, url, hashes, info)
            else:
                if hashes.exists() or json.loads(report.read_text())['exports']:
                    raise RuntimeError('M2-only negative fixture unexpectedly exported a hash')
                rejected = client(args, url, 'submit', capture, '--pattern', info['pattern'], expected=1)
                if '400' not in rejected.stderr:
                    raise RuntimeError('API did not reject raw M2-only capture input with HTTP 400')
            results.append({'fixture': name, 'recoverable': recoverable, 'pattern': info['pattern'],
                            'candidate_count': info['candidate_count'], 'passed': True})
            print(f'PASS: {name} ({"direct engine + API/client recovery" if recoverable else "negative conversion + API rejection"})', flush=True)
    return results


def run(args, directory):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    url = f'http://127.0.0.1:{port}'
    with tempfile.TemporaryDirectory(prefix='synthetic-api-', dir=directory) as temporary:
        with (Path(temporary) / 'api.log').open('wb') as log:
            invocation = [str(args.api), '--listen', f'127.0.0.1:{port}', '--data-dir', temporary,
                          '--engine', str(args.engine)]
            if args.backend == 'cpu':
                invocation.append('--cpu')
            api = subprocess.Popen(invocation, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            try:
                wait_ready(api, port)
                results = cases(args, directory, url)
            finally:
                api.terminate()
                try:
                    api.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    api.kill()
                    api.wait(timeout=10)
    summary = {'backend': args.backend, 'password': 'ABCDEF12', 'cases': results}
    (directory / 'validation.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print(f'PASS: all eight fixtures; evidence: {directory}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('generator', 'converter', 'engine', 'api', 'client'):
        parser.add_argument('--' + name, type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument('--backend', choices=('cpu', 'hip'), default='cpu')
    parser.add_argument('--unknown-suffix', type=int, choices=range(9), default=4)
    parser.add_argument('--output-dir', type=Path, help='New directory to retain generated fixtures and results')
    args = parser.parse_args()
    if args.output_dir:
        directory = args.output_dir.resolve()
        directory.mkdir(parents=True, exist_ok=False)
        run(args, directory)
    else:
        with tempfile.TemporaryDirectory(prefix='synthetic-pipeline-') as temporary:
            run(args, Path(temporary))


if __name__ == '__main__':
    main()
