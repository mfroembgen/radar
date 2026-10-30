#!/usr/bin/env python3
"""Package the fork chart from an exact source commit, retaining release versions."""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source-ref', required=True)
parser.add_argument('--version', required=True)
parser.add_argument('--output-dir', default='deploy/fork-chart')
args = parser.parse_args()
repo = Path(subprocess.check_output(
    ['git', 'rev-parse', '--show-toplevel'], cwd=Path(__file__).resolve().parent,
    text=True).strip())
source_sha = subprocess.check_output(
    ['git', 'rev-parse', f'{args.source_ref}^{{commit}}'], cwd=repo,
    text=True).strip()
output = (repo / args.output_dir).resolve()
output.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='radar-fork-chart-') as temporary:
    stage = Path(temporary)
    archive = subprocess.check_output(
        ['git', 'archive', source_sha, 'deploy/helm/radar'], cwd=repo)
    subprocess.run(['tar', '-xf', '-', '-C', str(stage)], input=archive, check=True)
    chart = stage / 'deploy/helm/radar'
    metadata = chart / 'Chart.yaml'
    text = metadata.read_text()
    # Preserve upstream maintainers, license and source; record the packaged commit.
    text = text.replace('sources:\n',
                        f'sources:\n  - https://github.com/mfroembgen/radar/tree/{source_sha}\n', 1)
    text = text.replace('image: ghcr.io/skyhook-io/radar:0.0.0-dev',
                        f'image: ghcr.io/mfroembgen/radar:{args.version}')
    metadata.write_text(text)
    values = chart / 'values.yaml'
    text = values.read_text().replace('repository: ghcr.io/skyhook-io/radar',
                                    'repository: ghcr.io/mfroembgen/radar', 1)
    values.write_text(text)
    subprocess.run(['helm', 'package', str(chart), '--version', args.version,
                    '--app-version', args.version, '--destination', str(output)], check=True)
subprocess.run(['helm', 'repo', 'index', str(output)], check=True)
print(f'Packaged release {args.version} from {source_sha} in {output}')
