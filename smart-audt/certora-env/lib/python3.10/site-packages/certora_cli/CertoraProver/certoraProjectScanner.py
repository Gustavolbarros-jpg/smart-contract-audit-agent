#     The Certora Prover
#     Copyright (C) 2025  Certora Ltd.
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, version 3 of the License.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.

import json
import logging
import os
import subprocess
from dataclasses import dataclass
from functools import partial
from multiprocessing import Pool
from pathlib import Path
from typing import List, Optional
from tqdm import tqdm


def get_solidity_files(project_root: Path) -> List[Path]:
    """
    Find all Solidity files under [project_root].
    If that dir is within a git repo, use `git ls-files` to find all Solidity files
    within the repo (in particular, this will skip files in submodules).
    Otherwise, recursively find all Solidity files while skipping hidden directories
    """
    extension = ".sol"

    def fallback_walk() -> List[Path]:
        # Use os.walk to find files with the given extension
        all_files = []
        for root, dirs, files in os.walk(project_root):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for file in files:
                if file.endswith(extension):
                    all_files.append((Path(root) / file).relative_to(project_root))
        return all_files

    try:
        # Try using git ls-files to find files
        result = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard", "--cached"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=project_root
        )
        all_files = result.stdout.splitlines()

        # Filter files by the desired extension
        return [Path(f) for f in all_files if f.endswith(extension)]

    except (subprocess.CalledProcessError, FileNotFoundError):
        # If Git fails or is not installed, fall back to os.walk
        print("Git is not available or the directory is not a Git repository. Falling back to os.walk.")
        return fallback_walk()


def get_solc_base_args(project_root: Path) -> List[str]:
    """
    Get base arguments for solc command including paths if node_modules exists
    """
    args = []
    if (project_root / 'node_modules').is_dir():
        args.extend(['--base-path', str(project_root), '--include-path', 'node_modules'])

    remappings_file = project_root / 'remappings.txt'
    if remappings_file.exists():
        with open(remappings_file) as f:
            remappings = [line.strip() for line in f if line.strip()]
            args.extend(remappings)
    else:
        logging.info("no 'remappings.txt' file found")

    return args


def get_ast_contract_nodes(sol_file: Path, project_root: Path) -> List[dict]:
    """
    Parse Solidity file and return list of ContractDefinition nodes from AST
    """
    base_args = get_solc_base_args(project_root)
    ast_cmd = ['solc', '--ast-compact-json', '--stop-after', 'parsing'] + base_args + [sol_file]
    ast_result = subprocess.run(
        ast_cmd,
        capture_output=True,
        text=True,
        cwd=project_root
    )

    if ast_result.returncode != 0:
        logging.error(f"Failed to build {sol_file}! Error:\n{ast_result.stderr}")
        return []

    contract_nodes = []
    for line in ast_result.stdout.split('\n'):
        if not line.strip() or line.startswith('>'):
            continue
        try:
            ast_json = json.loads(line)
            for node in ast_json.get('nodes', []):
                if node.get('nodeType') == 'ContractDefinition':
                    contract_nodes.append(node)
        except json.JSONDecodeError:
            continue

    return contract_nodes


def extract_deployable_contracts(sol_file: Path, project_root: Path) -> List[str]:
    """
    Extract the deployable contract names from a Solidity file.
    """
    try:
        base_args = get_solc_base_args(project_root)
        bin_runtime = 'bin-runtime'
        compiler_cmd = ['solc', '--combined-json', bin_runtime] + base_args + [str(sol_file)]
        result = subprocess.run(
            compiler_cmd,
            capture_output=True,
            text=True,
            cwd=project_root
        )

    except Exception as e:
        logging.error(f"Error extracting contracts from {sol_file}: {e}")
        return []

    if result.returncode != 0:
        logging.error(f"Failed to build {sol_file}! Error:\n{result.stderr}")
        return []

    contract_nodes = get_ast_contract_nodes(sol_file, project_root)

    bins = json.loads(result.stdout)

    if "contracts" not in bins:
        # an empty file...
        return []

    deployable_contracts: List[str] = []
    for contract, data in bins["contracts"].items():
        current_file, current_contract = contract.split(':')
        if data[bin_runtime] and data[bin_runtime] != '0x' and \
           str(sol_file).endswith(current_file) and \
           all(node.get('contractKind') != 'library' or node.get('name') != current_contract for node in contract_nodes):
            deployable_contracts.append(current_contract)

    return deployable_contracts


@dataclass
class FileResult:
    """Result of processing a single Solidity file"""
    file_path: Path
    contracts: List[str]


def process_file(project_root: Path, sol_file: Path) -> FileResult:
    """
    Process a single Solidity file. Designed for Pool.map usage.
    """
    contract_names = extract_deployable_contracts(sol_file, project_root)
    return FileResult(sol_file, contract_names)

def scan_project(project_path: Optional[str] = None) -> List[FileResult]:
    """
    Scan a project and return a list of `FileResult`s, each containing a
    filename and a list of (deployable) contracts declared in that file.
    Only files with at least one deployable contract are returned
    """
    if project_path is None:
        project_root = Path.cwd()
    else:
        project_root = Path(project_path).resolve()

    all_sol_files = get_solidity_files(project_root)

    # Process files in parallel with progress bar
    func = partial(process_file, project_root)
    with Pool() as pool:
        results = list(tqdm(
            pool.imap(func, all_sol_files),
            total=len(all_sol_files),
            desc="Processing Solidity files",
            unit="%"
        ))

    return list(filter(lambda result: len(result.contracts) > 0, results))
