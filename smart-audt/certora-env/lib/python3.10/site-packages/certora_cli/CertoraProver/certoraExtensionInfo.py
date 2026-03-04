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

import sys
from pathlib import Path
from typing import Any, Dict


scripts_dir_path = Path(__file__).parents[1]
sys.path.insert(0, str(scripts_dir_path))

import Shared.certoraUtils as Cu


def extension_file_written() -> bool:
    return Cu.get_extension_info_file().is_file()


class ExtensionInfoWriter:
    """
    A class that generates a JSON file containing information for the VSCode extension, such as the verification report
    link.
    It will always generate the file, either via an explicit call to close, or when this object is deleted from
    memory. The file should only be written once per certoraRun invocation.
    """
    def __init__(self) -> None:
        self.vscode_fields: Dict[str, Any] = {}

    def add_field(self, key: str, value: Any) -> None:
        # if extension_file_written():
        #     raise RuntimeError(f"Extension Info File was already written to {Cu.get_extension_info_file().resolve()}")
        if key in self.vscode_fields:
            f"Key {key} already exists in the Extension Info Writer with value {self.vscode_fields[key]}"
        self.vscode_fields[key] = value

    def write_file(self) -> None:
        if not extension_file_written():
            Cu.write_json_file(self.vscode_fields, Cu.get_extension_info_file())

    def __del__(self) -> None:
        self.write_file()
