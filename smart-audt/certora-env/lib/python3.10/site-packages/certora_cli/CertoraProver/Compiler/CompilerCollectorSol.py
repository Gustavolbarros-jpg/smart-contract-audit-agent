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

from pathlib import Path
from typing import Any, List, Tuple, Dict, Set

from CertoraProver.Compiler.CompilerCollector import CompilerLang, CompilerLangFunc
from CertoraProver.Compiler.CompilerCollectorSolBased import CompilerCollectorSolBased
from Shared.certoraUtils import Singleton, CompilerVersion, get_certora_config_dir
import CertoraProver.certoraType as CT


class CompilerLangSol(CompilerLang, metaclass=Singleton):
    """
    [CompilerLang] for Solidity.
    """

    @property
    def name(self) -> str:
        return "Solidity"

    @property
    def compiler_name(self) -> str:
        return "solc"

    @staticmethod
    def get_contract_def_node_ref(contract_file_ast: Dict[int, Any], contract_file: str, contract_name: str) -> \
            int:
        contract_def_refs = list(filter(
            lambda node_id: contract_file_ast[node_id].get("nodeType") == "ContractDefinition" and
            contract_file_ast[node_id].get("name") == contract_name, contract_file_ast))
        assert len(contract_def_refs) != 0, \
            f'Failed to find a "ContractDefinition" ast node id for the contract {contract_name}'
        assert len(
            contract_def_refs) == 1, f'Found multiple "ContractDefinition" ast node ids for the same contract ' \
                                     f'{contract_name}: {contract_def_refs}'
        return contract_def_refs[0]

    @staticmethod
    def compilation_output_path(sdc_name: str) -> Path:
        return get_certora_config_dir() / f"{sdc_name}.standard.stdout.json"

    @staticmethod
    def get_supports_imports() -> bool:
        return True

    # Todo - add this for Vyper too and make it a CompilerLang class method one day
    @staticmethod
    def compilation_error_path(sdc_name: str) -> Path:
        return get_certora_config_dir() / f"{sdc_name}.standard.json.stderr"

    @staticmethod
    def all_compilation_artifacts(sdc_name: str) -> Set[Path]:
        """
        Returns the set of paths for all files generated after compilation.
        """
        return {CompilerLangSol.compilation_output_path(sdc_name),
                CompilerLangSol.compilation_error_path(sdc_name)}

    @staticmethod
    def collect_source_type_descriptions_and_funcs(asts: Dict[str, Dict[str, Dict[int, Any]]],
                                                   data: Dict[str, Any],
                                                   contract_file: str,
                                                   contract_name: str,
                                                   build_arg_contract_file: str) -> \
            Tuple[List[CT.Type], List[CompilerLangFunc]]:
        assert False, "collect_source_type_descriptions() has not yet been implemented in CompilerLangSol"

    @property
    def supports_typed_immutables(self) -> bool:
        return True

    @property
    def supports_ast_output(self) -> bool:
        return True

    @property
    def supports_srclist_output(self) -> bool:
        return True


# This class is intended for calculations of compiler-settings related queries
class CompilerCollectorSol(CompilerCollectorSolBased):

    def __init__(self, version: CompilerVersion, lang: CompilerLang, use_memory_safe_autofinders: bool):
        super().__init__(version, lang)
        # will only be applied for supporting solc versions
        self.__use_memory_safe_autofinders = use_memory_safe_autofinders

    def normalize_storage(self, is_storage: bool, arg_name: str) -> str:
        if not is_storage:
            return arg_name
        if self.compiler_version[0] == 0 and self.compiler_version[1] < 7:
            return arg_name + "_slot"
        else:
            return arg_name + ".slot"

    def supports_calldata_assembly(self, arg_name: str) -> bool:
        return (self.compiler_version[1] > 7 or (
                self.compiler_version[1] == 7 and self.compiler_version[2] >= 5)) and arg_name != ""

    def supports_memory_safe_assembly(self) -> bool:
        return (self.compiler_version[1] > 8 or (
                self.compiler_version[1] == 8 and self.compiler_version[2] >= 13))

    def gen_memory_safe_assembly_prefix(self) -> str:
        if self.supports_memory_safe_assembly() and self.__use_memory_safe_autofinders:
            return 'assembly ("memory-safe")'
        else:
            return 'assembly'
