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

from CertoraProver.Compiler.CompilerCollector import CompilerCollector, CompilerLang
from Shared.certoraUtils import CompilerVersion


class CompilerCollectorSolBased(CompilerCollector):

    def __init__(self, version: CompilerVersion, lang: CompilerLang):
        self.__compiler_version = version
        self.__smart_contract_lang = lang

    @property
    def compiler_name(self) -> str:
        return self.smart_contract_lang.compiler_name

    @property
    def smart_contract_lang(self) -> CompilerLang:
        return self.__smart_contract_lang

    @property
    def compiler_version(self) -> CompilerVersion:
        return self.__compiler_version
