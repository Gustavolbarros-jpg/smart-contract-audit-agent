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

from typing import Any, Dict
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from Shared.certoraUtils import NoValEnum


class NodeFilters:

    class NodeType(NoValEnum):

        def is_this_node_type(self, type_name_node: Dict[str, Any]) -> bool:
            return type_name_node["nodeType"] == self.value

    class TypeNameNode(NodeType):
        ELEMENTARY = "ElementaryTypeName"
        FUNCTION = "FunctionTypeName"
        USER_DEFINED = "UserDefinedTypeName"
        MAPPING = "Mapping"
        ARRAY = "ArrayTypeName"

    class UserDefinedTypeDefNode(NodeType):
        ENUM = "EnumDefinition"
        STRUCT = "StructDefinition"
        VALUE_TYPE = "UserDefinedValueTypeDefinition"
        CONTRACT = "ContractDefinition"

    @staticmethod
    def CERTORA_CONTRACT_NAME() -> str:
        return "certora_contract_name"

    @staticmethod
    def is_enum_definition(node: Dict[str, Any]) -> bool:
        return node["nodeType"] == "EnumDefinition"

    @staticmethod
    def is_struct_definition(node: Dict[str, Any]) -> bool:
        return node["nodeType"] == "StructDefinition"

    @staticmethod
    def is_user_defined_value_type_definition(node: Dict[str, Any]) -> bool:
        return node["nodeType"] == "UserDefinedValueTypeDefinition"

    @staticmethod
    def is_contract_definition(node: Dict[str, Any]) -> bool:
        return node["nodeType"] == "ContractDefinition"

    @staticmethod
    def is_user_defined_type_definition(node: Dict[str, Any]) -> bool:
        return NodeFilters.is_enum_definition(node) or NodeFilters.is_struct_definition(
            node) or NodeFilters.is_user_defined_value_type_definition(node)

    @staticmethod
    def is_import(node: Dict[str, Any]) -> bool:
        return node["nodeType"] == "ImportDirective"

    @staticmethod
    def is_defined_in_a_contract_or_library(node: Dict[str, Any]) -> bool:
        return NodeFilters.CERTORA_CONTRACT_NAME() in node

    @staticmethod
    def is_defined_in_contract(node: Dict[str, Any], contract_name: str) -> bool:
        return node[NodeFilters.CERTORA_CONTRACT_NAME()] == contract_name
