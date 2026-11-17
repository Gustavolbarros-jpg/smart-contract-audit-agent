"""preparar_spec roda inteiro, com e sem o código do contrato.

Regressão: a chamada a ``declarar_owner_envfree`` foi acrescentada dentro de
``preparar_spec`` sem o parâmetro ``contract_source``, e **todo** pipeline completo morria
na ETAPA 3 com ``NameError: name 'contract_source' is not defined``. Nenhum teste
exercitava a função inteira — só os validadores por dentro — então o erro só apareceu na
primeira rodada ponta a ponta depois disso.
"""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

import orchestrator  # noqa: E402


SPEC_CALLING_OWNER = """methods {
  function pause() external;
}

rule only_the_owner_pauses {
  env e;
  require e.msg.sender != owner();
  pause@withrevert(e);
  assert lastReverted;
}
"""

CONTRACT_WITH_INHERITED_OWNER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Ownable} from "openzeppelin/access/Ownable.sol";

contract Treasury is Ownable {
    function pause() external onlyOwner {}
}
"""


class PrepararSpecTests(unittest.TestCase):
    def _run(self, spec, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "generated.spec"
            prepared = orchestrator.preparar_spec(spec, str(destination), **kwargs)
            self.assertTrue(destination.is_file())
            self.assertEqual(destination.read_text(encoding="utf-8"), prepared)
        return prepared

    def test_it_does_not_need_the_contract_source(self):
        prepared = self._run(SPEC_CALLING_OWNER)
        self.assertIn("rule only_the_owner_pauses", prepared)

    def test_an_inherited_owner_is_declared_envfree(self):
        prepared = self._run(
            SPEC_CALLING_OWNER, contract_source=CONTRACT_WITH_INHERITED_OWNER
        )
        self.assertIn("function owner() external returns(address) envfree;", prepared)

    def test_a_contract_without_an_owner_gets_no_declaration(self):
        prepared = self._run(
            SPEC_CALLING_OWNER, contract_source="contract Plain { function pause() external {} }"
        )
        self.assertNotIn("function owner()", prepared)

    def test_the_deterministic_methods_block_replaces_the_generated_one(self):
        block = "methods {\n  function pause() external;\n  function owner() external returns(address) envfree;\n}"
        prepared = self._run(SPEC_CALLING_OWNER, methods_block=block)
        self.assertIn("function owner() external returns(address) envfree;", prepared)
        self.assertEqual(prepared.count("methods {"), 1)
