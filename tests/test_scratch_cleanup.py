"""O pipeline não deixa mais a cópia de trabalho dentro de ``src/`` de produção.

O contrato corrigido **precisa** nascer ao lado do original: só ali os imports
relativos e os remappings do Foundry resolvem, e o Prover recusa arquivo fora do
diretório do repo. O efeito colateral era um ``*_AGENT_FIXED.sol`` por rodada dentro de
uma árvore `src/` real, que qualquer varredura do corpus conta como mais um contrato.
Como toda versão já é gravada em ``run_dir``, a cópia solta é redundante no fim — mas só
pode ser apagada quando foi esta rodada que a criou.
"""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

import orchestrator  # noqa: E402


class TestPreservarELimparScratch(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.src = base / "src"
        self.run_dir = base / "run"
        self.src.mkdir()
        self.run_dir.mkdir()
        self.scratch = self.src / "Vault_AGENT_FIXED.sol"
        self.conteudo = "// SPDX-License-Identifier: MIT\ncontract Vault { uint256 x; }\n"

    def tearDown(self):
        self._tmp.cleanup()

    def test_remove_a_copia_que_a_rodada_criou(self):
        self.scratch.write_text(self.conteudo, encoding="utf-8")

        destino = orchestrator.preservar_e_limpar_scratch(
            self.scratch, self.run_dir, "Vault", remover=True
        )

        self.assertFalse(self.scratch.exists())
        self.assertTrue(destino.exists())
        self.assertEqual(destino, self.run_dir / "Vault_FIXED.sol")

    def test_conteudo_chega_intacto_ao_run_dir(self):
        self.scratch.write_text(self.conteudo, encoding="utf-8")

        destino = orchestrator.preservar_e_limpar_scratch(
            self.scratch, self.run_dir, "Vault", remover=True
        )

        self.assertEqual(destino.read_text(encoding="utf-8"), self.conteudo)

    def test_nao_apaga_copia_que_nao_e_da_rodada(self):
        self.scratch.write_text(self.conteudo, encoding="utf-8")

        orchestrator.preservar_e_limpar_scratch(
            self.scratch, self.run_dir, "Vault", remover=False
        )

        self.assertTrue(self.scratch.exists())
        self.assertTrue((self.run_dir / "Vault_FIXED.sol").exists())

    def test_sem_arquivo_nao_quebra_e_nao_inventa_copia(self):
        destino = orchestrator.preservar_e_limpar_scratch(
            self.scratch, self.run_dir, "Vault", remover=True
        )

        self.assertFalse(destino.exists())
        self.assertEqual(destino, self.run_dir / "Vault_FIXED.sol")


class TestPipelineChamaALimpeza(unittest.TestCase):
    """A limpeza tem de estar nos dois caminhos de saída, não só no feliz."""

    def test_limpeza_no_fim_do_loop_e_no_bloqueio_do_patch_guard(self):
        fonte = (ROOT / "agent" / "orchestrator.py").read_text(encoding="utf-8")
        self.assertEqual(fonte.count("preservar_e_limpar_scratch("), 3)

    def test_decide_a_posse_antes_de_escrever_o_arquivo(self):
        fonte = (ROOT / "agent" / "orchestrator.py").read_text(encoding="utf-8")
        posse = fonte.index("scratch_do_run = ")
        primeira_escrita = fonte.index("revisar_patch_rejeitado_por_guard(\n        pasta_output")
        self.assertLess(posse, primeira_escrita)


if __name__ == "__main__":
    unittest.main()
