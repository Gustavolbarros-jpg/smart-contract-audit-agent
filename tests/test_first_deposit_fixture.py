"""Guarda o fixture que mostra o limite do catálogo.

O par `Pool.sol` / `PoolFixed.sol` só prova alguma coisa enquanto a **única** diferença
funcional entre os dois for o argumento de arredondamento. Se alguém editar um dos dois,
a conclusão registrada no README (oráculo separa, Slither não) deixa de valer em silêncio.
Este teste não roda o Prover — ele guarda a premissa.
"""

import re
import unittest
from pathlib import Path

FIX = Path(__file__).resolve().parents[1] / "tests/fixtures/certora/first_deposit_inflation"


def corpo(nome: str) -> str:
    return (FIX / nome).read_text(encoding="utf-8")


def sem_comentarios(texto: str) -> str:
    sem = re.sub(r"//[^\n]*", "", texto)
    return "\n".join(l.rstrip() for l in sem.splitlines() if l.strip())


class TestFixtureFirstDeposit(unittest.TestCase):
    def test_os_quatro_arquivos_existem(self):
        for nome in ("Pool.sol", "PoolFixed.sol", "inflation.spec", "README.md"):
            self.assertTrue((FIX / nome).exists(), nome)

    def test_a_unica_diferenca_funcional_e_o_arredondamento(self):
        vul = sem_comentarios(corpo("Pool.sol")).replace("contract Pool ", "contract X ")
        fix = sem_comentarios(corpo("PoolFixed.sol")).replace("contract PoolFixed ", "contract X ")
        self.assertIn("totalShares, false)", vul)
        self.assertIn("totalShares, true)", fix)
        self.assertEqual(vul.replace("totalShares, false)", "ROUND"),
                         fix.replace("totalShares, true)", "ROUND"))

    def test_a_spec_sumariza_o_token_em_vez_de_ligar(self):
        spec = corpo("inflation.spec")
        self.assertIn("_.balanceOf(address) external => NONDET", spec)
        self.assertIn("_.transferFrom(address, address, uint256) external => ALWAYS(true)", spec)

    def test_always_nao_leva_expect(self):
        """`=> ALWAYS(true) expect bool;` é erro de sintaxe em CVL; já custou uma rodada."""
        spec = corpo("inflation.spec")
        self.assertNotIn("ALWAYS(true) expect", spec)

    def test_a_regra_fala_de_shares_e_nao_de_um_detector(self):
        spec = corpo("inflation.spec")
        self.assertIn("rule deposit_never_mints_zero_shares", spec)
        for nome_de_detector in ("slither", "divide-before-multiply", "incorrect-equality"):
            self.assertNotIn(nome_de_detector, spec)

    def test_o_readme_registra_a_ressalva_do_que_nao_foi_provado(self):
        readme = corpo("README.md")
        self.assertIn("not a proof", readme.lower().replace("*", ""))
        self.assertIn("minimum liquidity", readme.lower())


if __name__ == "__main__":
    unittest.main()
