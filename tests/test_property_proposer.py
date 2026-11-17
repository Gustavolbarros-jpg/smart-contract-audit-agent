"""O propositor de propriedades: do fonte direto para CVL, sem detector no caminho.

O que o pipeline formaliza hoje é indexado por achado do Slither, e as 6 classes
`formalizable` do catálogo são todas simples. Este módulo é a outra rota: reconhece
*formas de contabilidade* no fonte e escreve a propriedade que qualquer implementação
correta daquela forma satisfaz.

Dois erros custam caro e por isso têm teste próprio: emitir um getter com o tipo de
retorno errado (o Prover rejeita a spec inteira, não só a linha) e descartar um parâmetro
em silêncio (a chamada gerada sai com aridade errada).
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from core.property_proposer import (  # noqa: E402
    build_spec,
    contract_like_names,
    propose,
    public_state,
    _params,
)

POOL = ROOT / "tests/fixtures/certora/first_deposit_inflation/Pool.sol"

COFRE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract Cofre {
    mapping(address => uint256) public saldos;
    mapping(address => bool) public liberado;
    uint256 public total;
    address public dono;

    modifier soDono() {
        require(msg.sender == dono, "nao e o dono");
        _;
    }

    function depositar() external payable {
        saldos[msg.sender] += msg.value;
        total += msg.value;
    }

    function sacar(uint256 quantia) external {
        saldos[msg.sender] -= quantia;
        total -= quantia;
    }

    function liberar(address quem) external soDono {
        liberado[quem] = true;
    }

    function ver(address quem) external view returns (uint256) {
        return saldos[quem];
    }
}
"""


class TestLeituraDeParametros(unittest.TestCase):
    def test_address_payable_nao_e_descartado(self):
        sig = "function emergencyWithdraw(address payable to, uint256 amount) external"
        self.assertEqual(_params(sig), [("address", "to"), ("uint256", "amount")])

    def test_tipo_de_interface_vira_address(self):
        sig = "function pull(IERC20 token, uint256 a) external"
        self.assertEqual(_params(sig, frozenset({"IERC20"})), [("address", "token"), ("uint256", "a")])

    def test_tipo_desconhecido_derruba_a_lista_inteira(self):
        """Melhor nenhuma propriedade do que uma chamada com assinatura errada."""
        sig = "function k(MinhaStruct s, uint256 a) external"
        self.assertEqual(_params(sig, frozenset()), [])

    def test_localizacao_de_dados_e_ignorada(self):
        sig = "function f(bytes calldata data, address to) external"
        self.assertEqual(_params(sig), [("bytes", "data"), ("address", "to")])

    def test_sem_parametros(self):
        self.assertEqual(_params("function g() external"), [])


class TestEstadoPublico(unittest.TestCase):
    def test_mapping_e_escalar_com_os_tipos_certos(self):
        d = public_state(COFRE)
        self.assertEqual(d["saldos"], ("address", "uint256"))
        self.assertEqual(d["liberado"], ("address", "bool"))
        self.assertEqual(d["total"], ("", "uint256"))
        self.assertEqual(d["dono"], ("", "address"))

    def test_nomes_de_contrato_sao_reconhecidos(self):
        self.assertIn("Cofre", contract_like_names(COFRE))


class TestPropostas(unittest.TestCase):
    def nomes(self, fonte):
        return [c.name for c in propose(fonte)]

    def test_credito_debito_e_portao_saem_do_cofre(self):
        nomes = self.nomes(COFRE)
        self.assertIn("depositar_never_credits_zero", nomes)
        self.assertIn("depositar_credits_total_by_the_same_amount", nomes)
        self.assertIn("sacar_debits_exactly", nomes)
        self.assertIn("sacar_debits_total_by_the_same_amount", nomes)
        self.assertIn("only_dono_calls_liberar", nomes)

    def test_funcao_view_nao_vira_propriedade(self):
        self.assertNotIn("ver_debits_exactly", self.nomes(COFRE))

    def test_mapping_nao_numerico_nao_gera_contabilidade(self):
        """`liberado` é bool: creditar/debitar não quer dizer nada ali."""
        for nome in self.nomes(COFRE):
            self.assertNotIn("liberar_never_credits_zero", nome)

    def test_a_propriedade_do_first_deposit_sai_do_contrato_do_corpus(self):
        nomes = self.nomes(POOL.read_text(encoding="utf-8"))
        self.assertIn("deposit_never_credits_zero", nomes)
        self.assertIn("withdraw_debits_exactly", nomes)

    def test_nao_repete_propriedade(self):
        nomes = self.nomes(COFRE)
        self.assertEqual(len(nomes), len(set(nomes)))

    def test_toda_proposta_diz_por_que(self):
        for c in propose(COFRE):
            self.assertTrue(c.rationale.strip())
            self.assertTrue(c.cvl.startswith("rule "))


class TestMontagemDaSpec(unittest.TestCase):
    def test_o_getter_de_address_nao_sai_como_uint256(self):
        """`function dono() returns (uint256)` faz o Prover rejeitar a spec inteira."""
        spec = build_spec(COFRE, propose(COFRE))
        self.assertIn("function dono() external returns (address) envfree;", spec)
        self.assertIn("function saldos(address) external returns (uint256) envfree;", spec)
        self.assertNotIn("function dono() external returns (uint256)", spec)

    def test_sumariza_o_token_so_quando_o_contrato_o_chama(self):
        pool = POOL.read_text(encoding="utf-8")
        self.assertIn("_.balanceOf(address) external => NONDET", build_spec(pool, propose(pool)))
        self.assertNotIn("_.balanceOf", build_spec(COFRE, propose(COFRE)))

    def test_always_sem_expect(self):
        pool = POOL.read_text(encoding="utf-8")
        spec = build_spec(pool, propose(pool))
        self.assertIn("=> ALWAYS(true);", spec)
        self.assertNotIn("ALWAYS(true) expect", spec)

    def test_a_spec_tem_methods_e_todas_as_regras(self):
        cands = propose(COFRE)
        spec = build_spec(COFRE, cands)
        self.assertTrue(spec.startswith("methods {"))
        for c in cands:
            self.assertIn(f"rule {c.name}", spec)


if __name__ == "__main__":
    unittest.main()


class TestCLI(unittest.TestCase):
    """A CLI é o que torna o propositor utilizável; um import quebrado passa despercebido."""

    def test_roda_e_grava_a_spec(self):
        import tempfile

        sys.path.insert(0, str(ROOT / "agent"))
        import propose_properties

        with tempfile.TemporaryDirectory() as tmp:
            destino = Path(tmp) / "saida.spec"
            codigo = propose_properties.main([str(POOL), "--contract-name", "Pool", "--out", str(destino)])
            self.assertEqual(codigo, 0)
            spec = destino.read_text(encoding="utf-8")
            self.assertIn("rule deposit_never_credits_zero", spec)
            self.assertIn("methods {", spec)

    def test_contrato_inexistente_devolve_erro(self):
        import propose_properties

        self.assertEqual(propose_properties.main(["/nao/existe/X.sol"]), 1)


class TestGuardsDoProprioContrato(unittest.TestCase):
    """Todo `require` é um invariante que o autor escreveu; a regra é que violá-lo reverta.

    É a forma que cobre teto, lock, whitelist, pausa e endereço zero sem uma regra por
    assunto. Traduzir errado custa caro dos dois lados: uma condição mal traduzida vira
    regra que falha em código correto, e recusar demais deixa o contrato sem propriedade.
    """

    DECLS = {
        "balances": ("address", "uint256"),
        "whitelist": ("address", "bool"),
        "lastWithdraw": ("address", "uint256"),
        "lockPeriod": ("", "uint256"),
        "maxWithdraw": ("", "uint256"),
        "paused": ("", "bool"),
        "owner": ("", "address"),
    }
    PARAMS = {"amount": "uint256", "to": "address"}

    def traduz(self, cond):
        from core.property_proposer import translate_condition

        return translate_condition(cond, self.PARAMS, self.DECLS)

    def test_estado_publico_vira_chamada_de_getter(self):
        self.assertEqual(self.traduz("amount <= maxWithdraw"), "amount <= maxWithdraw()")
        self.assertEqual(self.traduz("!paused"), "!paused()")

    def test_mapping_indexado_por_msg_sender(self):
        self.assertEqual(self.traduz("balances[msg.sender] >= amount"), "balances(e.msg.sender) >= amount")
        self.assertEqual(self.traduz("whitelist[msg.sender]"), "whitelist(e.msg.sender)")

    def test_janela_de_tempo_com_soma(self):
        self.assertEqual(
            self.traduz("block.timestamp >= lastWithdraw[msg.sender] + lockPeriod"),
            "e.block.timestamp >= lastWithdraw(e.msg.sender) + lockPeriod()",
        )

    def test_endereco_zero(self):
        self.assertEqual(self.traduz("to != address(0)"), "to != 0")

    def test_variavel_local_e_recusada(self):
        """`success` é local: traduzir viraria uma regra que falha em código correto."""
        self.assertIsNone(self.traduz("success"))

    def test_chamada_desconhecida_e_recusada(self):
        self.assertIsNone(self.traduz("foo(bar) > 0"))

    def test_address_this_e_recusado(self):
        self.assertIsNone(self.traduz("amount <= address(this).balance"))

    def test_guard_de_identidade_nao_duplica_a_regra_de_portao(self):
        nomes = [c.name for c in propose(COFRE)]
        self.assertIn("only_dono_calls_liberar", nomes)
        self.assertNotIn("liberar_enforces_msg_sender_dono", nomes)

    def test_o_guard_vira_regra_de_reversao(self):
        fonte = COFRE.replace(
            "function sacar(uint256 quantia) external {",
            "function sacar(uint256 quantia) external {\n        require(quantia <= total, \"acima do total\");",
        )
        regra = next(c for c in propose(fonte) if c.shape == "guard")
        self.assertIn("require !(quantia <= total());", regra.cvl)
        self.assertIn("@withrevert", regra.cvl)
        self.assertIn("assert lastReverted", regra.cvl)
