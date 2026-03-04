"""
agent/orchestrator.py
O orquestrador principal do nosso Pipeline de Auditoria Multi-Agentes.
"""
import os
import json
from pathlib import Path

# Nossas Ferramentas (Mãos)
from tools.slither_cli import run_slither
from tools.certora_cli import run_certora

# Nossa Inteligência (Cérebro)
from llm.client import chamar_ia_json
from llm.schemas import (
    RelatorioSlitherNormalizado, 
    ValidacaoSpec, 
    CodigoGerado, 
    AnaliseCertora
)

# Nossas Regras (Boca)
from prompts import system_prompts as sp

def salvar_arquivo(caminho: str, conteudo: str):
    """Utilitário para salvar os outputs para podermos visualizar depois."""
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(conteudo)
    print(f"💾 Salvo: {caminho}")

def executar_pipeline(contract_path: str):
    print("\n" + "="*60)
    print("🚀 INICIANDO AUDIT AGENT PIPELINE")
    print("="*60)

    # Verifica se o contrato existe
    if not os.path.exists(contract_path):
        print(f"❌ Erro: Contrato não encontrado em {contract_path}")
        return
    
    with open(contract_path, "r", encoding="utf-8") as f:
        contract_source = f.read()

    nome_contrato = Path(contract_path).stem
    pasta_output = Path("agent_outputs")
    pasta_output.mkdir(exist_ok=True)

    # ---------------------------------------------------------
    # ETAPA 1: Slither -> Normalização
    # ---------------------------------------------------------
    print("\n▶️ ETAPA 1: Executando Slither e Normalizando...")
    slither_raw = run_slither(contract_path)
    
    prompt_usuario_e1 = f"DADOS SLITHER:\n{json.dumps(slither_raw)}\n\nCONTRATO:\n{contract_source}"
    vulns_normalizadas = chamar_ia_json(sp.PROMPT_ETAPA1_NORMALIZAR, prompt_usuario_e1, RelatorioSlitherNormalizado)
    
    salvar_arquivo(pasta_output / "etapa1_vulns.json", json.dumps(vulns_normalizadas, indent=2))

    # ---------------------------------------------------------
    # ETAPA 3: Gerar Spec CVL
    # ---------------------------------------------------------
    print("\n▶️ ETAPA 3: Gerando Especificação Formal (.spec)...")
    prompt_usuario_e3 = f"VULNERABILIDADES:\n{json.dumps(vulns_normalizadas)}\n\nCONTRATO:\n{contract_source}"
    spec_gerado = chamar_ia_json(sp.PROMPT_ETAPA3_GERAR_SPEC, prompt_usuario_e3, CodigoGerado)
    spec_cvl = spec_gerado["codigo"]
    
    salvar_arquivo(pasta_output / "etapa3_raw.spec", spec_cvl)

    # ---------------------------------------------------------
    # ETAPA 2: Validar Spec
    # ---------------------------------------------------------
    print("\n▶️ ETAPA 2: Validando sintaxe do .spec...")
    prompt_usuario_e2 = f"SPEC GERADO:\n{spec_cvl}\n\nCONTRATO:\n{contract_source}"
    spec_validado_json = chamar_ia_json(sp.PROMPT_ETAPA2_VALIDAR_SPEC, prompt_usuario_e2, ValidacaoSpec)
    
    if not spec_validado_json["valido"]:
        print(f"⚠️ Erros encontrados no Spec: {spec_validado_json['erros']}")
        print("🔧 Agente aplicou correções automáticas.")
    
    spec_final = spec_validado_json["codigo_corrigido"]
    caminho_spec_final = pasta_output / f"{nome_contrato}.spec"
    salvar_arquivo(caminho_spec_final, spec_final)

    # ---------------------------------------------------------
    # EXECUÇÃO: Certora Prover
    # ---------------------------------------------------------
    print("\n▶️ CERTORA PROVER: Verificando as propriedades...")
    certora_output = run_certora(contract_path, str(caminho_spec_final), str(pasta_output))
    salvar_arquivo(pasta_output / "certora_raw_log.txt", certora_output)

    # ---------------------------------------------------------
    # ETAPA 4: Analisar Resultado do Certora
    # ---------------------------------------------------------
    print("\n▶️ ETAPA 4: Analisando o log do Certora (Identificando Falsos Positivos)...")
    prompt_usuario_e4 = f"LOG CERTORA:\n{certora_output}\n\nVULNERABILIDADES:\n{json.dumps(vulns_normalizadas)}"
    analise_final = chamar_ia_json(sp.PROMPT_ETAPA4_ANALISAR, prompt_usuario_e4, AnaliseCertora)
    
    salvar_arquivo(pasta_output / "etapa4_analise.json", json.dumps(analise_final, indent=2))

    # ---------------------------------------------------------
    # ETAPA 5: Correção do Contrato
    # ---------------------------------------------------------
    print("\n▶️ ETAPA 5: Corrigindo o Contrato Inteligente...")
    # Filtramos apenas as confirmadas para enviar ao Corretor
    vulns_confirmadas = [v for v in analise_final["analises"] if v["status"] in ["confirmed", "confirmed_static"]]
    
    if not vulns_confirmadas:
        print("✅ Nenhuma vulnerabilidade confirmada! O contrato já está seguro.")
    else:
        prompt_usuario_e5 = f"CONTRATO ORIGINAL:\n{contract_source}\n\nCONFIRMADAS:\n{json.dumps(vulns_confirmadas)}"
        contrato_corrigido = chamar_ia_json(sp.PROMPT_ETAPA5_CORRIGIR, prompt_usuario_e5, CodigoGerado)
        
        caminho_fix = pasta_output / f"{nome_contrato}_FIXED.sol"
        salvar_arquivo(caminho_fix, contrato_corrigido["codigo"])
        print(f"🎉 Contrato corrigido gerado com sucesso em: {caminho_fix}")

    print("\n" + "="*60)
    print("✨ PIPELINE CONCLUÍDO COM SUCESSO ✨")
    print("="*60)

if __name__ == "__main__":
    # Teste rápido: aponte para um dos contratos vulneráveis que você tem
    # Exemplo (ajuste o caminho de acordo com o seu):
    caminho_teste = "../smart-audt/contracts/DeFiVault.sol" 
    executar_pipeline(caminho_teste)