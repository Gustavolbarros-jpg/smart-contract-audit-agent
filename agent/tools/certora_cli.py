"""
agent/tools/certora_cli.py
Ferramenta para executar a Verificação Formal via Certora Prover.
"""
import subprocess
import os

def run_certora(contract_path: str, spec_path: str, output_dir: str) -> str:
    """Roda o Certora Prover e retorna o output bruto (stdout + stderr)."""
    if not os.path.exists(contract_path):
        raise FileNotFoundError(f"Contrato não encontrado: {contract_path}")
    if not os.path.exists(spec_path):
        raise FileNotFoundError(f"Spec CVL não encontrado: {spec_path}")
    
    # Extrai o nome do contrato (ex: "DeFiVault") a partir do caminho do arquivo
    contract_name = os.path.basename(contract_path).split('.')[0]
    json_output_path = os.path.join(output_dir, "certora_result.json")
    
    cmd = [
        "certoraRun", 
        contract_path, 
        "--verify", f"{contract_name}:{spec_path}",
        "--solc", "solc",
        "--msg", "Agent_Automated_Run",
        "--json_output", json_output_path
    ]
    
    try:
        print(f"🔬 [Certora] Iniciando Prover para {contract_name} com {os.path.basename(spec_path)}...")
        print("⏳ Isso pode demorar alguns minutos...")
        
        # Certora precisa de um timeout longo (10 minutos)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        # Juntamos stdout e stderr para o LLM ter todo o contexto se der erro de sintaxe
        output_completo = result.stdout + "\n" + result.stderr
        return output_completo
        
    except subprocess.TimeoutExpired:
        raise TimeoutError("Certora abortado: excedeu o limite de 10 minutos de prova.")
    except FileNotFoundError:
        raise RuntimeError("O comando 'certoraRun' não foi encontrado. O Certora CLI está instalado?")