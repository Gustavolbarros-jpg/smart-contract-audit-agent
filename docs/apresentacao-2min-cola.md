# Cola — 2 minutos (sem decorar, só pra não perder o fio)

1. **Oi** — nome, CIn/UFPE, tema: segurança de contratos inteligentes com
   IA + verificação formal.
2. **Problema** — contrato com falha = dinheiro explorado; otimizar gás
   pode quebrar o comportamento original.
3. **Solução** — pipeline automática: Slither → LLM → spec CVL → Certora →
   diagnóstico → correção → revalidação.
4. **[roda o script]** — narra por cima:
   - Slither acha os problemas.
   - Certora *prova matematicamente* (não só testa exemplos) → contraexemplo.
   - IA diagnostica a causa e corrige.
   - Corrigido volta pro Certora — só fica bom se **verificar** de novo.
5. **Caso: DeFiVault** — controle de acesso, endereço inválido,
   transferência insegura, reentrância → 5/5 corrigidos.
6. **Fecha** — diferencial é IA que gera + prova formal que confirma; não
   substitui auditoria humana, reduz trabalho repetitivo. Obrigado!

Comando do demo:

```bash
python3 docs/demo_replay_defivault.py
```
