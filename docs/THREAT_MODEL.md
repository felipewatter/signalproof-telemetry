# Modelo de ameaças (v0.1.0)

## Ativos e fronteiras de confiança

- Entradas não confiáveis: inventário, configuração de Collector, recibos e relatórios de terceiros.
- Segredo: chave HMAC injetada por variável de ambiente.
- Saídas: arquivos JSON/SARIF/DOT e logs da CLI.
- Contexto: execução local por operador ou runner CI com permissões de leitura do workspace.

| Ameaça | Tratamento implementado | Limite residual |
|---|---|---|
| YAML perigoso | SafeLoader, recusa de tags Python e chaves duplicadas | YAML extremamente adversarial ainda deve ser processado em runtime isolado |
| Explosão de entrada | Limites de tamanho/profundidade, caminhos, itens e iterações do grafo | Custos de CPU/memória não são contratualmente garantidos para todos os cenários |
| JSON ambíguo | Rejeita chaves duplicadas e NaN/Infinity | Tipos extras desconhecidos podem ser aceitos, porém ignorados |
| Recibos forjados | Autenticação HMAC opcional/obrigatória por política | Qualquer detentor da chave pode forjar eventos; HMAC não prova recepção verdadeira |
| Falso positivo de integridade | Assinatura incorreta faz a análise falhar explicitamente | O produtor pode ter sido comprometido antes de assinar |
| Replay de recibos | Janela de frescor e validação temporal | Replay recente dentro da janela é possível; não há nonce ou sequência |
| Uso de relógio malicioso | Validação de ordem e tolerância de skew | A CLI confia no relógio configurado pelo executor (`--now`) |
| Falhas de roteamento | Percurso explícito do grafo, receipts vinculados à última pipeline | Configuração declarada pode diferir do runtime efetivo |
| Escrita de saída | Arquivo temporário, fsync, chmod 0600 onde aplicável, troca atômica | Pasta controlada por atacante permite corridas de symlinks; usar pasta segura |
| Vazamento de segredos | Sem logs de valores HMAC e sem transmissão externa | Config do Collector pode conter credenciais; NÃO enviar em issues |
| Dependência comprometida | PyYAML com intervalo delimitado, CI e Dependabot | É necessário revisar advisories e atualizações antes de cada release |

## Abusos e políticas operacionais

A ferramenta é exclusivamente defensiva. Não acessa sistemas remotos nem executa comandos de exploração. Não foi projetada para forjar telemetria nem criar evidências de auditoria fictícias em produção. O arquivo `examples/evidence.json` é deliberadamente sintético e possui datas fixas.

## Divulgação responsável

Consulte `SECURITY.md`. Não publique provas de conceito contendo dados de clientes, chaves de API, hostnames internos ou evidências que exponham uma arquitetura real.
