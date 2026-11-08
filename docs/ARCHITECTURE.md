# Arquitetura técnica

## Separação de responsabilidades

- `io.py`: leitura UTF-8, validação JSON/YAML estrita, limites de recursos e escrita atômica.
- `model.py`: validações de schemas, datas e criticidade; fingerprints de findings.
- `graph.py`: criação do grafo de pipelines do Collector e enumeração limitada de caminhos de sinal.
- `evidence.py`: canonização de payload, assinatura e autenticação HMAC-SHA256.
- `engine.py`: cruzamento de rotas esperadas e recibos, atribuição de severidade, score e diff.
- `report.py`: saída humana, JSON, SARIF 2.1.
- `cli.py`: parsing de argumentos, exit codes e comandos.

## Semântica do grafo

Nomes de pipelines OpenTelemetry seguem `<sinal>` ou `<sinal>/<nome>`, onde sinal é logs, metrics ou traces. Um receiver e exporter devem aparecer **na mesma pipeline** ou estar ligados por um connector declarado como exporter da pipeline anterior e receiver da próxima. Cada salto precisa manter o mesmo sinal original. A busca rejeita ciclos e tem limites explícitos de tamanho.

A ferramenta sinaliza como finding qualquer caminho que omita um processor obrigatório ou contenha um processor proibido, mesmo se houver caminhos alternativos válidos. Essa abordagem conservadora evita considerar o serviço plenamente aprovado quando há fan-out para um caminho sem os controles exigidos. **Limitação:** a ferramenta não executa as regras de cada processor; ela avalia apenas sua presença estrutural.

Para comprovar o destino, o recibo deve informar a pipeline de saída de uma rota válida; o nome da pipeline intermediária não basta. Um recibo que aponta para uma pipeline desconectada é `ORPHAN_RECEIPT`.

## Mecanismo de cobertura

1. Valida todos os insumos e seus limites.
2. Verifica a assinatura das evidências, se fornecida, antes de tratar recibos como verdadeiros.
3. Calcula caminhos por ativo/sinal/exporter.
4. Verifica processors de cada caminho e identifica alternativas válidas.
5. Compara recibos à configuração e verifica frescor e volume.
6. Gera uma decisão por par `(ativo, sinal, exporter)` e findings determinísticos.
7. Calcula `coverage_percent = 100 * checks_passed / checks_total`.

## Decisões de projeto

- **Sem rede e sem banco:** funcionamento reproduzível, auditável e isolado.
- **HMAC por arquivo de evidências:** flexível para integração externa, porém simétrico; autenticidade depende de confiança no produtor.
- **Chaves por variável de ambiente:** reduz exposição em argumentos e logs, mas não substitui cofre de segredos.
- **SARIF com localizações lógicas:** não inventa posições em arquivos de origem.
- **Fail thresholds:** operação em pipelines de CI e gestão de exceções por criticidade.
- **Parsers defensivos:** evita duplicatas e tags executáveis em entradas locais não confiáveis.

## Não objetivos

Não valida ACLs da rede, roteamento IP, segurança de segredos no YAML, propriedades OTTL, retenção de logs, integridade dos eventos ou metadados de ativos que não foram explicitamente declarados. Não deve ser apresentado como auditoria completa de observabilidade ou segurança.
