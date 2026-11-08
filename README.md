# SignalProof Telemetry

[![CI](https://github.com/felipewatter/signalproof-telemetry/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/signalproof-telemetry/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab)
![License](https://img.shields.io/badge/license-MIT-blue)
![Status](https://img.shields.io/badge/status-v0.1.0-green)

**Validação de cobertura e continuidade de telemetria para operações de segurança, observabilidade e gestão de TI.** O SignalProof é uma ferramenta CLI **offline**, escrita em Python, para cruzar (1) o inventário de ativos críticos, (2) as pipelines efetivamente habilitadas no OpenTelemetry Collector e (3) os recibos de entrega de sinais emitidos pelo sistema de destino ou pela integração de observabilidade.

> **Problema:** um serviço pode ter um receiver configurado e mesmo assim não entregar logs, métricas ou traces ao destino esperado. Estar configurado não comprova entrega. O SignalProof distingue **rota declarada** de **recibo de entrega recente**, sem prometer uma garantia de ponta a ponta que os dados fornecidos não sustentem.

## Funcionalidades

| Recurso | Objetivo técnico |
|---|---|
| Reconstrução de pipelines | Interpretar `service.pipelines` de arquivos YAML/JSON do OpenTelemetry Collector |
| Rastreamento conservador de conectores | Resolver rotas de mesmo tipo de sinal passando por múltiplas pipelines |
| Cobertura por ativo | Conferir cada `(ativo, sinal, exporter)` contra o inventário de obrigatoriedades |
| Requisitos de processamento | Verificar processors obrigatórios e proibir processors indesejados nos caminhos analisados |
| Recibos verificáveis | Exigir timestamps timezone-aware, contagem mínima de eventos e pipeline de destino esperada |
| Autenticação de evidências | Assinar/verificar um conjunto canônico de recibos com HMAC-SHA256 |
| Controles de frescor | Detectar ausência, atraso, timestamp futuro e volume insuficiente |
| Gestão de mudanças | Comparar relatórios e classificar findings novos, resolvidos e persistentes |
| Automação DevSecOps | Saída human-readable, JSON, SARIF 2.1 e DOT; exit codes previsíveis |
| Operação offline | Nenhuma conexão com SIEM, Kubernetes, cloud, Prometheus ou Collector |

## O que o SignalProof **não** faz

- **Não** coleta telemetria em produção e **não** verifica o backend remotamente: os recibos são insumos fornecidos por integrações externas. HMAC autentica o arquivo quanto à chave compartilhada; **não** prova a honestidade do produtor, do relógio ou do destino.
- **Não** substitui OpenTelemetry Collector, SIEM, EDR ou detector de intrusão.
- **Não** interpreta semântica de `filter`, `transform`, `routing` ou expressões OTTL. Um processor presente é uma verificação estrutural, não uma prova de que todo evento passou.
- **Não** avalia a configuração final após expansão de variáveis de ambiente, overlays ou múltiplos `--config`; use a configuração consolidada e revisada em produção.
- **Não** certifica criptograficamente o Collector nem prova entrega de dados não instrumentados.
- Conectores que convertem sinais (ex.: traces → metrics) **não** são interpretados como rota de entrega do sinal original.

## Requisitos

- Python **3.10 ou superior**, Linux/macOS/Windows.
- `PyYAML>=6.0.3,<7` para parsing YAML seguro; demais funcionalidades dependem apenas da biblioteca padrão.
- Nenhum banco de dados, token de GitHub, servidor, Docker ou infraestrutura externa.

## Instalação

```bash
git clone https://github.com/felipewatter/signalproof-telemetry.git
cd signalproof-telemetry
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
signalproof --help
signalproof --version
```

Para executar testes:

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
python -m compileall -q src tests
```

## Início rápido: demonstração reproduzível

Os exemplos são **fictícios**, com timestamps fixos apenas para treinamento. `--now` permite reproduzir os resultados em qualquer data. Não use datas artificiais em monitoramento de produção.

```bash
# Linux/macOS
export SIGNALPROOF_HMAC_KEY='chave-de-teste-substituir-em-producao'

# Windows PowerShell:
# $env:SIGNALPROOF_HMAC_KEY='chave-de-teste-substituir-em-producao'

signalproof sign-evidence \
  --evidence examples/evidence.json \
  --output examples/evidence.signed.json \
  --key-env SIGNALPROOF_HMAC_KEY

signalproof scan \
  --collector examples/collector.yaml \
  --inventory examples/inventory.json \
  --evidence examples/evidence.signed.json \
  --key-env SIGNALPROOF_HMAC_KEY \
  --now 2026-11-08T14:02:00Z \
  --format human
```

**Saída esperada** (com os exemplos originais):

```text
SignalProof Telemetry | 2/2 verificações aprovadas
Cobertura observada: 100.0% | Falhas: 0
Evidência HMAC autenticada: sim
Nenhuma falha identificada nas premissas fornecidas.
```

É possível inspecionar **somente** a configuração, sem passar recibos, mas o resultado acusará `NO_EVIDENCE` — um caminho configurado não equivale a uma entrega comprovada.

## Comandos

| Comando | Uso |
|---|---|
| `signalproof scan` | Executa verificações de cobertura e entrega |
| `signalproof sign-evidence` | Assina recibos JSON usando chave de variável de ambiente |
| `signalproof graph` | Exporta grafo DOT da topologia lógica declarada |
| `signalproof diff` | Compara dois relatórios JSON |

### Scan com JSON/SARIF

```bash
signalproof scan \
  --collector examples/collector.yaml \
  --inventory examples/inventory.json \
  --evidence examples/evidence.signed.json \
  --key-env SIGNALPROOF_HMAC_KEY \
  --now 2026-11-08T14:02:00Z \
  --format json \
  --output scan.json

signalproof scan \
  --collector examples/collector.yaml \
  --inventory examples/inventory.json \
  --format sarif \
  --output scan.sarif
```

> O arquivo SARIF identifica findings com localizações lógicas. Não inventamos números de linha da configuração. `--format sarif` é útil para integração a ferramentas que aceitam SARIF, mas um upload ao GitHub Code Scanning exige permissões/configuração separadas.

### Grafo DOT e comparação de mudanças

```bash
signalproof graph --collector examples/collector.yaml --output collector.dot
# Opcional, se Graphviz estiver instalado:
# dot -Tsvg collector.dot -o collector.svg

signalproof diff --before scan-ontem.json --after scan-hoje.json --output delta.json
```

**Códigos de saída:** `0` = análise aprovada de acordo com `--fail-on` ou comando executado; `1` = finding no limiar configurado; `2` = entrada/configuração/E/S inválida. `--fail-on error` é o padrão; `warning`, `note` e `none` permitem ajustar o bloqueio. Findings de ativos `high` são `error`, `medium` são `warning`, `low` são `note`.

## Arquivos de entrada

### 1. Collector YAML

Uma configuração OpenTelemetry Collector contendo `receivers`, `processors`, `exporters`, `connectors` (opcional) e `service.pipelines`. Exemplo:

```yaml
receivers:
  otlp: {}
processors:
  memory_limiter: {}
  batch: {}
exporters:
  otlphttp/siem: {}
service:
  pipelines:
    logs/security:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlphttp/siem]
```

O SignalProof lê a estrutura; **não** usa credenciais ou endpoints presentes na configuração para fazer conexões. Por precaução, não versione arquivos reais contendo segredos.

### 2. Inventário JSON

Cada ativo declara quais sinais precisam ser comprovados, por qual receiver entram e quais exporters são esperados. Você pode exigir processors e proibir outros, com políticas por sinal.

```json
{
  "schema_version": 1,
  "defaults": {
    "max_age_seconds": 300,
    "min_events": 10,
    "max_clock_skew_seconds": 30,
    "require_signature": true
  },
  "assets": [
    {
      "id": "api-gateway",
      "criticality": "high",
      "signals": {
        "logs": {
          "receiver": "otlp",
          "exporters": ["otlphttp/siem"],
          "required_processors": ["memory_limiter", "batch"],
          "forbidden_processors": ["filter/drop"]
        }
      }
    }
  ]
}
```

### 3. Recibos JSON de entrega

Devem ser produzidos por um sistema confiável de observabilidade ou integração com acesso **ao destino real**, não inferidos do próprio Collector. Cada recibo identifica ativo, tipo de sinal, pipeline de saída, exporter, horário de observação, horário de recebimento e volume.

```json
{
  "schema_version": 1,
  "receipts": [
    {
      "asset": "api-gateway",
      "signal": "logs",
      "pipeline": "logs/security",
      "exporter": "otlphttp/siem",
      "observed_at": "2026-11-08T14:00:00Z",
      "received_at": "2026-11-08T14:00:05Z",
      "count": 37
    }
  ]
}
```

Os timestamps devem ter offset UTC ou timezone explícito. Os recibos são avaliados em relação à hora da análise. Valores de exemplo devem ser substituídos por dados recentes no uso real.

## Modelo de confiança HMAC

A assinatura é calculada sobre JSON canonizado (`sort_keys=True`, separadores compactos, Unicode em UTF-8 e campo `signature` excluído), usando HMAC-SHA256. O verificador usa comparação em tempo constante. A chave **nunca é passada por argumento de linha de comando** (que pode ser registrado no histórico do terminal e em listagens de processos); ela é lida por variável de ambiente com `--key-env`.

**Recomendação:** segredos longos, aleatórios, gerados por gerenciador de segredos; rotação planejada; produtor de recibos e verificador com acesso controlado. HMAC é autenticação simétrica, **não** assinatura digital assimétrica ou não repúdio. Quem conhece a chave pode produzir recibos arbitrários. Para confiança forte, proteja o coletor de evidências e confirme o relógio na origem. Não publique recibos reais.

Se `require_signature: true`, recibos não autenticados produzem `UNTRUSTED_EVIDENCE`. Se for `false`, recibos **não assinados** podem ser usados (cenário de laboratório), mas um recibo que já contenha uma assinatura inválida **nunca** é aceito como evidência.

## Taxonomia de findings

| Código | Significado |
|---|---|
| `NO_ROUTE` | Não existe rota ativa entre receiver e exporter esperado |
| `MISSING_PROCESSOR` | Processor necessário não aparece na rota |
| `FORBIDDEN_PROCESSOR` | Processor proibido aparece na rota |
| `NO_EVIDENCE` | Não foi fornecido arquivo de recibos |
| `UNTRUSTED_EVIDENCE` | Evidência presente mas sem autenticação exigida |
| `MISSING_RECEIPT` | Não há recibo para ativo/sinal/exporter |
| `ORPHAN_RECEIPT` | Recibo aponta para pipeline não alcançável ou inválida |
| `STALE_RECEIPT` | Última entrega válida está fora da janela de frescor |
| `LOW_VOLUME` | Quantidade de eventos inferior à exigida |
| `CLOCK_SKEW` | Ordem temporal incompatível ou timestamp futuro além da tolerância |

## Arquitetura

```text
Inventário JSON ──┐
Collector YAML ───┼──▶ Validação estrita ──▶ Grafo de rotas ──────┐
Recibos JSON ─────┘                     ┌──▶ Verificação HMAC ───────┤
                                       └──▶ Regras de frescor ───────┤
                                                        ┌───────────┘
                                                        ▼
                                                Motor de cobertura
                                                        │
                                              Findings + fingerprints
                                                        │
                                                 JSON / SARIF / DOT
```

Consulte [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) e [docs/SCHEMAS.md](docs/SCHEMAS.md).

## Segurança e privacidade

- Processamento totalmente local e **offline**, sem chamadas de rede, execução de shell ou importação dinâmica de plugins.
- YAML lido por `SafeLoader` especializado que rejeita chaves duplicadas, tags de objeto Python e aliases compartilhados/cíclicos.
- Limites defensivos de bytes, profundidade, quantidade de elementos, ativos, recibos e complexidade do grafo.
- Relatórios gravados por arquivo temporário com substituição atômica, permissões restritas em plataformas compatíveis e recusa de destinos que sejam symlinks. Não é uma defesa completa contra adversário local concorrente com controle do diretório.
- Não versionar tokens, endpoints confidenciais, nomes de ativos reais ou recibos de produção em issues ou PRs.
- CI em GitHub Actions com permissões mínimas, ações fixadas por SHA e matriz de OS/Python. Release **manual e bloqueado pelo resultado do CI** (ver [docs/RELEASE_PROCESS.md](docs/RELEASE_PROCESS.md)).

## Limites operacionais

- Até 2 MB por arquivo de entrada, 5.000 ativos, 20.000 recibos, 500 pipelines e caminhos limitados; exceder limites causa erro explícito.
- Matching exato de IDs e nomes (case-sensitive).
- O score de cobertura é a fração de pares `(ativo, sinal, exporter)` aprovados, **não** um indicador formal de maturidade SOC, eficácia da detecção ou conformidade regulatória.
- Análise de uma única configuração consolidada do Collector. Não interpreta templating, `include`, Helm, Kubernetes ConfigMaps externos ou variáveis não resolvidas.

## Roadmap (não implementado em v0.1.0)

- Importadores de recibos de APIs de SIEM, Prometheus e backends OTLP, com credenciais read-only.
- Suporte a bundles de configurações Collector e `confmap` resolvido.
- Perfil declarativo de conectores que convertem sinais, com validação de fluxo por tipo.
- Evidências assinadas por chave pública, manifests versionados e inventário CMDB.
- Testes sintéticos controlados ponta a ponta (exigem ambiente isolado e consentimento explícito).

## Referências técnicas

- [OpenTelemetry Collector — configuração](https://opentelemetry.io/docs/collector/configuration/)
- [OpenTelemetry Collector — connectors](https://opentelemetry.io/docs/collector/components/)
- [Priority logs for SIEM ingestion — ASD/ACSC, 2025](https://www.cyber.gov.au/publication/priority-logs-for-siem-ingestion-practitioner-guidance)
- [OWASP — Logging and Monitoring](https://owasp.github.io/DevSecOpsGuideline/2-Process/2-7-Operate/2-7-2-Logging-and-Monitoring/)
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

## Colaboração e licença

Pull requests bem fundamentados e reproduções com dados sintéticos são bem-vindos. Veja [CONTRIBUTING.md](CONTRIBUTING.md) e [SECURITY.md](SECURITY.md). Licença **MIT** — consulte [LICENSE](LICENSE).

**Autor:** Felipe Watter · GitHub [@felipewatter](https://github.com/felipewatter)
