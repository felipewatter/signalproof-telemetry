# Contratos de entrada e saída (v1)

Todos os dados JSON usam UTF-8 e rejeitam chaves repetidas e NaN/Infinity. Os documentos devem ter raiz de objeto. Nomes e identificadores têm até 180 caracteres, sem caracteres de controle. Datas exigem ISO 8601 com timezone.

## Inventory

`schema_version`: inteiro `1`.

`defaults`: objeto opcional com:

- `max_age_seconds`: inteiro positivo, padrão 300.
- `min_events`: inteiro positivo, padrão 1.
- `max_clock_skew_seconds`: inteiro não-negativo, padrão 60.
- `require_signature`: booleano, padrão false. Para produção, habilitar.

`assets`: lista de 1 a 5.000 ativos únicos:

- `id`: string única.
- `criticality`: `high`, `medium`, `low`.
- `signals`: mapa com pelo menos uma chave de `logs`, `metrics`, `traces`. Cada sinal define:
  - `receiver`: identificador do receiver no Collector.
  - `exporters`: lista não vazia e sem duplicatas de destinos.
  - `required_processors`: lista opcional de processors.
  - `forbidden_processors`: lista opcional de processors.
  - `max_age_seconds`, `min_events`: overrides opcionais.

## Evidence

`schema_version`: inteiro `1`.

`receipts`: lista de até 20.000 objetos com:

- `asset`, `signal`, `exporter`, `pipeline`: identificação exata.
- `observed_at`: horário observado na origem em ISO 8601 com offset.
- `received_at`: horário confirmado no destino em ISO 8601 com offset.
- `count`: inteiro entre 0 e 100 milhões.

`signature`, opcional: `{ "alg": "HMAC-SHA256", "value": "<hex minúsculo de 64 caracteres>" }`.

**Canonização:** retira somente o campo de topo `signature`, faz dump JSON ordenado, compacto, Unicode em UTF-8 sem NaN, e HMAC-SHA256. Não é RFC 8785/JCS e não garante compatibilidade com bibliotecas que usam outro processo de canonização.

## JSON Report

- `tool`: `signalproof-telemetry`.
- `schema_version`: 1.
- `generated_at`: horário ISO UTC.
- `evidence_authenticated`: booleano.
- `summary`: checks, passed, failed, coverage_percent.
- `checks`: decisões individuais com asset, criticality, signal, exporter, status, reachable_pipelines, finding_codes.
- `findings`: objetos com code, severity, asset, signal, exporter, message, pipeline e fingerprint.

O fingerprint é `SHA-256` do array JSON canônico `[code, asset, signal, exporter, pipeline]` (UTF-8, sem espaços extras). Isso evita colisões simples de separador e possibilita comparar relatórios sem expor detalhes do texto da mensagem. O fingerprint não é autenticação de dados e não deve ser usado como controle de acesso.
