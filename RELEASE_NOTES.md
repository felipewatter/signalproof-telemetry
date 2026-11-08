# SignalProof Telemetry v0.1.0

Primeira versão pública da ferramenta de verificação **offline** de cobertura e continuidade de telemetria.

**Inclui:** leitura de pipelines OpenTelemetry Collector, enumeração de rotas com connectors de mesmo sinal, validação de processor e de recibos HMAC-SHA256, checagens de frescor/volume, relatórios JSON/SARIF/DOT e comparação de findings.

**Segurança:** entradas limitadas e parsers restritos; nenhuma conexão de rede; chave HMAC somente via variável de ambiente; código e testes revisados.

**Limitações:** os recibos são fornecidos por integração externa; HMAC não prova a realidade do evento; interpretação de processors é estrutural e não semântica; não há validação de Collector em execução.

Antes de usar, consulte README.md, docs/THREAT_MODEL.md, SECURITY.md e LICENSE. Artefatos devem ser publicados somente após CI aprovado no mesmo commit.
