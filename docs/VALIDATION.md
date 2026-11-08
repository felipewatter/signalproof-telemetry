# Validação de qualidade — versão candidata v0.1.0

Conjunto de testes Pytest desenvolvido com cenários positivos, negativos e adversariais, incluindo:

- rotas OTel com connectors, processors esperados e proibidos;
- comportamento conservador entre tipos de sinais;
- assinatura HMAC correta, ausente, incorreta e alteração posterior;
- frescor e timestamp futuro, volume mínimo e recibos órfãos;
- entradas malformadas, schema inválido e duplicatas;
- YAML com tags Python, aliases compartilhados/cíclicos e limites de tamanho;
- escrita atômica, destinos symlink, SARIF, DOT, CLI e comparações.

## Resultados da validação local — 2026-11-08

- **89 testes Pytest aprovados** após correção de regressão de múltiplas pipelines.
- `python -m compileall -q src tests`: aprovado.
- `python -m pip wheel . --no-deps --no-build-isolation`: aprovado.
- Instalação do wheel em diretório isolado: aprovada.
- `python -m signalproof --version`: `signalproof 0.1.0`.
- `sign-evidence`, `scan`, `graph` com exemplos: aprovados (2/2 pares de telemetria).
- YAML dos workflows interpretado e conferido; **Actions remoto ainda não executado**, pois depende de publicação do repositório após autorização.

**Escopo da validação:** executado localmente em Linux/Python 3.11+ do ambiente de construção. A matriz remota Windows/macOS/Linux com Python 3.10 a 3.13 está apenas preparada, não atestada até o GitHub Actions rodar. Não foi executado teste em SIEM real, redes de produção ou infraestrutura de terceiros.

