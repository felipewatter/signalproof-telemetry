# Processo de publicação

## Ordem obrigatória

1. Validar o projeto localmente com `pytest`, `compileall` e construção do pacote.
2. Publicar arquivos completos na branch `main` do repositório público.
3. Aguardar sucesso do workflow **CI**, com matriz de 3 SOs × 4 versões do Python.
4. No GitHub, abrir `Actions` → **Release** → **Run workflow**; informar `v0.1.0`.
5. O workflow verifica novamente a versão, o branch `main`, o CI bem-sucedido **do mesmo commit** e executa testes antes de criar o GitHub Release.
6. Confirmar tag, artefato ZIP/checksum e notas do release pela API do GitHub.

O release não é criado automaticamente por `push`. A rotina manual reduz o risco de divulgar uma versão não revisada. O GitHub Token do workflow precisa de permissão `contents: write`; as demais etapas são executadas com privilégios mínimos.

## Preparação de uma nova versão

- Atualizar `pyproject.toml`, `src/signalproof/__init__.py`, `CHANGELOG.md`, `RELEASE_NOTES.md`.
- Conferir exemplos, links, licenças e workflows fixados por SHA.
- Executar CI antes de disparar o workflow manual.
- Publicar release somente após o CI completo ser aprovado.
