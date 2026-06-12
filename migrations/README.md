# Migrações (Alembic)

Hoje o app cria as tabelas no startup via `Base.metadata.create_all()`, o que
cobre **tabelas novas** automaticamente. O Alembic está configurado para gerir
**alterações incrementais de schema** (novas colunas, índices, etc.) sem o
`ALTER TABLE` manual.

## Cutover para Alembic (uma vez, no seu ambiente)

Com o banco no ar e dependências instaladas:

```bash
# 1. Gerar a migração baseline a partir dos models atuais
alembic revision --autogenerate -m "baseline"

# 2. Em um banco que JÁ tem as tabelas (create_all), marque como aplicado:
alembic stamp head

#    Em um banco vazio, em vez do stamp, aplique:
# alembic upgrade head
```

## Fluxo dia a dia

```bash
# após mudar um model:
alembic revision --autogenerate -m "descricao da mudanca"
alembic upgrade head
```

A URL do banco vem de `DATABASE_URL` (mesma do app); não há credencial neste diretório.
