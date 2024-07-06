dev:
  npx wrangler@latest dev --env dev

deploy:
  npx wrangler@latest deploy

lint:
  ruff check --no-fix
  ruff format --check --diff

lint-fix:
  ruff check --fix
  ruff format