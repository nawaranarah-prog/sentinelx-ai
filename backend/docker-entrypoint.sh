#!/bin/sh
set -e

# Apply database migrations before serving traffic.
alembic upgrade head

# Optional controlled demo seed (shared Nova Bank workspace + role-based demo accounts).
if [ "${SEED_DEMO:-false}" = "true" ]; then
  python -m app.seed
fi

exec "$@"
