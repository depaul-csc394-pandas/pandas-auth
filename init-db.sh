#!/bin/bash
set -e

echo "Initializing database..."

# by default, postgres on docker only listens on UNIX socket
pg_ctl -o "-c listen_addresses='localhost'" -w restart

diesel database setup --locked-schema
