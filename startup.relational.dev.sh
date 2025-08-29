#!/usr/bin/env bash
set -e

# Wait for core services
/opt/wait-for-it.sh postgres:5432
/opt/wait-for-it.sh qdrant:6333
/opt/wait-for-it.sh ollama:11434

# Setup Ollama with embedding model
echo "Waiting for Ollama to be ready..."
sleep 5
echo "Pulling embedding model..."
curl -X POST http://ollama:11434/api/pull -d '{"name":"mxbai-embed-large"}' || echo "Model pull failed, continuing..."
curl -X POST http://ollama:11434/api/pull -d '{"name":"llama3.2"}' || echo "Model pull failed, continuing..."
sleep 10

# Run database setup and start
npm run migration:run
npm run seed:run:relational
npm run start:prod
