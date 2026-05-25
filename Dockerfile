FROM python:3.11-slim

# Instala apenas dependências mínimas do sistema
RUN apt-get update && apt-get install -y \
    ca-certificates \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copia e instala dependências Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o restante da aplicação
COPY . .

EXPOSE 3000

CMD gunicorn -b 0.0.0.0:${PORT:-3000} --timeout 120 --workers 1 app:app
