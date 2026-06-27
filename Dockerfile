FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias primero (capa cacheada)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código
COPY . .

# Crear carpetas necesarias
RUN mkdir -p static/uploads data

EXPOSE 5000

CMD ["python", "app.py"]
