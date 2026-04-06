FROM python:3.11-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -e .

EXPOSE 5001
CMD ["bash", "start.sh"]
