FROM python:3.11-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -e .

EXPOSE 5001
CMD ["python", "-m", "flask", "--app", "dashboard.app", "run", "--host", "0.0.0.0", "--port", "5001"]
