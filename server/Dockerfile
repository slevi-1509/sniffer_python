FROM python:3.13.1-slim
WORKDIR /app
COPY server_ai.py /app/
COPY .env /app/
COPY requirements.txt /app/
COPY openai_request.py /app/
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python", "server_ai.py"]