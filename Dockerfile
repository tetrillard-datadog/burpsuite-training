FROM python:3.7-slim-buster
WORKDIR /app
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY app.py .
CMD [ "python3", "app.py" ]
