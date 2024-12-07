FROM python:3.7-slim

WORKDIR /app
ADD . .

RUN apt-get update 
RUN pip install -r requirements.txt 

EXPOSE 8081
CMD ["python3", "main.py"]
