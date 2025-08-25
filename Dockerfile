FROM python:3.13-slim

RUN apt-get update && apt-get install -y gcc libc6-dev \
    libgmp-dev libmpfr-dev libmpc-dev \
    libsasl2-dev libldap2-dev \
    default-jre --no-install-recommends

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src

CMD ["python", "-m", "src.bot"]
