FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt
COPY parser.py ./
RUN mkdir -p /run/iqkb && chown 65532:65532 /run/iqkb
USER 65532:65532
CMD ["python", "parser.py"]
