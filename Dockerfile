FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 NMAP_PRIVILEGED=1

# nmap gets raw-socket capabilities so SYN scan + OS detection work without running as root
RUN apt-get update && apt-get install -y --no-install-recommends nmap libcap2-bin \
 && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)" \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 10001 netrec

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY wsgi.py .
COPY app ./app
USER netrec
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

# 1 worker + threads on purpose: scan jobs and cancel handles live in this process
CMD ["sh","-c","exec gunicorn -b ${BIND:-0.0.0.0:8000} --workers 1 --threads 8 --timeout 120 wsgi:app"]
