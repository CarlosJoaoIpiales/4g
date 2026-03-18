FROM python:3.11-slim

WORKDIR /app
COPY udp_bove_4g_server.py .

# -u = stdout sin buffer → los logs aparecen inmediatamente en fly logs
CMD ["python", "-u", "udp_bove_4g_server.py"]
