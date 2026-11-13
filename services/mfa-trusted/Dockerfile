FROM veriq-mfa-python
COPY services/mfa-trusted/server.py /app/mfa_trusted.py
USER 10002:10002
ENTRYPOINT ["/app/.venv/bin/python", "/app/mfa_trusted.py"]
