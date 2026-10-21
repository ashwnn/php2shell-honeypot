FROM python:3.12-slim
WORKDIR /app
COPY honeypot.py /app/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "honeypot.py", "serve"]
CMD ["--host", "0.0.0.0", "--data", "/data"]
