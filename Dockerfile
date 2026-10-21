FROM python:3.12-slim
WORKDIR /app
COPY honeypot.py trace.py /app/
RUN mkdir -p /data && chown 65532:65532 /data && chmod 700 /data
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "honeypot.py", "serve"]
CMD ["--host", "0.0.0.0", "--data", "/data"]
