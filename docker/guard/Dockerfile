FROM alpine:3.22
RUN apk add --no-cache iptables
COPY guard.sh /guard.sh
ENTRYPOINT ["/bin/sh", "/guard.sh"]
