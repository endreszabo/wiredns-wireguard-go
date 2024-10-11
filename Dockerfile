FROM scratch

COPY wireguard /wireguard
EXPOSE 2112 2112
CMD ["/wireguard", "-f", "wiredns"]

