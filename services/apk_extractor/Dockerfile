FROM mobile-base:latest
COPY services/shared ./shared
COPY services/apk_extractor ./apk_extractor
ENV PYTHONPATH=/app
WORKDIR /app/apk_extractor
ENTRYPOINT ["./entrypoint.sh"]
