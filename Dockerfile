FROM python:3.12-slim

# Node.js from Debian's own repo (no curl|bash), then clean up
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user with no login shell
RUN useradd --create-home --shell /usr/sbin/nologin sandboxuser

WORKDIR /sandbox

# Copy the entrypoint script and make it executable
COPY config/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh

# Drop privileges: everything from here runs as the non-root user
USER sandboxuser

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
