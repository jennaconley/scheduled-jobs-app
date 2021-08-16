FROM python:3.9.2

WORKDIR /app
COPY . /app
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV TZ=America/Chicago
RUN ln -snf /var/db/timezone/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN date

# # Download special certificate auth. bundle to use in https requests to some internal sites.
ENV CERT_AUTH_BUNDLE="/app/ca-bundle.crt"
ADD http://allthecerts.widgets.com/widget-certs/widget-ca-bundle.crt $CERT_AUTH_BUNDLE
ENV REQUESTS_CA_BUNDLE=$CERT_AUTH_BUNDLE
ENV SSL_CERT_FILE=$CERT_AUTH_BUNDLE

# Download runtime-connector and save it in / directory
ENV RUNTIME_VERSION=v2.0.12
# -o, --output <file> (Tells curl to write output to <file> instead of to stdout.)
# tar is an archiving utility, -x to extract files from an archive, -v for verbose, 
# -z to (de)compress using gzip, -f <file> to point to an archive file,
# -C / to change to the / directory.
RUN curl \
    "https://repo-central.widgets.com/platform/runtime-connector/${RUNTIME_VERSION}.tgz" \
    --output /runtime-connector.tgz \
    && tar xvzf /runtime-connector.tgz -C / \
    && rm /runtime-connector.tgz \
    && echo "Runtime connector downloaded!"

# Install Python packages
RUN pip3 install --upgrade pip \
    -r requirements.txt \
    && echo "Pip has installed requirements.txt packages!"

# Expose port/s accepting incoming traffic
EXPOSE 8080

# Start Container
# Use -- to divide the runtime-connector's command options from the begining of a new command, 
# otherwise runtime-connector might parse the command incorrectly.
ENTRYPOINT ["/runtime-connector", "--", "python3", "/app/app.py"]
