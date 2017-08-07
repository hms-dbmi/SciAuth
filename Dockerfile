FROM dbmi/pynxgu

COPY app /app
RUN pip install -r /app/requirements.txt

RUN pip install awscli

RUN apt-get update && apt-get install -y jq

RUN mkdir /entry_scripts/
COPY gunicorn-nginx-entry.sh /entry_scripts/
RUN chmod u+x /entry_scripts/gunicorn-nginx-entry.sh

COPY sciauth.conf /etc/nginx/sites-available/pynxgu.conf

# Link nginx logs to stdout/stderr
RUN ln -sf /dev/stdout /var/log/nginx/access.log && ln -sf /dev/stderr /var/log/nginx/error.log

RUN mkdir /nessus/
COPY NessusAgent-6.10.9-debian6_amd64.deb /nessus/
WORKDIR /nessus/
RUN dpkg -i NessusAgent-6.10.9-debian6_amd64.deb
RUN /opt/nessus_agent/sbin/nessuscli agent link --key=ba71d5afb7819defd6d3c469aaf29dcd35964c6664b71955a9b7bf2529844d75 --host=ns-manager.itsec.harvard.edu --port=8834 --groups=HMS-LINUX

WORKDIR /

ENTRYPOINT ["/entry_scripts/gunicorn-nginx-entry.sh"]