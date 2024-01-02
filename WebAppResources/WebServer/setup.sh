#!/bin/bash -xe

sudo apt-get update || true
sudo apt-get install -y mysql-server python3-venv authbind || true
sudo touch /etc/authbind/byport/80 || true
sudo chmod 500 /etc/authbind/byport/80 || true
sudo chown ubuntu /etc/authbind/byport/80 || true
sudo mv gunicorn.service /etc/systemd/system/ || true
mkdir Cloud-Web-Server || true
mv WebServer.zip Cloud-Web-Server/ || true
unzip Cloud-Web-Server/WebServer.zip -d Cloud-Web-Server/ || true
if python3 -m venv Cloud-Web-Server/venv; then
    if source Cloud-Web-Server/venv/bin/activate; then
        pip install -r requirements.txt
    else
        echo "pip install -r requirements.txt FAILED"
    fi
else
    echo "python3 -m venv Cloud-Web-Server/venv FAILED"
fi
sudo systemctl daemon-reload || true
sudo systemctl start gunicorn || true
sudo systemctl enable gunicorn || true