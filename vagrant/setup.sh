#!/bin/bash

# Install pip and python development libs
apt-get -y install python-pip python-dev
# Install pythonb libs
pip install -r /vagrant/requirements.txt
# Make python-oauth2 available for python
if ! grep -Fxq "export PYTHONPATH=/opt/python-oauth2" /home/vagrant/.bashrc
then
    echo "export PYTHONPATH=/opt/python-oauth2" >> /home/vagrant/.bashrc
fi
# Execute script to create a testclient entry in mongodb
python /vagrant/create_testclient.py
