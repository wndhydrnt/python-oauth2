#!/bin/bash

# Install pip and python development libs
apt-get -y install python-pip python-dev libmysqlclient-dev make
# Install pythonb libs
pip install -r /opt/python-oauth2/requirements.txt
# Make python-oauth2 available for python
if ! grep -Fxq "export PYTHONPATH=/opt/python-oauth2" /home/vagrant/.bashrc
then
    echo "export PYTHONPATH=/opt/python-oauth2" >> /home/vagrant/.bashrc
fi
# Create the testdb database in mysql
mysql -uroot < /vagrant/mysql-schema.sql
# Execute script to create a testclient entry in mongodb
python /vagrant/create_testclient.py
