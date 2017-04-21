#!/bin/bash

mkdir /etc/doddnsd/
cp -v doddnsd.conf /etc/doddnsd/
cp -v doddnsd.service /lib/systemd/system/
cp -v doddnsd.py /usr/local/bin/
chmod a+x /usr/local/bin/doddnsd.py
systemctl daemon-reload
systemctl enable doddnsd.service
