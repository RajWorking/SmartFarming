#!/bin/bash

mv keys1.json device1/keys.json
mv keys2.json device2/keys.json

mv cred_G.json gatewayDevice/
mv GWN.key gatewayDevice/
mv GWN.pub gatewayDevice

mv cred_ES.json edgeServer/

cp ES.pub gatewayDevice/

mv ES.key edgeServer/
mv ES.pub edgeServer/

tree device1/ device2/ gatewayDevice/ edgeServer/
