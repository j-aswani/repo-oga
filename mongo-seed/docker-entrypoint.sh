#!/bin/bash

url="http://169.254.169.254/metadata/instance?api-version=2021-01-01"
http_code=$(curl  -H "Metadata: true" -s -o /dev/null -w "%{http_code}" "$url")

if [ "$http_code" == "200" ]; then
    # This code is Telefónica specific, for our deployment in Azure.
    # It is not needed for local development.
    mongo mongodb:27017/authserver-telefonica --quiet azure/app-provision.js
    mongo mongodb:27017/authserver-vodafone --quiet azure/app-provision.js
    mongo mongodb:27017/aggregator-telco-router-1 --quiet azure/aggregator-app-provision.js
    mongo mongodb:27017/aggregator-telco-router-2 --quiet azure/aggregator-app-provision.js
else
    mongo mongodb:27017/authserver-telefonica --quiet localhost/app-provision.js
    mongo mongodb:27017/authserver-vodafone --quiet localhost/app-provision.js
    mongo mongodb:27017/aggregator-telco-router-1 --quiet localhost/aggregator-app-provision.js
    mongo mongodb:27017/aggregator-telco-router-2 --quiet localhost/aggregator-app-provision.js
fi
