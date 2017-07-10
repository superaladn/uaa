#!/bin/bash
set -x
set -e
set -v

sleep 10s

export ACCEPTANCE_ZONE_ID=uaa-acceptance-zone
export ACCEPTANCE_SUBDOMAIN=uaa-acceptance-zone

uaac target http://localhost:8080/uaa
uaac token client get admin -s adminsecret

#Create zone
uaac curl -X POST /identity-zones -H 'Content-Type: application/json' -d "{ \"id\": \"$ACCEPTANCE_ZONE_ID\", \"subdomain\":\"$ACCEPTANCE_SUBDOMAIN\", \"name\":\"$ACCEPTANCE_SUBDOMAIN\"}"
uaac -t curl -H "X-Identity-Zone-Id:$ACCEPTANCE_ZONE_ID" -XPOST -H"Content-Type:application/json" -H"Accept:application/json" --data "{ \"client_id\" : \"admin\", \"client_secret\" : \"acceptance-test\", \"scope\" : [\"uaa.none\"], \"resource_ids\" : [\"none\"], \"authorities\" : [\"uaa.admin\",\"clients.read\",\"clients.write\",\"clients.secret\",\"scim.read\",\"scim.write\",\"clients.admin\", \"sps.write\", \"sps.read\", \"zones.$ACCEPTANCE_ZONE_ID.admin\", \"idps.read\", \"idps.write\"], \"authorized_grant_types\" : [\"client_credentials\"]}" /oauth/clients