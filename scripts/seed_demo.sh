#!/usr/bin/env bash
set -euo pipefail
sqlite3 ${DB_PATH:-./data/app.db} "insert into zones(domain,enabled,soa_mname,soa_rname,soa_serial,soa_refresh,soa_retry,soa_expire,soa_minimum,created_at,updated_at,version) values('example.com',1,'ns1.example.com.','hostmaster.example.com.',1,3600,600,1209600,300,strftime('%s','now'),strftime('%s','now'),1);"
