-- DuckDB schema for parsed Cowrie events. ingest.py is idempotent: re-running
-- against the same logs does not duplicate rows (primary keys + anti-join).

create table if not exists sessions (
  session        varchar primary key,
  src_ip         varchar,
  src_port       integer,
  protocol       varchar,
  client_version varchar,
  start_ts       timestamp,
  end_ts         timestamp,
  duration_s     double,
  login_user     varchar,
  login_pass     varchar,
  login_success  boolean
);

create table if not exists logins (
  ts        timestamp,
  session   varchar,
  src_ip    varchar,
  username  varchar,
  password  varchar,
  success   boolean
);

create table if not exists commands (
  ts       timestamp,
  session  varchar,
  src_ip   varchar,
  command  varchar
);

create table if not exists downloads (
  ts       timestamp,
  session  varchar,
  src_ip   varchar,
  url      varchar,
  shasum   varchar,
  outfile  varchar
);

-- enrichment, keyed by IP (enrich.py fills this)
create table if not exists ip_intel (
  src_ip        varchar primary key,
  country       varchar,
  country_code  varchar,
  asn           varchar,
  org           varchar,
  abuse_score   integer,
  is_tor        boolean,
  updated_ts    timestamp
);
