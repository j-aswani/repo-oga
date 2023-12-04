import gzip
import ipaddress
import logging
import os
import shutil
import sqlite3
import urllib.request

import time
from dbutils.pooled_db import PooledDB
from ipwhois import IPWhois

from resolvers.resolver import IdentifierResolver
from settings import ASN_DATABASE, RIPE_OPERATORS, RIPE_DATABASE_FILE, RIPE_DB_OUTPUT_FILE, RIPE_DB_URL

logger = logging.getLogger()


#
# Telco resolution logic using ipwhois, that uses Regional Internet Registries.
# This PoC uses the REST API. It is a naive implementation for demo purposes
# that works for Telefónica and Vodafone.
#
# It should evolve to use a local copy of a registry database or other smarter
# approaches.
#
class AsnIpResolver(IdentifierResolver):

    def get_operator(self, identifier_value):
        try:
            # Default value for private IPs
            if ipaddress.ip_address(identifier_value).is_private:
                return "TELEFONICA"

            # example 83.58.58.57 (Telefónica)
            # example 109.42.3.0 (Vodafone)
            whois = IPWhois(identifier_value).lookup_whois()
            logger.info(f"Resolved operator asn: {whois['asn']}")

            asn = int(whois['asn'])  # see https://asrank.caida.org/asns
            operator_id = next(key for key, value in ASN_DATABASE.items() if asn in value)
            return operator_id
        except StopIteration:
            return None


#
# Telco resolution logic using RIPE
# The database is not committed to the repo due to licensing restrictions.
class RipeIpResolver(IdentifierResolver):

    def __init__(self):
        self.pool = PooledDB(creator=self.create_connection, mincached=1, maxcached=5, maxconnections=10)
        self._load_ripe_database()

    def create_connection(self):
        return sqlite3.connect(RIPE_DATABASE_FILE)

    # This function loads the RIPE database into a SQLite database.
    def _load_ripe_database(self):
        logger.info("Loading RIPE database...")
        start_time = time.time()
        self._download_ripe_database(RIPE_DB_URL, RIPE_DB_OUTPUT_FILE)
        self._populate_local_database(RIPE_DB_OUTPUT_FILE)
        elapsed_time = time.time() - start_time
        logger.info(f"Done in {elapsed_time:.2f} seconds.")

    def _download_ripe_database(self, url, ripe_output_file):
        if not os.path.isfile(ripe_output_file + ".gz"):
            logger.info(f"Downloading {url}...")
            urllib.request.urlretrieve(url, ripe_output_file + ".gz")

        if not os.path.isfile(ripe_output_file):
            logger.info(f"Uncompressing {ripe_output_file}.gz...")
            with gzip.open(ripe_output_file + ".gz", 'rb') as f_in, open(ripe_output_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        logger.info("File downloaded and uncompressed successfully.")

    def _populate_local_database(self, ripe_output_file):
        logger.info(f"Populating database with CIDR ranges. This might take a couple of minutes...")
        start_ip = None
        end_ip = None
        conn = None
        try:
            conn = self.pool.connection()
            cursor = conn.cursor()
            create_table_query = '''
                CREATE TABLE IF NOT EXISTS ripe_inetnum (
                    id INTEGER PRIMARY KEY, start INTEGER, end INTEGER, org TEXT
                );
                '''
            cursor.execute(create_table_query)

            cursor.execute("BEGIN TRANSACTION;")
            with open(ripe_output_file, 'r', encoding='latin-1') as f_in:
                for line in f_in:
                    line = line.strip()
                    if line.startswith('inetnum:'):
                        inetnum = line.split(':')[1].strip()
                        if inetnum == '0.0.0.0 - 255.255.255.255':
                            continue
                        start_ip, end_ip = map(str.strip, inetnum.split('-'))
                        start_ip = int(ipaddress.ip_address(start_ip))
                        end_ip = int(ipaddress.ip_address(end_ip))
                    elif line.startswith('org:'):
                        org = line.split(':')[1].strip()
                        cursor.execute("INSERT OR IGNORE INTO ripe_inetnum (start, end, org) VALUES (?, ?, ?);", (start_ip, end_ip, org))
                    elif not line:
                        start_ip = None
                        end_ip = None
            cursor.execute("COMMIT;")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_start ON ripe_inetnum (start);")

            logger.info(f"Database populated")
        finally:
            if conn:
                conn.close()

    def get_operator(self, identifier_value):

        # Default value for private IPs
        if ipaddress.ip_address(identifier_value).is_private:
            return "TELEFONICA"
        
        conn = None
        try:
            ip = int(ipaddress.ip_address(identifier_value))
            conn = self.pool.connection()
            cursor = conn.cursor()
            cursor.execute("SELECT org FROM ripe_inetnum WHERE start <= ? AND end >= ?;", (ip, ip))

            row = cursor.fetchone()
            org = row[0] if row else None
            if org in RIPE_OPERATORS:
                logger.info("RIPE org: %s", org)
                return RIPE_OPERATORS[org]
            else:
                logger.info("Unknown operator from RIPE org: %s", org)
                return None
        finally:
            if conn:
                conn.close()
