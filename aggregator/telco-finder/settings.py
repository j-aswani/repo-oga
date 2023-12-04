import os

PORT = int(os.environ.get('PORT', 5000))

OIDC_DATA_TTL = 60
OIDC_VERIFY_CERTIFICATE = False
OIDC_HTTP_TIMEOUT = 10  # in seconds
OIDC_DISCOVERY_PATH = '/.well-known/openid-configuration'
OIDC_WEBFINGER_PATH = '/.well-known/webfinger'

OPERATOR_CLIENT_ID = "f1283a82-46d7-471c-9c3c-39b4d393cbe6"
OPERATOR_TELCOFINDER_SCOPES = ["telcofinder"]

JWT_SIGNING_ALGORITHM = 'RS256'
JWT_PRIVATE_KEY_FILE = os.path.join(os.path.dirname(__file__), 'jwtRS256_private.pem')
JWT_PRIVATE_KEY_PASSWORD = 'mobileconnect'
JWT_KID = 'defaultKid'

# Identifier type prefix -> Resolver class
OPERATOR_RESOLVERS = {
    'ipport': os.environ.get('IP_RESOLVER', 'resolvers.ip.AsnIpResolver'),
    'tel': os.environ.get('MSISDN_RESOLVER', 'resolvers.msisdn.DummyMsisdnResolver')
}

ASN_DATABASE = {
    "TELEFONICA": [
        12956, 22927, 3352, 10834, 16629, 6805, 6147, 14117, 35228, 262202,
        6306, 19889, 60793, 19422, 56460, 15311, 263783, 22364, 17069, 40260, 12638, 27680,
        11815, 29180, 61510, 27877, 22501, 6813, 263777, 49318, 8789, 23416, 52447, 4926,
        27950, 31418, 263814, 265795, 264819, 204758, 203672, 264652, 269873, 270063, 267858,
        267903, 22185, 198198, 264123, 19196, 265773
    ],
    "VODAFONE": [
        1273, 55410, 12302, 15924, 3209, 16019, 12430, 12357, 3329, 30722,
        33915, 24835, 6739, 21334, 12969, 50973, 12353, 55644, 6660, 21183, 48728, 38442,
        15502, 34912, 5378, 17993, 16338, 133612, 15897, 201917, 36935, 31334, 15480, 8386,
        25310, 17435, 44957, 12361, 25135, 18291, 211559, 212661, 62211, 31654, 3273, 134927,
        30995, 133580, 136987, 328794
    ]
}

OPERATOR_DATABASE = {
    "TELEFONICA": {
        "iss": "http://operator-platform-authserver-1:9010",
        "apis": "http://operator-platform-apigateway-1:8000"
    },
    "VODAFONE": {
        "iss": "http://operator-platform-authserver-2:9020",
        "apis": "http://operator-platform-apigateway-2:8000"
    }
}

RIPE_DB_URL = "https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz"
RIPE_DB_OUTPUT_FILE = "ripe.db.inetnum"
RIPE_DATABASE_FILE = "ripe.db"
RIPE_OPERATORS = {
    "ORG-TDE1-RIPE": "TELEFONICA",
    "ORG-VDG1-RIPE": "VODAFONE"
}

