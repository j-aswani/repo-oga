db.apps.replaceOne(
    {
        _id : "73902489-c201-4819-bdf9-3708a484fe21"
    },
    {
        _id : "73902489-c201-4819-bdf9-3708a484fe21",
        consumer_secret : "3184428a-1ea4-4e1c-9969-b623f36fbc2f",
        name : "Demo App",
        description : "App for testing",
        developer : {
            email : "johndoe@demo-app.com",
            name : "John Doe Developer"
        },
        status : "active",
        grants : [
            {
                grant_type : "urn:ietf:params:oauth:grant-type:jwt-bearer",
                scopes : [
                    "device-location-verification-verify-read"
                ]
            },
            {
                grant_type : "authorization_code",
                scopes : [
                    "openid",
                    "number-verification-verify-hashed-read",
                    "device-location-verification-verify-read"
                ]
            }
        ],
        sector_identifier_uri : "https://opengateway.baikalplatform.es",
        jwks_uri : "https://aggregator-telco-router-2.opengateway.baikalplatform.es/oauth2/jwks",
        redirect_uri : [
            "https://aggregator-telco-router-2.opengateway.baikalplatform.es/oauth2/authorize/callback"
        ]
    },
    {
        upsert: true
    }
)

db.apps.replaceOne(
    {
        _id : "f1283a82-46d7-471c-9c3c-39b4d393cbe6"
    },
    {
        _id : "f1283a82-46d7-471c-9c3c-39b4d393cbe6",
        name : "TelcoRouter 2",
        description : "TelcoRouter 2 for testing",
        developer : {
            email : "jeandupont@telcorouter.com",
            name : "Jean Dupont Developer"
        },
        status : "active",
        grants : [
            {
                grant_type : "client_credentials",
                scopes : [
                    "telcofinder"
                ]
            }
        ],
        jwks_uri : "https://aggregator-telco-router-2.opengateway.baikalplatform.es/oauth2/jwks"
    },
    {
        upsert: true
    }
);

db.apps.replaceOne(
    {
        _id : "4d019263-3ff0-4d0e-a48a-5b3d877038dc"
    },
    {
        _id : "4d019263-3ff0-4d0e-a48a-5b3d877038dc",
        consumer_secret : "4222fddd-64b6-4452-b24e-23caae9ccc08",
        name : "API Gateway",
        description : "API Gateway for testing",
        developer : {
            email : "jeandupont@operator.com",
            name : "Jean Dupont Developer"
        },
        status : "active",
        grants : [
            {
                grant_type : "basic",
                scopes : [
                    "telcofinder"
                ]
            }
        ]
    },
    {
        upsert: true
    }
);
