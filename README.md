Keycloak (v19) demo for Authentication flows.

You can use this demo to test access control on 2 clients application with 3 different users.
The client applications are plain OIDC tokens debug apps.
2 Keycloak configuration are available, the second one contained altered authentication flows managing the access control level on applications based on users group membership.

## 1- Build the stack

```bash
docker-compose build
docker-compose up -d
docker-compose ps
           Name                          Command              State                 Ports               
--------------------------------------------------------------------------------------------------------
keycloak-exp_keycloak_1       /opt/keycloak/bin/kc.sh start   Up      127.0.0.1:8080->8080/tcp, 8443/tcp
keycloak-exp_oidc-tester1_1   node index.js                   Up      127.0.0.1:9091->80/tcp            
keycloak-exp_oidc-tester2_1   node index.js                   Up      127.0.0.1:9092->80/tcp            
keycloak-exp_postgres_1       docker-entrypoint.sh postgres   Up      127.0.0.1:9438->5432/tcp
```

## Alter /etc/hosts

Add these entries in your hosts file:

```
127.0.0.1 keycloak.local
127.0.0.1 client1.local
127.0.0.1 client2.local
```

## Import first keycloak config

```bash
# keycloak must not run whil the import occurs
docker-compose stop keycloak
docker-compose \
  run --rm \
   --entrypoint "/bin/bash -c" \
  keycloak \
  " \
   /opt/keycloak/bin/kc.sh \
     --auto-build \
     import \
     --dir /config/ \
     --override true \
  "
```
Without the --auto-build if fail on an error message like this:

```log
WARN  [org.hibernate.engine.jdbc.env.internal.JdbcEnvironmentInitiator] (JPA Startup Thread: keycloak-default) HHH000342: Could not obtain connection to query metadata: org.postgresql.util.PSQLException: FATAL: password authentication failed for user "sa"
```

As if the configuration is not loaded when using import/export command (you can try show-config and see that the config seems right and does not use the sa user). With the `--auto-build` this bug is fixed, but we fail at the end on this error:

```log
Unknown option: '--auto-build'
Try 'kc.sh --help' for more information on the available options.
ERROR: 2
```

But that's OK, As you can see on previous logs the import **IS** done.

```
(...)
INFO  [org.keycloak.services] (main) KC-SERVICES0050: Initializing master realm
INFO  [org.keycloak.services] (main) KC-SERVICES0030: Full model import requested. Strategy: OVERWRITE_EXISTING
INFO  [org.keycloak.exportimport.util.ImportUtils] (main) Realm 'test' imported
INFO  [org.keycloak.exportimport.dir.DirImportProvider] (main) Imported users from /config/test-users-0.json
INFO  [org.keycloak.services] (main) KC-SERVICES0032: Import finished successfully
(...)
```

You can now get the stack back online
```bash
docker-compose up -d
```

## Stack Urls

* http://keycloak.local:8080/auth keycloak (Admin console account: kadmin : kpasswd)
* http://client1.local:9091 : a sample OIDC debugger client (confidential client, load config1 on first visit)
* http://client2.local:9092 : a sample OIDC debugger client (confidential client, load config2 on first visit)

The oidc debug client can be use to check content of Id Token, Access Token, Refresh Token and login/logout behaviors. There are 2 because... the goal of an SSO is to share authentification on sevaral applications.

You have 3 tests users on the test realm (for these debug applications)

* test1 : password test, member of group 1
* test2 : password test, member of group 2
* test3 : password test, member of both groups

## Import fixed configuration

If you want to import the second version of the configuration, with alternative authentication flows, run this command:

```bash
# keycloak must not run while the import occurs
docker-compose stop keycloak
docker-compose \
  run --rm \
   --entrypoint "/bin/bash -c" \
  keycloak \
  " \
   /opt/keycloak/bin/kc.sh \
     --auto-build \
     import \
     --dir /config-v2/ \
     --override true \
  "
  docker-compose up -d
```

Failing at `Unknown option: '--auto-build'` but like he previous one it's still ok.

By the way if you want to export your conf someday you can user:

```bash
# keycloak must not run whil the import occurs
docker-compose stop keycloak
docker-compose \
  run --rm \
   --entrypoint "/bin/bash -c" \
  keycloak \
  " \
   /opt/keycloak/bin/kc.sh \
     --auto-build \
     export \
     --realm test \
     --dir /config \
     --users different_files \
     --users-per-file 100 \
  "
  docker-compose up -d
```
