VirAuth
========

A customized JDBC auth module for [OpenAM](http://openam.forgerock.org/) (based on the [original](http://sources.forgerock.org/changelog/openam/trunk/openam/openam-authentication/openam-auth-jdbc) JDBC auth module)
There is a great tutorial about custom authentication modules in the [developer docs](http://openam.forgerock.org/openam-documentation/openam-doc-source/doc/dev-guide/index.html#chap-auth-spi).

## Install

### Customize the war and deploy it

```bash
cp target/openam-auth-vir-jdbc-2.0.jar $openam_war/WEB-INF/lib/
cp src/main/resources/amAuthVirJDBC* $openam_war/WEB-INF/classes/
cp src/main/resources/config/auth/default/VirJDBC.xml $openam_war/config/auth/default/
```

### Register the service with `ssoadm`


```bash
$SSOADM_HOME/ssoadm create-svc -u amadmin -f $PASSWD_FILE -X src/main/resources/amAuthVirJDBC.xml
$SSOADM_HOME/ssoadm register-auth-module -u amadmin -f $PASSWD_FILE -a hu.sch.vir.auth.VirJDBC
```

## Uninstall

```bash
$SSOADM_HOME/ssoadm unregister-auth-module -u amadmin -f $PASSWD_FILE -a hu.sch.vir.auth.VirJDBC
$SSOADM_HOME/ssoadm delete-svc -u amadmin -f $PASSWD_FILE -s iPlanetAMAuthVirJDBCService
```
