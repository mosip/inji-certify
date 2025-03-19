# How to compile ?

## Pre-requisite:

1. Java21
2. mvn

## Compiling

```bash
$ mvn clean package
$ cd target/
```
## Running

- after going inside the target directory, the below commands can be run

# How to run ?

Basic usage:
```bash
$ java -jar clientrunner-0.0.1-SNAPSHOT.jar

Generating a proofjwt with below params:
Nonce: 
Expiry: 
audience: https://esignet-mock.collab.mosip.net
issuer/client-id: wallet-demo
Signed JWT: eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVkMjU1MTkiLCJqd2siOnsia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJES2M3bVdlUlN0WVEwcndsTXNueG5GeHJPalNIOWFZS2Y4VG1LMXFrTk93In19.eyJpc3MiOiJ3YWxsZXQtZGVtbyIsImF1ZCI6Imh0dHBzOi8vZXNpZ25ldC1tb2NrLmNvbGxhYi5tb3NpcC5uZXQiLCJpYXQiOjE3NDA1NTU1Njl9.8nd5Fak-xwNKLoulz_P08q5_NDJb6VoOH93xL4LlRFf4Fz3i7gIkVoJAPhMDDoUsM3WiNbQwijrtaWgRfM6IBQ

```

With custom configuration:
```bash
java -jar clientrunner-0.0.1-SNAPSHOT.jar \
  --nonce=something \
  --exp=PT30s \
  --aud=http://localhost:8090 \
  --iss=wallet-demo
```

## Configuration Parameters

| Parameter | Default Value                         | Description                      |
|-----------|---------------------------------------|----------------------------------|
| nonce     |                                       | nonce value                      |
| exp       |                                       | expiry time duration of proofjwt |
| aud       | https://esignet-mock.collab.mosip.net | audience of the proofjwt token   |
| iss       | "wallet-demo"                         | issuer/client-id of the proofjwt |


## Decoding the token

- Ed25519 jwt encoded can be decoded [here](https://jwt.ms).
