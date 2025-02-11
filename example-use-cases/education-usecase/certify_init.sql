INSERT INTO certify.credential_template (context, credential_type, template, cr_dtimes, upd_dtimes) VALUES ('https://www.w3.org/2018/credentials/v1', 'UniversityCredential,VerifiableCredential', '{
     "@context": [
         "https://www.w3.org/2018/credentials/v1",
         "https://vharsh.github.io/DID/university.json",
         "https://w3id.org/security/suites/ed25519-2020/v1"
     ],
     "issuer": "${_issuer}",
     "type": [
         "VerifiableCredential",
         "UniversityCredential"
     ],
     "issuanceDate": "${validFrom}",
     "expirationDate": "${validUntil}",
     "credentialSubject": {
        "id": "${_holderId}",
        "rollNumber": "${rollNumber}",
        "studentName": "${studentName}",
        "courseName": "${courseName}",
        "courseDivisionName": "${courseDivisionName}",
        "courseDuration": "${courseDuration}",
        "result": "${result}",
        "startDate": "${startDate}",
        "completionDate": "${completionDate}",
        "dateOfBirth": "${dateOfBirth}",
        "gender": "${gender}",
        "face": "${face}"
     }
}
', 'NOW()', NULL);

INSERT INTO certify.credential_template (context, credential_type, template, cr_dtimes, upd_dtimes) VALUES ('https://www.w3.org/ns/credentials/v2', 'FarmerCredential,VerifiableCredential', '{
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://vharsh.github.io/DID/university.json",
        "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "issuer": "${_issuer}",
    "type": [
        "VerifiableCredential",
        "UniversityCredential"
    ],
    "validFrom": "${validFrom}",
    "validUntil": "${validUntil}",
    "credentialSubject": {
        "id": "${_holderId}",
        "rollNumber": "${rollNumber}",
        "studentName": "${studentName}",
        "courseName": "${courseName}",
        "courseDivisionName": "${courseDivisionName}",
        "courseDuration": "${courseDuration}",
        "result": "${result}",
        "startDate": "${startDate}",
        "completionDate": "${completionDate}",
        "dateOfBirth": "${dateOfBirth}",
        "gender": "${gender}",
        "face": "${face}"
    }
}', 'NOW()', NULL);
