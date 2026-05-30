"""Verified vendor sample payloads (field names confirmed against official docs
during research). Reused by schema tests and replay fixtures."""

from __future__ import annotations

import json

GITHUB_PUSH = json.loads(
    r"""
{"ref":"refs/heads/main","before":"9049f1265b7d61be4a8904a9a27120d2064dab3b","after":"0d1a26e67d8f5eaf1f6ba5c57fc3c7d91ac0fd1c","created":false,"deleted":false,"forced":false,"base_ref":null,"compare":"https://github.com/octo-org/sentinel/compare/9049f1265b7d...0d1a26e67d8f","commits":[{"id":"0d1a26e67d8f5eaf1f6ba5c57fc3c7d91ac0fd1c","tree_id":"f9d2a07e9488b91af2641b26b9407fe22a451433","distinct":true,"message":"Add credentials helper","timestamp":"2026-05-30T14:21:07-07:00","url":"https://github.com/octo-org/sentinel/commit/0d1a26e67d8f","author":{"name":"Alice Dev","email":"alice@octo-org.com","username":"alice-dev"},"committer":{"name":"Alice Dev","email":"alice@octo-org.com","username":"alice-dev"},"added":["src/creds.py"],"removed":[],"modified":["README.md"]}],"head_commit":{"id":"0d1a26e67d8f5eaf1f6ba5c57fc3c7d91ac0fd1c","tree_id":"f9d2a07e9488b91af2641b26b9407fe22a451433","message":"Add credentials helper","timestamp":"2026-05-30T14:21:07-07:00","author":{"name":"Alice Dev","email":"alice@octo-org.com","username":"alice-dev"},"committer":{"name":"Alice Dev","email":"alice@octo-org.com","username":"alice-dev"},"added":["src/creds.py"],"removed":[],"modified":["README.md"]},"pusher":{"name":"alice-dev","email":"alice@octo-org.com"},"repository":{"id":186853002,"node_id":"MDEwOlJlcG9zaXRvcnkxODY4NTMwMDI=","name":"sentinel","full_name":"octo-org/sentinel","private":true,"owner":{"login":"octo-org","id":6811672,"type":"Organization","site_admin":false},"html_url":"https://github.com/octo-org/sentinel","default_branch":"main","visibility":"private"},"organization":{"login":"octo-org","id":6811672},"sender":{"login":"alice-dev","id":21031067,"type":"User","site_admin":false}}
"""
)

GITHUB_MEMBER_ADDED = json.loads(
    r"""
{"action":"added","member":{"login":"mallory","id":583231,"type":"User","site_admin":false,"html_url":"https://github.com/mallory"},"changes":{"permission":{"to":"admin"}},"repository":{"id":186853002,"name":"sentinel","full_name":"octo-org/sentinel","private":true,"owner":{"login":"octo-org","id":6811672,"type":"Organization"}},"organization":{"login":"octo-org","id":6811672},"sender":{"login":"alice-admin","id":21031067,"type":"User","site_admin":false}}
"""
)

CLOUDTRAIL_ASSUMEROLE = json.loads(
    r"""
{"eventVersion":"1.08","userIdentity":{"type":"IAMUser","principalId":"AIDAJ45Q7YFFAREXAMPLE","arn":"arn:aws:iam::123456789012:user/Alice","accountId":"123456789012","accessKeyId":"AKIAIOSFODNN7EXAMPLE","userName":"Alice"},"eventTime":"2026-05-30T14:21:07Z","eventSource":"sts.amazonaws.com","eventName":"AssumeRole","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.64","userAgent":"aws-cli/2.15.0 Python/3.11 Linux/5.15","requestParameters":{"roleArn":"arn:aws:iam::123456789012:role/AdminRole","roleSessionName":"alice-cli","durationSeconds":3600},"responseElements":{"credentials":{"accessKeyId":"ASIAIOSFODNN7EXAMPLE","expiration":"May 30, 2026 3:21:07 PM"},"assumedRoleUser":{"assumedRoleId":"AROACKCEVSQ6C2EXAMPLE:alice-cli","arn":"arn:aws:sts::123456789012:assumed-role/AdminRole/alice-cli"}},"requestID":"f1d2c3b4-0000-1111-2222-333344445555","eventID":"a1b2c3d4-e5f6-7788-9900-aabbccddeeff","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"eventCategory":"Management","recipientAccountId":"123456789012","resources":[{"accountId":"123456789012","type":"AWS::IAM::Role","ARN":"arn:aws:iam::123456789012:role/AdminRole"}]}
"""
)

CLOUDTRAIL_CREATEACCESSKEY = json.loads(
    r"""
{"eventVersion":"1.08","userIdentity":{"type":"AssumedRole","principalId":"AROAIDPPEZS35WEXAMPLE:alice-cli","arn":"arn:aws:sts::123456789012:assumed-role/AdminRole/alice-cli","accountId":"123456789012","accessKeyId":"ASIAIOSFODNN7EXAMPLE","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"AROAIDPPEZS35WEXAMPLE","arn":"arn:aws:iam::123456789012:role/AdminRole","accountId":"123456789012","userName":"AdminRole"},"webIdFederationData":{},"attributes":{"mfaAuthenticated":"true","creationDate":"2026-05-30T14:20:01Z"}}},"eventTime":"2026-05-30T14:22:30Z","eventSource":"iam.amazonaws.com","eventName":"CreateAccessKey","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.64","userAgent":"aws-cli/2.15.0","requestParameters":{"userName":"bob"},"responseElements":{"accessKey":{"userName":"bob","accessKeyId":"AKIAEXAMPLENEWKEY123","status":"Active","createDate":"May 30, 2026 2:22:30 PM"}},"eventID":"b2c3d4e5-f6a7-8899-0011-223344556677","readOnly":false,"eventType":"AwsApiCall","managementEvent":true,"eventCategory":"Management","recipientAccountId":"123456789012"}
"""
)

CLOUDTRAIL_GETOBJECT = json.loads(
    r"""
{"eventVersion":"1.09","userIdentity":{"type":"AssumedRole","principalId":"AROAIDPPEZS35WEXAMPLE:app-session","arn":"arn:aws:sts::123456789012:assumed-role/AppRole/app-session","accountId":"123456789012","accessKeyId":"ASIAIOSFODNN7EXAMPLE","sessionContext":{"sessionIssuer":{"type":"Role","principalId":"AROAIDPPEZS35WEXAMPLE","arn":"arn:aws:iam::123456789012:role/AppRole","accountId":"123456789012","userName":"AppRole"},"attributes":{"mfaAuthenticated":"false","creationDate":"2026-05-30T13:00:00Z"}}},"eventTime":"2026-05-30T14:25:11Z","eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-east-1","sourceIPAddress":"198.51.100.22","userAgent":"aws-sdk-java/2.25.0","requestParameters":{"bucketName":"acme-secrets","key":"prod/db-credentials.json","Host":"acme-secrets.s3.us-east-1.amazonaws.com"},"responseElements":null,"readOnly":true,"eventID":"c3d4e5f6-a7b8-9900-1122-334455667788","eventType":"AwsApiCall","managementEvent":false,"eventCategory":"Data","recipientAccountId":"123456789012","resources":[{"type":"AWS::S3::Object","ARN":"arn:aws:s3:::acme-secrets/prod/db-credentials.json"},{"accountId":"123456789012","type":"AWS::S3::Bucket","ARN":"arn:aws:s3:::acme-secrets"}]}
"""
)

OKTA_LOGIN_SUCCESS = json.loads(
    r"""
{"uuid":"d2f9a1c0-1111-2222-3333-444455556666","published":"2026-05-30T14:21:07.123Z","eventType":"user.session.start","version":"0","severity":"INFO","legacyEventType":"core.user_auth.login_success","displayMessage":"User login to Okta","actor":{"id":"00u1a2b3c4D5e6F7g8h9","type":"User","alternateId":"alice@acme.com","displayName":"Alice Dev"},"client":{"id":null,"ipAddress":"203.0.113.64","device":"Computer","zone":"null","userAgent":{"rawUserAgent":"Mozilla/5.0","os":"Mac OS X","browser":"CHROME"},"geographicalContext":{"city":"San Jose","state":"California","country":"United States","postalCode":"95113","geolocation":{"lat":37.3382,"lon":-121.8863}}},"outcome":{"result":"SUCCESS","reason":null},"target":[],"transaction":{"id":"YVx9k0aBcDeFgHiJ","type":"WEB","detail":{}},"authenticationContext":{"authenticationProvider":"OKTA_AUTHENTICATION_PROVIDER","credentialType":"PASSWORD","authenticationStep":0,"externalSessionId":"102abc3DEf4gHiJkLmN5oPqR6"},"securityContext":{"asNumber":7922,"asOrg":"comcast cable","isp":"comcast","domain":"comcast.net","isProxy":false}}
"""
)

OKTA_LOGIN_FAILURE = json.loads(
    r"""
{"uuid":"e3a0b2d1-2222-3333-4444-555566667777","published":"2026-05-30T14:19:55.880Z","eventType":"user.session.start","version":"0","severity":"WARN","legacyEventType":"core.user_auth.login_failed","displayMessage":"User login to Okta","actor":{"id":"00u1a2b3c4D5e6F7g8h9","type":"User","alternateId":"alice@acme.com","displayName":"Alice Dev"},"client":{"id":null,"ipAddress":"198.51.100.200","device":"Unknown","zone":"null","userAgent":{"rawUserAgent":"python-requests/2.31.0","os":"Unknown","browser":"UNKNOWN"},"geographicalContext":{"city":"Moscow","state":"Moscow","country":"Russia","postalCode":null,"geolocation":{"lat":55.7558,"lon":37.6173}}},"outcome":{"result":"FAILURE","reason":"INVALID_CREDENTIALS"},"target":[],"transaction":{"id":"ZWy0l1bCdEfGhIjK","type":"WEB","detail":{}},"authenticationContext":{"authenticationProvider":"OKTA_AUTHENTICATION_PROVIDER","credentialType":"PASSWORD","authenticationStep":0,"externalSessionId":"unknown"},"securityContext":{"asNumber":12389,"asOrg":"rostelecom","isp":"rostelecom","domain":"rt.ru","isProxy":true}}
"""
)

OKTA_SSO = json.loads(
    r"""
{"uuid":"f4b1c3e2-3333-4444-5555-666677778888","published":"2026-05-30T14:22:40.500Z","eventType":"user.authentication.sso","version":"0","severity":"INFO","displayMessage":"User single sign on to app","actor":{"id":"00u1a2b3c4D5e6F7g8h9","type":"User","alternateId":"alice@acme.com","displayName":"Alice Dev"},"client":{"ipAddress":"203.0.113.64","device":"Computer","geographicalContext":{"city":"San Jose","country":"United States"}},"outcome":{"result":"SUCCESS","reason":null},"target":[{"id":"0oa9z8y7x6W5v4U3t2s1","type":"AppInstance","alternateId":"AWS Account Federation","displayName":"AWS Account Federation","detailEntry":{"signOnModeType":"SAML_2_0"}}],"authenticationContext":{"credentialType":"ASSERTION","externalSessionId":"102abc3DEf4gHiJkLmN5oPqR6"},"securityContext":{"asNumber":7922,"asOrg":"comcast cable","isProxy":false}}
"""
)

FALCO_SHELL = json.loads(
    r"""
{"hostname":"falco-xczjd","output":"13:44:05.478445995: Critical A shell was spawned in a container with an attached terminal","priority":"Critical","rule":"Terminal shell in container","source":"syscall","tags":["container","mitre_execution","shell"],"time":"2026-05-30T13:44:05.478445995Z","output_fields":{"container.id":"ee97d9c4186f","container.image.repository":"docker.io/library/alpine","evt.time":1685022245478445995,"k8s.ns.name":"default","k8s.pod.name":"kubecon","proc.cmdline":"sh -c clear; (bash || ash || sh)","proc.name":"sh","proc.pname":"runc","proc.tty":34816,"user.loginuid":-1,"user.name":"root"}}
"""
)

FALCO_SENSITIVE_FILE = json.loads(
    r"""
{"hostname":"node-prod-3","output":"14:25:11: Warning Sensitive file opened for reading by non-trusted program","priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["container","filesystem","host","mitre_credential_access","T1555"],"time":"2026-05-30T14:25:11.002311004Z","output_fields":{"container.id":"ee97d9c4186f","container.name":"web","container.image.repository":"docker.io/library/nginx","evt.type":"openat","fd.name":"/etc/shadow","k8s.ns.name":"frontend","k8s.pod.name":"web-7d9f","proc.cmdline":"cat /etc/shadow","proc.name":"cat","proc.pname":"bash","proc.exepath":"/usr/bin/cat","proc.tty":34817,"user.loginuid":-1,"user.name":"www-data","user.uid":33}}
"""
)
