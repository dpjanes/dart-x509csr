/*
 * lib/src/ids.dart
 *
 * David Janes
 * 2018-03-13
 *
 * Copyright [2019] David P. Janes
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 *  https://tools.ietf.org/html/rfc2256
 */

import 'package:asn1lib/asn1lib.dart';

const ids = {
    "cn": "2.5.4.3",
    "sn": "2.5.4.4",
    "c": "2.5.4.6",
    "l": "2.5.4.7",
    "st": "2.5.4.8",
    "o": "2.5.4.10",
    "ou": "2.5.4.11",
    "title": "2.5.4.12",
    "registeredAddress": "2.5.4.26",
    "member": "2.5.4.31",
    "owner": "2.5.4.32",
    "roleOccupant": "2.5.4.33",
    "seeAlso": "2.5.4.34",
    "givenName": "2.5.4.42",
    "initials": "2.5.4.43",
    "generationQualifier": "2.5.4.44",
    "dmdName": "2.5.4.54",
    "alias": "2.5.6.1",
    "country": "2.5.6.2",
    "locality": "2.5.6.3",
    "organization": "2.5.6.4",
    "organizationalUnit": "2.5.6.5",
    "person": "2.5.6.6",
    "organizationalPerson": "2.5.6.7",
    "organizationalRole": "2.5.6.8",
    "groupOfNames": "2.5.6.9",
    "residentialPerson": "2.5.6.10",
    "applicationProcess": "2.5.6.11",
    "applicationEntity": "2.5.6.12",
    "dSA": "2.5.6.13",
    "device": "2.5.6.14",
    "strongAuthenticationUser": "2.5.6.15",
    "certificationAuthority": "2.5.6.16",
    "groupOfUniqueNames": "2.5.6.17",
    "userSecurityInformation": "2.5.6.18",
    "certificationAuthority-V2": "2.5.6.16.2",
    "cRLDistributionPoint": "2.5.6.19",
    "dmd": "2.5.6.20",

    // X.509 stuff
    "md5WithRSAEncryption": "1.2.840.113549.1.1.4",
    "rsaEncryption": "1.2.840.113549.1.1.1",

    // stuff I've added
    "s": "2.5.4.8",
};

ASN1ObjectIdentifier lookupX500ObjectIdentifier(String id) {
    ASN1ObjectIdentifier result;

    id = id.toLowerCase();
    ids.forEach((key, value) {
        if (key.toLowerCase() == id) {
            result = ASN1ObjectIdentifier(value.split(".").map((v) => int.parse(v)).toList());
        }
    });

    return result;
}

/*
main(List<String> arguments) {
    dynamic value = lookup("organizationalUnit");
    print(value);
}
*/
