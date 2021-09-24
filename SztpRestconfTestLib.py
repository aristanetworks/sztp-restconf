#!/usr/bin/env python3
# Copyright (c) 2021 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.
#
# -----------------------------------------------------------
# Library of illustrative helpful routines to generate SZTP restconf responses
# for use with apache servers.
# References:
# - RFC8572, Secure Zero Touch Provisioning (SZTP)
# - RFC8366, A Voucher Artifact for Bootstrapping Protocols
# -----------------------------------------------------------

from __future__ import absolute_import, division, print_function

import os
import subprocess
import json
from datetime import datetime
import string

def runOpensslCmd( cmd1Args, cmd2Args ):
   """Execute shell command, piping output by default to base64, return output."""
   p1 = subprocess.Popen( cmd1Args, stdout=subprocess.PIPE )
   p2 = subprocess.Popen( cmd2Args, stdin=p1.stdout, stdout=subprocess.PIPE )
   # Close p1.stdout so only process(p2) attached to the pipe; if p2 exits,
   # p1 will receive a SIGPIPE.
   p1.stdout.close()
   output = p2.communicate()[ 0 ]
   return output

def opensslCmsDataCreate( conveyedInfoFile ):
   """Create a DER encoded CMS data type given a conveyed-info file and
   base64-encode the response."""
   opensslCmdArgs = [ "openssl", "cms", "-data_create", "-in", conveyedInfoFile,
                      "-outform", "der" ]
   conveyedInfoCmsDerBase64 = runOpensslCmd( opensslCmdArgs, [ "base64" ] )
   return conveyedInfoCmsDerBase64

def opensslCmsSignedDataCreate( conveyedInfoFile, cert, privateKey ):
   """Create a signed CMS encoded object given a conveyed-info file and
   base64 encode the response."""
   opensslCmdArgs = [ "openssl", "cms", "-sign", "-in", conveyedInfoFile,
                      "-signer", cert,
                      "-inkey", privateKey,
                      "-outform", "der", "-nodetach" ]
   conveyedInfoCmsSignedDerBase64 = runOpensslCmd( opensslCmdArgs, [ "base64" ] )
   return conveyedInfoCmsSignedDerBase64

def opensslCmsCertCreate( ownerCertFile ):
   """Create a degenerate CMS encoded object given a cert file and base64-encode
   the response."""
   opensslCmdArgs = [ "openssl", "crl2pkcs7", "-certfile", ownerCertFile,
                      "-nocrl", "-outform", "der" ]
   ownerCertCmsDerBase64 = runOpensslCmd( opensslCmdArgs, [ "base64" ] )
   return ownerCertCmsDerBase64

def getBase64PinnedDomainCert( pinnedDomainCertFile ):
   """Extract base64 value from pinned-domain-cert file;
   i.e. given a PEM encoded cert, strip header and footer."""
   tailCmdArgs = [ "tail", "-n", "+2", pinnedDomainCertFile ]
   headCmdArgs = [ "head", "-n", "-1" ]
   pinnedDomainCertBase64 = runOpensslCmd( tailCmdArgs, headCmdArgs )
   return pinnedDomainCertBase64

def createHttpdResponseFile( responseXml, restconfDir="/restconf/operations" ):
   """Create a file within httpd directory containing response for uri
   (/restconf/operations/ietf-sztp-bootstrap-server:get-bootstrapping-data)."""
   if not os.path.exists( restconfDir ):
      os.makedirs( restconfDir )
   responseXmlFile = "{}/ietf-sztp-bootstrap-server:get-bootstrapping-data".\
                     format( restconfDir )
   with open( responseXmlFile, "w" ) as respFile:
      respFile.write( responseXml )
   return responseXmlFile

def verifyDictTypes( template, dictToCheck ):
   """Verify dict value types correspond to template"""
   for key in dictToCheck:
      if not ( ( isinstance( dictToCheck[ key ], list ) and
                 isinstance( template[ key ], list ) ) or
               ( isinstance( dictToCheck[ key ], dict ) and
                 isinstance( template[ key ], dict ) ) or
               ( isinstance( dictToCheck[ key ], template[ key ] ) ) ):
         return False

   return True

def genConvRedirectInfoJsonFile( sztpRedirectServers, redirectFileJson ):
   """Generate file containing bootstrap redirect information (json).
   sztpRedirectServers is a list of dictionaries, of the template below.
   """
   template = { "address": str,
                "port": int,
                "trust-anchor": str
   }
   mandatory = [ "address" ]
   # verify redirect-server list is correctly constructed
   assert isinstance( sztpRedirectServers, list ), "Expected list"
   assert all( isinstance( svr, dict ) for svr in sztpRedirectServers ), \
      "Expected list element to be dict"

   for svr in sztpRedirectServers:
      assert set( svr.keys() ).issubset( set( template.keys() ) ), \
         "Unexpected keys in dict"
      assert verifyDictTypes( template, svr ), \
         "Unexpected values types"
      assert set( mandatory ).issubset( svr ), \
         "Mandatory keys not present"

   # construct outer dictionary and convert to json
   bootstrapServers = { "bootstrap-server": sztpRedirectServers }
   ietfRedirectInfo = {
      "ietf-sztp-conveyed-info:redirect-information": bootstrapServers }
   jsonIetfRedirectInfo = json.dumps( ietfRedirectInfo, indent=4 )

   # save to file
   with open( redirectFileJson, "w" ) as tmpFile:
      tmpFile.write( jsonIetfRedirectInfo )

def genConvOnboardingInfoJsonFile( sztpOnboardingInfo, onboardingFileJson ):
   """Generate file containing bootstrap onboarding information (json).
   sztpOnboardingInfo is a dictionary with the following elements:
   """
   template = {
      "boot-image": {
         "os-name": str,
         "os-version": str,
         "download-uri": list, # of uri strings
         "image-verification": [ {
            "hash-algorithm": str,
            "hash-value": str } ],
      },
      "configuration-handling": str,
      "pre-configuration-script": str,
      "configuration": str,
      "post-configuration-script": str
   }

   def verifyBootImage( template, sztpBootImage ):
      """Verify boot image is correct"""
      def verifyImageVerification( imageVerification ):
         """Verify instance of image-verification is correct"""
         if "hash-algorithm" in imageVerification:
            assert imageVerification[ "hash-algorithm" ] == \
               "ietf-sztp-conveyed-info:sha-256",\
               "Unsupported hash-algorithm"
         assert "hash-value" in imageVerification, \
            "Expected hash-value not present"
         hashValue = imageVerification[ "hash-value" ]
         # Verify hashValue appears to be a yang:hex-string
         assert len( hashValue ) == 32 * 3 - 1 and \
                  all( c == ':' or c in string.hexdigits for c in hashValue ), \
            "hash-value invalid"

      def verifyImageVerificationList( template, sztpImageVerification ):
         """Verify image-verification list is correct"""
         assert isinstance( sztpImageVerification, list ), \
            "Expected list"
         for imageVer in sztpImageVerification:
            assert verifyDictTypes( template, imageVer ), "Unexpected value types"
            assert set( imageVer.keys() ).issubset( set( template.keys() ) ), \
               "Unexpected keys in dict"
            verifyImageVerification( imageVer )

      mandatory = [ "download-uri" ]
      assert isinstance( sztpBootImage, dict ), "Expected dict"
      assert set( sztpBootImage.keys() ).issubset( template.keys() ), \
               "Unexpected keys in dict"
      assert verifyDictTypes( template, sztpBootImage ), \
         "Unexpected value types"
      assert set( mandatory ).issubset( sztpBootImage ), \
         "Mandatory keys not present"
      if "image-verification" in sztpBootImage:
         verifyImageVerificationList( template[ "image-verification" ][ 0 ],
                  sztpBootImage[ "image-verification" ] )

   # verify onboarding-info dict is correctly constructed
   assert isinstance( sztpOnboardingInfo, dict ), "Expected dict"
   assert set( sztpOnboardingInfo.keys() ).issubset( template.keys() ), \
      "Unexpected keys in dict"
   assert verifyDictTypes( template, sztpOnboardingInfo ), \
      "Unexpected values types"
   assert sztpOnboardingInfo[ "configuration-handling" ] == "replace", \
            "Unsupported configuration-handling value"
   if "boot-image" in sztpOnboardingInfo:
      verifyBootImage( template[ "boot-image" ],
                       sztpOnboardingInfo[ "boot-image" ] )

   # construct outer dictionary and convert to json
   ietfOnboardingInfo = { "ietf-sztp-conveyed-info:onboarding-information":
                          sztpOnboardingInfo }
   jsonIetfOnboardingInfo = json.dumps( ietfOnboardingInfo, indent=4 )

   # save to file
   with open( onboardingFileJson, "w" ) as tmpFile:
      tmpFile.write( jsonIetfOnboardingInfo )

def genOwnershipVoucherJsonFile( ownershipVoucher, voucherFileJson ):
   """Convert ownership-voucher dictionary to json and write to file.
   ownershipVoucher is a dictionary of the template below with values as per RFC8366.
   """
   template = { "created-on": str,
                "expires-on": str,
                "assertion": str,
                "serial-number": str,
                "pinned-domain-cert": str,
                "domain-cert-revocation-checks": bool,
                "last-renewal-date": str
   }

   def validDateTime( dateTime ):
      """Verify a dateTime string conforms to RFC3339 format (only Z TZ accepted)"""
      try:
         datetime.strptime( dateTime, "%Y-%m-%dT%H:%M:%S.%fZ" )
         return True
      except ValueError:
         return False

   mandatory = [ "created-on", "assertion", "serial-number", "pinned-domain-cert" ]
   # verify ownership-coucher dict is correctly constructed
   assert isinstance( ownershipVoucher, dict ), "Expected dict"
   assert set( ownershipVoucher.keys() ).issubset( template.keys() ), \
      "Unexpected keys in dict"
   assert verifyDictTypes( template, ownershipVoucher ), \
                    "Unexpected value types"
   assert set( mandatory ).issubset( ownershipVoucher ), \
      "Mandatory keys not present"
   assert ownershipVoucher[ "assertion" ] == "verified", \
      "Unsupported assertion value"
   assert validDateTime( ownershipVoucher.get( "created-on" ) ) and \
      validDateTime( ownershipVoucher.get( "expires-on", "" ) ) and \
      validDateTime( ownershipVoucher.get( "last-renewal-date", "" ) ), \
      "Invalid datetime value"

   ietfVoucher = { "ietf-voucher:voucher": ownershipVoucher }
   jsonOwnershipVoucher = json.dumps( ietfVoucher, indent=4 )

   # save to file
   with open( voucherFileJson, "w" ) as tmpFile:
      tmpFile.write( jsonOwnershipVoucher )

def genBootstrappingDataResponseFile( conveyedInfo,
                                      ownerCertificate=None,
                                      ownershipVoucher=None,
                                      reportingLevel="verbose" ):
   """Generate SZTP redirect response for response to following https uri
   https://<ip>/restconf/operations/ietf-sztp-bootstrap-server:get-bootstrapping-data
   Response requires multiple layers of encoding, e.g.

   HTTP/1.1 200 OK
   Date: Sat, 24 August 2021 10:12:14 GMT
   Server: example-server
   Content-Type: application/yang.data+xml

   <output
   xmlns="urn:ietf:params:xml:ns:yang:ietf-SZTP-bootstrap-server">
   <reporting-level>enum</reporting-level>
   <conveyed-information>base64encodedvalue==</conveyed-information>
   <owner-certificate>base64encodedvalue==</owner-certificate>
   <ownership-voucher>base64encodedvalue==</ownership-voucher>
   </output>"""

   # enclose the base64 encoded data in XML response
   if not conveyedInfo:
      return ""
   conveyedInfoXml = "\n<conveyed-information>\n{}</conveyed-information>".format(
      conveyedInfo )
   ownerCertificateXml = ""
   if ownerCertificate:
      ownerCertificateXml = "\n<owner-certificate>\n{}</owner-certificate>".format(
         ownerCertificate )

   ownershipVoucherXml = ""
   if ownershipVoucher:
      ownershipVoucherXml = "\n<ownership-voucher>\n{}</ownership-voucher>".format(
         ownershipVoucher )

   reportingLevelXml = ""
   if reportingLevel:
      reportingLevelXml = "\n<reporting-level>{}</reporting-level>".format(
         reportingLevel )

   bootstrappingDataResponseXml = \
"""<output xmlns="urn:ietf:params:xml:ns:yang:ietf-SZTP-bootstrap-server">
{reportingLevelXml}{conveyedInfoXml}{ownerCertificateXml}{ownershipVoucherXml}
</output>
""".format( reportingLevelXml=reportingLevelXml,
            conveyedInfoXml=conveyedInfoXml,
            ownerCertificateXml=ownerCertificateXml,
            ownershipVoucherXml=ownershipVoucherXml )

   # save to httpd file
   return createHttpdResponseFile( bootstrappingDataResponseXml )

def genSztpBootstrapResponseFile( conveyedInfoFileJson, reportingLevel ):
   """Generate unsigned bootstrap restconf response that will only contain
   cms-unsigned(conveyed-information(json))."""

   # CMS wrap this data (unsigned)
   conveyedInfoCms = opensslCmsDataCreate( conveyedInfoFileJson )

   # XML encode the artifacts (conveyedInfo only)
   return genBootstrappingDataResponseFile( conveyedInfo=conveyedInfoCms,
                                            reportingLevel=reportingLevel )

def genSztpSignedBootstrapResponseFile( conveyedInfoFileJson, ownerCert, ownerKey,
                                        ownershipVoucher, manufacturerCert,
                                        manufacturerKey,
                                        reportingLevel ):
   """ generate signed bootstrap restconf file that will contain
   cms-signed(conveyed-information(json), owner-cert)
   cms(owner-certificate)
   cms-signed(ownership-voucher, manufacturer-cert)."""

   # CMS sign and wrap the conveyed-info using the ownerCert
   conveyedInfoCms = opensslCmsSignedDataCreate(
      conveyedInfoFileJson, ownerCert, ownerKey )

   # CMS wrap the owner-certificate
   ownerCertificateCms = opensslCmsCertCreate( ownerCert )

   # CMS sign and wrap the ownership-voucher using manufacturerCert
   ownershipVoucherCms = opensslCmsSignedDataCreate(
      ownershipVoucher, manufacturerCert, manufacturerKey )

   # XML encode all artifacts
   return genBootstrappingDataResponseFile( conveyedInfo=conveyedInfoCms,
                                            ownerCertificate=ownerCertificateCms,
                                            ownershipVoucher=ownershipVoucherCms,
                                            reportingLevel=reportingLevel )
