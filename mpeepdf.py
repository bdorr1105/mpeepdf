#!/usr/bin/env python

#
# peepdf is a tool to analyse and modify PDF files
#    http://peepdf.eternal-todo.com
#    By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#    Copyright (C) 2011-2017 Jose Miguel Esparza
#
#    This file is part of peepdf.
#
#        peepdf is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        (at your option) any later version.
#
#        peepdf is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with peepdf.    If not, see <http://www.gnu.org/licenses/>.
#

'''
    Initial script to launch the tool
'''

import sys
import os
import optparse
import re
import urllib2
import hashlib
import traceback
import json
from datetime import datetime
from PDFCore import PDFParser, vulnsDict
from PDFUtils import vtcheck
from PDFConstants import *

try:
    import PyV8
    JS_MODULE = True
except:
    JS_MODULE = False
try:
    import pylibemu
    EMU_MODULE = True
except:
    EMU_MODULE = False
try:
    from colorama import init, Fore, Back, Style
    COLORIZED_OUTPUT = True
except:
    COLORIZED_OUTPUT = False
try:
    from PIL import Image
    PIL_MODULE = True
except:
    PIL_MODULE = False


def getRepPaths(url, path=''):
    paths = []
    try:
        browsingPage = urllib2.urlopen(url + path).read()
    except:
        sys.exit('[x] Connection error while getting browsing page "' + url + path + '"')
    browsingPageObject = json.loads(browsingPage)
    for file in browsingPageObject:
        if file['type'] == 'file':
            paths.append(file['path'])
        elif file['type'] == 'dir':
            dirPaths = getRepPaths(url, file['path'])
            paths += dirPaths
    return paths


def getLocalFilesInfo(filesList):
    localFilesInfo = {}
    print '[-] Getting local files information...'
    for path in filesList:
        absFilePath = os.path.join(absPeepdfRoot, path)
        if os.path.exists(absFilePath):
            content = open(absFilePath, 'rb').read()
            shaHash = hashlib.sha256(content).hexdigest()
            localFilesInfo[path] = [shaHash, absFilePath]
    print '[+] Done'
    return localFilesInfo


def getPeepXML(statsDict, version, revision):
    root = etree.Element('peepdf_analysis', version=version + ' r' + revision)
    analysisDate = etree.SubElement(root, 'date')
    analysisDate.text = datetime.today().strftime('%Y-%m-%d %H:%M')
    basicInfo = etree.SubElement(root, 'basic')
    fileName = etree.SubElement(basicInfo, 'filename')
    fileName.text = statsDict['File']
    md5 = etree.SubElement(basicInfo, 'md5')
    md5.text = statsDict['MD5']
    sha1 = etree.SubElement(basicInfo, 'sha1')
    sha1.text = statsDict['SHA1']
    sha256 = etree.SubElement(basicInfo, 'sha256')
    sha256.text = statsDict['SHA256']
    size = etree.SubElement(basicInfo, 'size')
    size.text = statsDict['Size']
    pagesCount = statsDict['Pages Number']
    if pagesCount is not None:
        pages = etree.SubElement(basicInfo, 'pages')
        pages.text = statsDict['Pages Number']
    detection = etree.SubElement(basicInfo, 'detection')
    if statsDict['Detection']:
        detectionRate = etree.SubElement(detection, 'rate')
        detectionRate.text = '%d/%d' % (statsDict['Detection'][0], statsDict['Detection'][1])
        detectionReport = etree.SubElement(detection, 'report_link')
        detectionReport.text = statsDict['Detection report']
    version = etree.SubElement(basicInfo, 'pdf_version')
    version.text = statsDict['Version']
    binary = etree.SubElement(basicInfo, 'binary', status=statsDict['Binary'].lower())
    linearized = etree.SubElement(basicInfo, 'linearized', status=statsDict['Linearized'].lower())
    encrypted = etree.SubElement(basicInfo, 'encrypted', status=statsDict['Encrypted'].lower())
    if statsDict['Encryption Algorithms']:
        algorithms = etree.SubElement(encrypted, 'algorithms')
        for algorithmInfo in statsDict['Encryption Algorithms']:
            algorithm = etree.SubElement(algorithms, 'algorithm', bits=str(algorithmInfo[1]))
            algorithm.text = algorithmInfo[0]
    updates = etree.SubElement(basicInfo, 'updates')
    updates.text = statsDict['Updates']
    objects = etree.SubElement(basicInfo, 'num_objects')
    objects.text = statsDict['Objects']
    streams = etree.SubElement(basicInfo, 'num_streams')
    streams.text = statsDict['Streams']
    comments = etree.SubElement(basicInfo, 'comments')
    comments.text = statsDict['Comments']
    errors = etree.SubElement(basicInfo, 'errors', num=str(len(statsDict['Errors'])))
    for error in statsDict['Errors']:
        errorMessageXML = etree.SubElement(errors, 'error_message')
        errorMessageXML.text = error
    advancedInfo = etree.SubElement(root, 'advanced')
    suspiciousProperties = etree.SubElement(advancedInfo, 'suspicious_global_properties')
    if statsDict['suspiciousProperties']:
        for suspiciousProperty in statsDict['suspiciousProperties']:
            suspiciousPropertyInfo = etree.SubElement(suspiciousProperties, 'suspicious_global_property', name=suspiciousProperty)
    for version in range(len(statsDict['Versions'])):
        statsVersion = statsDict['Versions'][version]
        if version == 0:
            versionType = 'original'
        else:
            versionType = 'update'
        versionInfo = etree.SubElement(advancedInfo, 'version', num=str(version), type=versionType)
        catalog = etree.SubElement(versionInfo, 'catalog')
        if statsVersion['Catalog'] is not None:
            catalog.set('object_id', statsVersion['Catalog'])
        info = etree.SubElement(versionInfo, 'info')
        if statsVersion['Info'] is not None:
            info.set('object_id', statsVersion['Info'])
        objects = etree.SubElement(versionInfo, 'objects', num=statsVersion['Objects'][0])
        for id in statsVersion['Objects'][1]:
            object = etree.SubElement(objects, 'object', id=str(id))
            if statsVersion['Compressed Objects'] is not None:
                if id in statsVersion['Compressed Objects'][1]:
                    object.set('compressed', 'true')
                else:
                    object.set('compressed', 'false')
            if statsVersion['Errors'] is not None:
                if id in statsVersion['Errors'][1]:
                    object.set('errors', 'true')
                else:
                    object.set('errors', 'false')
        streams = etree.SubElement(versionInfo, 'streams', num=statsVersion['Streams'][0])
        for id in statsVersion['Streams'][1]:
            stream = etree.SubElement(streams, 'stream', id=str(id))
            if statsVersion['Xref Streams'] is not None:
                if id in statsVersion['Xref Streams'][1]:
                    stream.set('xref_stream', 'true')
                else:
                    stream.set('xref_stream', 'false')
            if statsVersion['Object Streams'] is not None:
                if id in statsVersion['Object Streams'][1]:
                    stream.set('object_stream', 'true')
                else:
                    stream.set('object_stream', 'false')
            if statsVersion['Encoded'] is not None:
                if id in statsVersion['Encoded'][1]:
                    stream.set('encoded', 'true')
                    if statsVersion['Decoding Errors'] is not None:
                        if id in statsVersion['Decoding Errors'][1]:
                            stream.set('decoding_errors', 'true')
                        else:
                            stream.set('decoding_errors', 'false')
                else:
                    stream.set('encoded', 'false')
        jsObjects = etree.SubElement(versionInfo, 'js_objects')
        if statsVersion['Objects with JS code'] is not None:
            for id in statsVersion['Objects with JS code'][1]:
                etree.SubElement(jsObjects, 'container_object', id=str(id))
        actions = statsVersion['Actions']
        events = statsVersion['Events']
        vulns = statsVersion['Vulns']
        properties = statsVersion['Properties']
        elements = statsVersion['Elements']
        indicators = statsVersion['Indicators']
        suspicious = etree.SubElement(versionInfo, 'suspicious_elements')
        if events != None or actions != None or vulns != None or elements != None:
            if events:
                triggers = etree.SubElement(suspicious, 'triggers')
                for event in events:
                    trigger = etree.SubElement(triggers, 'trigger', name=event)
                    for id in events[event]:
                        etree.SubElement(trigger, 'container_object', id=str(id))
            if actions:
                actionsList = etree.SubElement(suspicious, 'actions')
                for action in actions:
                    actionInfo = etree.SubElement(actionsList, 'action', name=action)
                    for id in actions[action]:
                        etree.SubElement(actionInfo, 'container_object', id=str(id))
            if elements:
                elementsList = etree.SubElement(suspicious, 'elements')
                for element in elements:
                    elementInfo = etree.SubElement(elementsList, 'element', name=element)
                    if vulnsDict.has_key(element):
                        vulnName = vulnsDict[element][0]
                        vulnCVEList = vulnsDict[element][1]
                        for vulnCVE in vulnCVEList:
                            cve = etree.SubElement(elementInfo, 'cve')
                            cve.text = vulnCVE
                    for id in elements[element]:
                        etree.SubElement(elementInfo, 'container_object', id=str(id))
            if vulns:
                vulnsList = etree.SubElement(suspicious, 'js_vulns')
                for vuln in vulns:
                    vulnInfo = etree.SubElement(vulnsList, 'vulnerable_function', name=vuln)
                    if vulnsDict.has_key(vuln):
                        vulnName = vulnsDict[vuln][0]
                        vulnCVEList = vulnsDict[vuln][1]
                        for vulnCVE in vulnCVEList:
                            cve = etree.SubElement(vulnInfo, 'cve')
                            cve.text = vulnCVE
                    for id in vulns[vuln]:
                        etree.SubElement(vulnInfo, 'container_object', id=str(id))
        suspiciousIndicators = etree.SubElement(versionInfo, 'suspicious_indicators')
        if indicators:
            for indicator in indicators:
                etree.SubElement(suspiciousIndicators, 'suspicious_indicator', name=indicator)
        suspiciousProperties = etree.SubElement(versionInfo, 'suspicious_properties')
        if properties:
            for property in properties:
                etree.SubElement(suspiciousProperties, 'property', name=property)
        urls = statsVersion['URLs']
        suspiciousURLs = etree.SubElement(versionInfo, 'suspicious_urls')
        if urls != None:
            for url in urls:
                urlInfo = etree.SubElement(suspiciousURLs, 'url')
                urlInfo.text = url
        # add Javascript
        jsCodes = statsVersion["javascriptCode"]
        javascriptCodes = etree.SubElement(versionInfo, 'javascriptCodes')
        if jsCodes:
            for jsCode in jsCodes:
                code = etree.SubElement(javascriptCodes, 'js')
                code.text = str(jsCode)
        # add unescaped bytes
        unescaped = statsVersion["unescapedBytes"]
        unescapedBytes = etree.SubElement(versionInfo, 'unescapedBytes')
        if unescapedBytes:
            for unescapedByte in unescapedBytes:
                byte = etree.SubElement(javascriptCodes, 'unescaped')
                byte.text =  str(unescapedByte)
    #Scoring
    scoringInfo = etree.SubElement(root, 'Scoring')
    
    if statsDict['Score']>=7:
        scoreMessage="HIGH probability of being malicious"
    elif statsDict['Score']>=4:
        scoreMessage="MEDIUM probability of being malicious"
    else:
        scoreMessage="LOW probability of being malicious"
    score = '%0.1f - %s' % (statsDict['Score'],scoreMessage)
    riskScore = etree.SubElement(scoringInfo, 'risk_score')
    riskScore.text = str(score)
    return etree.tostring(root, pretty_print=True)
      
def getPeepHTML(statsDict,jsCodesInPDF,urlsInPDF,unescapedBytesInPDF):
    html = """
    <!DOCTYPE html>
    <html>
    <head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
    .collapsible{
    background-color: #777;
    color: white;
    cursor: pointer;
    padding: 18px;
    width: 100%%;
    border: none;
    text-align: left;
    outline: none;
    font-size: 15px;}
    h2 {
    background-color: #777;
    color: white;
    }
    .active, .collapsible:hover {
    background-color: #555;
    }
    .content {
    padding: 0 18px;
    max-height: 0;
    overflow: hidden;
    transition: max-height 0.2s ease-out;
    background-color: #f1f1f1;
    }
    .mainContent {
    padding: 0 18px;
    max-height: 0;
    transition: max-height 0.2s ease-out;
    background-color: #f1f1f1;}

    .base{
    color: black;
    font-weight: bold;
    }
    .normal{
    olor: black;
    }

    .warning{
        color: orange;
    }
    .critical{
    color: red;
    }
    </style>
    </head>
    <body>
    <center> <h2>Analysis Report</h2> </center>
    <button class="collapsible" class="active">Summary</button>
    <div class="content">
    <pre>
    %s
    </pre>
    </div>

    <button class="collapsible">Found JS Code</button>
    <div class="content">
    <pre>
    %s
    </pre>
    </div>

    <button class="collapsible">Found URLs in JS</button>
    <div class="content">
    <pre>
    %s
    </pre>
    </div>

    <button class="collapsible">Found UnescapedBytes</button>
    <div class="content">
    <pre>
    %s
    </pre>
    </div>

    <button class="collapsible">Errors</button>
    <div class="content">
    <pre>
    %s
    </pre>
    </div>

    <script>

    var coll = document.getElementsByClassName("collapsible");
    var i;
    for (i = 0; i < coll.length; i++) {
    coll[i].addEventListener("click", function(){
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                if (content.style.maxHeight)
                {
                    content.style.maxHeight = null;
                } else{
                    content.style.maxHeight = content.scrollHeight + "px";
                }
        });
    }
    </script>
    </body>
    </html>
    """
    itemString = '<span class="%s"> %s </span> <span class="%s"> %s </span><br>'
    summarySession = '' + newLine
    jsCodesSession = '' + newLine
    urlsSession = '' + newLine
    unescapedBytesSession = '' + newLine
    errorSession = '' + newLine

    # Summary session
    #basic info
    summarySession += itemString % ("base","File: ","normal",statsDict['File']) + newLine
    summarySession += itemString % ("base","MD5: ","normal",statsDict['MD5']) + newLine
    summarySession += itemString % ("base","SHA1: ","normal",statsDict['SHA1']) + newLine
    summarySession += itemString % ("base","SHA256: ","normal",statsDict['SHA256']) + newLine
    summarySession += itemString % ("base","Size: ","normal",statsDict['Size']) + newLine
    summarySession += itemString % ("base","Pages Number: ","normal",str(statsDict['Pages Number'])) + newLine
    if statsDict['Detection'] != [] and statsDict['Detection'] is not None:
        if statsDict['Detection'][0] > 0:
            summarySession += itemString % ("base","VirusTotal Detection: ","warning",str(statsDict['Detection'][0])+"/"+str(statsDict['Detection'][1])) + newLine
        else:
            summarySession += itemString % ("base","VirusTotal Detection: ","normal",str(statsDict['Detection'][0])+"/"+statsDict['Detection'][1]) + newLine
    summarySession += itemString % ("base","Version: ","normal",statsDict['Version']) + newLine
    summarySession += itemString % ("base","Binary: ","normal",statsDict['Binary']) + newLine
    summarySession += itemString % ("base","Linearized: ","normal",statsDict['Linearized']) + newLine
    summarySession += itemString % ("base","Encrypted: ","normal",statsDict['Encrypted']) + newLine
    #advanced info
    summarySession += itemString % ("base","Updates: ","normal",statsDict['Updates']) + newLine
    summarySession += itemString % ("base","Objects: ","normal",statsDict['Objects']) + newLine
    summarySession += itemString % ("base","Streams: ","normal",statsDict['Streams']) + newLine
    summarySession += itemString % ("base","URIs: ","normal",statsDict['URIs']) + newLine
    summarySession += itemString % ("base","Comments: ","normal",statsDict['Comments']) + newLine
    summarySession += itemString % ("base","Errors: ","normal",str(len(statsDict['Errors']))) + newLine
    
    suspiciousProperties = statsDict['suspiciousProperties']
    if suspiciousProperties is not None:
        for suspiciousProperty in suspiciousProperties:
            summarySession += itemString % ("base","","warning",str(suspiciousProperty)) + newLine

    summarySession += "<br>" + newLine

    for version in range(len(statsDict['Versions'])):
        statsVersion = statsDict['Versions'][version]
        summarySession += itemString % ("base","Version ","normal",str(version)) + newLine
        if statsVersion['Catalog'] != None:
            summarySession += '\t' + itemString % ("base","Catalog: ","normal",statsVersion['Catalog']) + newLine
        else:
            summarySession += '\t' + itemString % ("base","Catalog: ","normal","no") + newLine

        if statsVersion['Info'] != None:
            summarySession += '\t' + itemString % ("base","Info: ","normal",statsVersion['Info']) + newLine
        else:
            summarySession += '\t' + itemString % ("base","Info: ","normal",statsVersion['Info']) + newLine
 
        summarySession += '\t' + itemString % ("base",'Objects (' + statsVersion['Objects'][0] + '): ',"normal",str(statsVersion['Objects'][1])) + newLine
        if statsVersion['Compressed Objects'] != None:
            summarySession += '\t' + itemString % ("base",'Compressed objects (' + statsVersion['Compressed Objects'][0] + '): ',"normal",str(statsVersion['Compressed Objects'][1])) + newLine
        if statsVersion['Errors'] != None:
            summarySession += '\t\t' + itemString % ("base",'Errors (' + statsVersion['Errors'][0] + '): ',"normal",str(statsVersion['Errors'][1])) + newLine
        summarySession += '\t' + itemString % ("base",'Streams (' + statsVersion['Streams'][0] + '): ',"normal",str(statsVersion['Streams'][1])) + newLine

        if statsVersion['Xref Streams'] != None:
            summarySession += '\t\t' + itemString % ("base",'Xref streams (' + statsVersion['Xref Streams'][0] + '): ',"normal",str(statsVersion['Xref Streams'][1])) + newLine

        if statsVersion['Object Streams'] != None:
            summarySession += '\t\t' + itemString % ("base",'Object streams (' + statsVersion['Object Streams'][0] + '): ',"normal",str(statsVersion['Object Streams'][1])) + newLine
        if int(statsVersion['Streams'][0]) > 0:
            summarySession += '\t\t' + itemString % ("base",'Encoded (' + statsVersion['Encoded'][0] + '): ',"normal",str(statsVersion['Encoded'][1])) + newLine
            if statsVersion['Decoding Errors'] != None:
                summarySession += '\t\t' + itemString % ("base",'Decoding errors (' + statsVersion['Decoding Errors'][0] + '): ',"normal",str(statsVersion['Decoding Errors'][1])) + newLine
        if statsVersion['URIs'] is not None:
            summarySession += '\t' + itemString % ("base",'Objects with URIs (' + statsVersion['URIs'][0] + '): ' ,"normal",str(statsVersion['URIs'][1])) + newLine
            summarySession += '\t' + itemString % ("base","Found URIs:" ,"normal","") + newLine
            for display in statsVersion['URIDisplay']:
                display=str(display)
                if "http" in display.lower():
                    summarySession += '\t\t' + itemString % ("base","" ,"normal",display) + newLine

        if statsVersion['Objects with JS code'] != None:
            summarySession += '\t' + itemString % ("warning",'Objects with JS code (' + statsVersion['Objects with JS code'][0] + '): ' ,"normal",str(statsVersion['Objects with JS code'][1])) + newLine


        actions = statsVersion['Actions']
        events = statsVersion['Events']
        vulns = statsVersion['Vulns']
        properties = statsVersion['Properties']
        elements = statsVersion['Elements']
        indicators = statsVersion['Indicators']
        if events != None or actions != None or vulns != None or elements != None:
            summarySession += '\t' + itemString % ("warning","Suspicious elements:" ,"normal","") + newLine
            if events != None:
                for event in events:
                    summarySession += '\t\t' + itemString % ("warning",event + ' (%d): ' % len(events[event]),"normal",str(events[event])) + newLine
            if actions != None:
                for action in actions:
                    summarySession += '\t\t' + itemString % ("warning",action + ' (%d): ' % len(actions[action]),"normal",str(actions[action])) + newLine
            if vulns != None:
                for vuln in vulns:
                    if vulnsDict.has_key(vuln):
                        vulnName = vulnsDict[vuln][0]
                        vulnCVEList = vulnsDict[vuln][1]
                        vulString = vulnName + ' ('
                        for vulnCVE in vulnCVEList:
                            vulString += vulnCVE + ','
                        summarySession += '\t\t' + itemString % ("warning",vulString + ') (%d): ' % len(vulns[vuln]),"normal",str(vulns[vuln])) + newLine

                    else:
                        summarySession += '\t\t' + itemString % ("warning",vuln + ' (%d): ' % len(vulns[vuln]),"normal",str(vulns[vuln])) + newLine
            if elements != None:
                for element in elements:
                    if vulnsDict.has_key(element):
                        vulnName = vulnsDict[element][0]
                        vulnCVEList = vulnsDict[element][1]
                        vulString = vulnName + ' ('
                        for vulnCVE in vulnCVEList:
                            vulString += vulnCVE + ','
                        summarySession += '\t\t' + itemString % ("warning",vulString + "): ","normal",str(elements[element])) + newLine
                    else:
                        summarySession += '\t\t' + itemString % ("warning",element + ": ","normal",str(elements[element])) + newLine

        if indicators is not None:
            summarySession += '\t' + itemString % ("warning","Suspicious Indicators:" ,"normal","") + newLine
            for indicator in indicators:
                summarySession += '\t\t' + itemString % ("warning",indicator,"normal",str(indicators[indicator])) + newLine

        if properties is not None:
            summarySession += '\t' + itemString % ("warning","Suspicious Properties:","normal","") + newLine
            for prop in properties:
                summarySession += '\t\t' + itemString % ("warning","","warning",str(prop)) + newLine
        unescapedBytes = statsVersion["unescapedBytes"]
        urls = statsVersion['URLs']
        if unescapedBytes != None or urls != None:
            summarySession += '\t' + itemString % ("warning","Automatic JS analysis:","warning","") + newLine
        if unescapedBytes != None:
            summarySession += '\t\t' + itemString % ("warning","Found unescaped bytes: ","warning",str(len(unescapedBytes))) + newLine
        if urls != None:
            summarySession += '\t\t' + itemString % ("warning","Found URLs: ","warning",str(len(urls))) + newLine
    #Scoring
    scoreColor= ''
    scoreMessage= ''
    if pdf.score >= 7:
        scoreColor = "critical"
        scoreMessage="HIGH probability of being malicious"
    elif pdf.score > 4 and pdf.score < 7:
        scoreColor = "warning"
        scoreMessage="MEDIUM probability of being malicious"
    else:
        scoreColor = "normal"
        scoreMessage="LOW probability of being malicious"
    summarySession += itemString % ("base","Maliciousness Score: ",scoreColor,str(pdf.score)+"-"+scoreMessage) + newLine

    #Javascript session
    if jsCodesInPDF:
        for jsCode in jsCodesInPDF:
            jsCodesSession +=itemString % ("warning","="*100,"normal","") + newLine
            jsCodesSession +=itemString % ("warning","="*100,"normal","") + newLine
            jsCodesSession +=itemString % ("base","","normal",str(jsCode)) + newLine
    else:
        jsCodesSession +=itemString % ("warning","","normal","There is no Javascript found") + newLine
    #URLs session
    if urlsInPDF:
        for url in urlsInPDF:
            urlsSession +=itemString % ("base","","normal",str(url)) + newLine
    else:
        urlsSession +=itemString % ("base","","normal","There is no URL found") + newLine
    #UnescapedBytes
    if unescapedBytesInPDF:
        for unescaped in unescapedBytesInPDF:
            unescapedBytesSession +=itemString % ("warning","="*100,"normal","") + newLine
            unescapedBytesSession +=itemString % ("warning","="*100,"normal","") + newLine
            unescapedBytesSession +=itemString % ("base","","normal",str(unescaped)) + newLine
    else:
        unescapedBytesSession +=itemString % ("warning","","normal","There is no unescaped bytes found") + newLine
    
    # Error session
    if not JS_MODULE:
        errorSession += itemString % ("base","Warning Message: ","warning","PyV8 is not installed!!") + newLine
    if not EMU_MODULE:
        errorSession += itemString % ("base","Warning Message: ","warning","pylibemu is not installed!!") + newLine
    if not PIL_MODULE:
        errorSession += itemString % ("base","Warning Message: ","warning","Python Imaging Library (PIL) is not installed!!") + newLine
    errors = statsDict['Errors']
    for error in errors:
        if error.find('Decryption error') != -1:
            errorSession += itemString % ("base","PeePDF errors: ","warning",str(error)) + newLine
    # In case of no error found
    if len(errorSession) < 2: # session string has minimum length of 1 due to newLine added
        errorSession = itemString % ("base","PeePDF errors: ","normal","There is no errors") + newLine
    return html % (summarySession,jsCodesSession,urlsSession,unescapedBytesSession,errorSession)
def getPeepJSON(statsDict, version, revision):
    # peepdf info
    peepdfDict = {'version': version,
                  'revision': revision,
                  'author': 'Tho Le',
                 }
    # Basic info
    basicDict = {}
    basicDict['filename'] = statsDict['File']
    basicDict['md5'] = statsDict['MD5']
    basicDict['sha1'] = statsDict['SHA1']
    basicDict['sha256'] = statsDict['SHA256']
    basicDict['size'] = int(statsDict['Size'])
    basicDict['detection'] = {}
    if statsDict['Detection'] != [] and statsDict['Detection'] is not None:
        basicDict['detection']['rate'] = '%d/%d' % (statsDict['Detection'][0], statsDict['Detection'][1])
        basicDict['detection']['report_link'] = statsDict['Detection report']
 
    basicDict['pdf_version'] = statsDict['Version']
    basicDict['binary'] = bool(statsDict['Binary'])
    basicDict['linearized'] = bool(statsDict['Linearized'])
    basicDict['encrypted'] = bool(statsDict['Encrypted'])
    basicDict['encryption_algorithms'] = []
    if statsDict['Encryption Algorithms']:
        for algorithmInfo in statsDict['Encryption Algorithms']:
            basicDict['encryption_algorithms'].append({'bits': algorithmInfo[1], 'algorithm': algorithmInfo[0]})
    basicDict['updates'] = int(statsDict['Updates'])
    basicDict['num_objects'] = int(statsDict['Objects'])
    basicDict['num_streams'] = int(statsDict['Streams'])
    basicDict['comments'] = int(statsDict['Comments'])
    basicDict['errors'] = []
    for error in statsDict['Errors']:
        basicDict['errors'].append(error)
    # Advanced info
    advancedInfo = []
    javascriptCodes = []
    unescapedBytes =  []

    advancedInfo.append({'suspicious_global_properties': statsDict['suspiciousProperties']})
    for version in range(len(statsDict['Versions'])):
        statsVersion = statsDict['Versions'][version]
        if version == 0:
            versionType = 'original'
        else:
            versionType = 'update'
        versionInfo = {}
        versionInfo['version_number'] = version
        versionInfo['version_type'] = versionType
        versionInfo['catalog'] = statsVersion['Catalog']
        versionInfo['info'] = statsVersion['Info']
        if statsVersion['Objects'] is not None:
            versionInfo['objects'] = statsVersion['Objects'][1]
        else:
            versionInfo['objects'] = []
        if statsVersion['Compressed Objects'] is not None:
            versionInfo['compressed_objects'] = statsVersion['Compressed Objects'][1]
        else:
            versionInfo['compressed_objects'] = []
        if statsVersion['Errors'] is not None:
            versionInfo['error_objects'] = statsVersion['Errors'][1]
        else:
            versionInfo['error_objects'] = []
        if statsVersion['Streams'] is not None:
            versionInfo['streams'] = statsVersion['Streams'][1]
        else:
            versionInfo['streams'] = []
        if statsVersion['Xref Streams'] is not None:
            versionInfo['xref_streams'] = statsVersion['Xref Streams'][1]
        else:
            versionInfo['xref_streams'] = []
        if statsVersion['Encoded'] is not None:
            versionInfo['encoded_streams'] = statsVersion['Encoded'][1]
        else:
            versionInfo['encoded_streams'] = []
        if versionInfo['encoded_streams'] and statsVersion['Decoding Errors'] is not None:
            versionInfo['decoding_error_streams'] = statsVersion['Decoding Errors'][1]
        else:
            versionInfo['decoding_error_streams'] = []
        if statsVersion['Objects with JS code'] is not None:
            versionInfo['js_objects'] = statsVersion['Objects with JS code'][1]
        else:
            versionInfo['js_objects'] = []
        elements = statsVersion['Elements']
        elementArray = []
        if elements:
            for element in elements:
                elementInfo = {'name': element}
                if element in vulnsDict:
                    elementInfo['vuln_name'] = vulnsDict[element][0]
                    elementInfo['vuln_cve_list'] = vulnsDict[element][1]
                elementInfo['objects'] = elements[element]
                elementArray.append(elementInfo)
        vulns = statsVersion['Vulns']
        vulnArray = []
        if vulns:
            for vuln in vulns:
                vulnInfo = {'name': vuln}
                if vuln in vulnsDict:
                    vulnInfo['vuln_name'] = vulnsDict[vuln][0]
                    vulnInfo['vuln_cve_list'] = vulnsDict[vuln][1]
                vulnInfo['objects'] = vulns[vuln]
                vulnArray.append(vulnInfo)
        versionInfo['suspicious_elements'] = {'triggers': statsVersion['Events'],
                                              'actions': statsVersion['Actions'],
                                              'elements': elementArray,
                                              'js_vulns': vulnArray,
                                              'urls': statsVersion['URLs']}
        properties = statsVersion['Properties']
        propertiesArray = []
        if properties:
            for prop in properties:
                propInfo = {'name': prop}
                propertiesArray.append(propInfo)
        indicators = statsVersion['Indicators']
        indicatorArray = []
        if indicators:
            for indicator in indicators:
                indicatorInfo = {'name': indicator}
                indicatorInfo['objects'] = indicators[indicator]
                indicatorArray.append(indicatorInfo)
        versionInfo['suspicious_properties'] = {'suspicious_properties': propertiesArray}
        versionInfo['suspicious_indicators'] = {'suspicious_indicators': indicatorArray}
        versionReport = {'version_info': versionInfo}
        advancedInfo.append(versionReport)
        # Javascript codes
        javascriptCodes.append({version:statsVersion["javascriptCode"]})
        # unescaped bytes founds
        unescapedBytes.append({version:str(statsVersion["unescapedBytes"])})
    
    #Scoring  
    scoreMessage = ''
    if statsDict['Score']>=7:
        scoreMessage="HIGH probability of being malicious"
    elif statsDict['Score']>=4:
        scoreMessage="MEDIUM probability of being malicious"
    else:
        scoreMessage="LOW probability of being malicious"
    score = '%0.1f - %s' % (statsDict['Score'],scoreMessage)

    #generate json output
    jsonDict = {'peepdf_analysis':
                    {'peepdf_info': peepdfDict,
                     'date': datetime.today().strftime('%Y-%m-%d %H:%M'),
                     'basic': basicDict,
                     'advanced': advancedInfo,
                     'scoring':{"risk_score":score},
                     'javascriptCode': javascriptCodes,
                     'unescapedBytes': unescapedBytes
                    }
                }
    return json.dumps(jsonDict, indent=4, sort_keys=True)

if __name__ == "__main__":
    stats = ''
    pdf = None
    fileName = None
    statsDict = None
    vtJsonDict = None
    newLine = os.linesep
    absPeepdfRoot = os.path.dirname(os.path.realpath(sys.argv[0]))
    errorsFile = os.path.join(absPeepdfRoot, 'errors.txt')

    versionHeader = 'Version: peepdf ' + version + ' r' + revision
    peepdfHeader = versionHeader + newLine * 2 + \
                url + newLine + \
                peepTwitter + newLine + \
                email + newLine * 2 + \
                author + newLine + \
                twitter + newLine

    argsParser = optparse.OptionParser(usage='Usage: peepdf.py [options] PDF_file', description=versionHeader)
    argsParser.add_option('-i', '--interactive', action='store_true', dest='isInteractive', default=False,
                        help='Sets console mode.')
    argsParser.add_option('-s', '--load-script', action='store', type='string', dest='scriptFile',
                        help='Loads the commands stored in the specified file and execute them.')
    argsParser.add_option('-c', '--check-vt', action='store_true', dest='checkOnVT', default=False,
                        help='Checks the hash of the PDF file on VirusTotal.')
    argsParser.add_option('-f', '--force-mode', action='store_true', dest='isForceMode', default=False,
                        help='Sets force parsing mode to ignore errors.')
    argsParser.add_option('-l', '--loose-mode', action='store_true', dest='isLooseMode', default=False,
                        help='Sets loose parsing mode to catch malformed objects.')
    argsParser.add_option('-m', '--manual-analysis', action='store_true', dest='isManualAnalysis', default=False,
                        help='Avoids automatic Javascript analysis. Useful with eternal loops like heap spraying.')
    argsParser.add_option('-u', '--update', action='store_true', dest='update', default=False,
                        help='Updates peepdf with the latest files from the repository.')
    argsParser.add_option('-g', '--grinch-mode', action='store_true', dest='avoidColors', default=False,
                        help='Avoids colorized output in the interactive console.')
    argsParser.add_option('-v', '--version', action='store_true', dest='version', default=False,
                        help='Shows program\'s version number.')
    argsParser.add_option('-x', '--xml', action='store', dest='xmlPath', type='string',
                        help='Exports the document information in XML format.')
    argsParser.add_option('-j', '--json', action='store', dest='jsonPath', type='string',
                        help='Exports the document information in JSON format.')
    argsParser.add_option('-w', '--html', action='store', dest='htmlPath', type='string',
                        help='Exports the document information in JSON format.')
    argsParser.add_option('-C', '--command', action='append', type='string', dest='commands',
                        help='Specifies a command from the interactive console to be executed.')
    (options, args) = argsParser.parse_args()

    try:
        # Avoid colors in the output
        if not COLORIZED_OUTPUT or options.avoidColors:
            warningColor = ''
            errorColor = ''
            alertColor = ''
            staticColor = ''
            resetColor = ''
        else:
            warningColor = Fore.YELLOW
            errorColor = Fore.RED
            alertColor = Fore.RED
            staticColor = Fore.BLUE
            resetColor = Style.RESET_ALL
        if options.version:
            print peepdfHeader
        elif options.update:
            updated = False
            newVersion = ''
            localVersion = 'v' + version + ' r' + revision
            reVersion = 'version = \'(\d\.\d)\'\s*?revision = \'(\d+)\''
            repURL = 'https://api.github.com/repos/tholep/mpeepdf/contents/'
            rawRepURL = 'https://api.github.com/repos/tholep/mpeepdf/contents/'
            print '[-] Checking if there are new updates...'
            try:
                remotePeepContent = urllib2.urlopen(rawRepURL + 'peepdf.py').read()
            except:
                sys.exit('[x] Connection error while trying to connect with the repository')
            repVer = re.findall(reVersion, remotePeepContent)
            if repVer:
                newVersion = 'v' + repVer[0][0] + ' r' + repVer[0][1]
            else:
                sys.exit('[x] Error getting the version number from the repository')
            if localVersion == newVersion:
                print '[+] No changes! ;)'
            else:
                print '[+] There are new updates!!'
                print '[-] Getting paths from the repository...'
                pathNames = getRepPaths(repURL, '')
                print '[+] Done'
                localFilesInfo = getLocalFilesInfo(pathNames)
                print '[-] Checking files...'
                for path in pathNames:
                    try:
                        fileContent = urllib2.urlopen(rawRepURL + path).read()
                    except:
                        sys.exit('[x] Connection error while getting file "' + path + '"')
                    if path in localFilesInfo:
                        # File exists
                        # Checking hash
                        shaHash = hashlib.sha256(fileContent).hexdigest()
                        if shaHash != localFilesInfo[path][0]:
                            open(localFilesInfo[path][1], 'wb').write(fileContent)
                            print '[+] File "' + path + '" updated successfully'
                    else:
                        # File does not exist
                        index = path.rfind('/')
                        if index != -1:
                            dirsPath = path[:index]
                            absDirsPath = os.path.join(absPeepdfRoot, dirsPath)
                            if not os.path.exists(absDirsPath):
                                print '[+] New directory "' + dirsPath + '" created successfully'
                                os.makedirs(absDirsPath)
                        open(os.path.join(absPeepdfRoot, path), 'wb').write(fileContent)
                        print '[+] New file "' + path + '" created successfully'
                message = '[+] peepdf updated successfully'
                if newVersion != '':
                    message += ' to ' + newVersion

        else:
            if len(args) == 1:
                fileName = args[0]
                if not os.path.exists(fileName):
                    sys.exit('Error: The file "' + fileName + '" does not exist!!')
                elif not os.path.isfile(fileName):
                    sys.exit('Error: "' + fileName + '" is not a file!!')
            elif len(args) > 1 or (len(args) == 0 and not options.isInteractive):
                sys.exit(argsParser.print_help())

            if options.scriptFile is not None:
                if not os.path.exists(options.scriptFile):
                    sys.exit('Error: The script file "' + options.scriptFile + '" does not exist!!')

            if fileName is not None:
                pdfParser = PDFParser()
                # print options.isForceMode, options.isLooseMode, options.isManualAnalysis
                ret, pdf = pdfParser.parse(fileName, options.isForceMode, options.isLooseMode, options.isManualAnalysis, options.checkOnVT)
                if options.checkOnVT and pdf.detectionRate == []:
                    # Checks the MD5 on VirusTotal
                    md5Hash = pdf.getMD5()
                    ret = vtcheck(md5Hash, VT_KEY)
                    if ret[0] == -1:
                        pdf.addError(ret[1])
                    else:
                        vtJsonDict = ret[1]
                        if vtJsonDict.has_key('response_code'):
                            if vtJsonDict['response_code'] == 1:
                                if vtJsonDict.has_key('positives') and vtJsonDict.has_key('total'):
                                    pdf.setDetectionRate([vtJsonDict['positives'], vtJsonDict['total']])
                                else:
                                    pdf.addError('Missing elements in the response from VirusTotal!!')
                                if vtJsonDict.has_key('permalink'):
                                    pdf.setDetectionReport(vtJsonDict['permalink'])
                            else:
                                pdf.setDetectionRate(None)
                        else:
                            pdf.addError('Bad response from VirusTotal!!')
                statsDict = pdf.getStats()

            if options.xmlPath:
                try:
                    from lxml import etree

                    xml = getPeepXML(statsDict, version, revision)
                    with open(options.xmlPath,"wb") as file:
                        file.write(xml)
                except:
                    errorMessage = '*** Error: Exception while generating the XML file!!'
                    traceback.print_exc(file=open(errorsFile, 'a'))
                    raise Exception('PeepException', 'Send me an email ;)')
            elif options.jsonPath and not options.commands:
                try:
                    jsonReport = getPeepJSON(statsDict, version, revision)
                    with open(options.jsonPath,"wb") as file:
                        file.write(jsonReport)
                except:
                    errorMessage = '*** Error: Exception while generating the JSON report!!'
                    traceback.print_exc(file=open(errorsFile, 'a'))
                    raise Exception('PeepException', 'Send me an email ;)')
            elif options.htmlPath and not options.commands:
            
                #export an html report, can be used in webserver later on.
                try:
                    extractedJSCodes = []
                    extractedURLs = []
                    extractedUnescapedBytes= []
                    for body in pdf.body:
                        jsCodes = body.getJSCode()
                        for js in jsCodes:
                            if js not in extractedJSCodes:
                                extractedJSCodes.append(js)
                    
                        urls = body.getURLs()
                        for url in urls:
                            if url not in extractedURLs:
                                extractedURLs.append(url)

                        unescapedBytes = body.getUnescapedBytes()
                        for unescaped in unescapedBytes:
                            if unescaped not in extractedUnescapedBytes:
                                extractedUnescapedBytes.append(unescaped)

                    htmlReport = getPeepHTML(statsDict,extractedJSCodes,extractedURLs,extractedUnescapedBytes)
                    with open(options.htmlPath,"wb") as file:
                        file.write(htmlReport)
                except:
                    errorMessage = '*** Error: Exception while generating the HTML report!!'
                    traceback.print_exc(file=open(errorsFile, 'a'))
                    raise Exception('PeepException', 'Send me an email ;)')
            else:
                if COLORIZED_OUTPUT and not options.avoidColors:
                    try:
                        init()
                    except:
                        COLORIZED_OUTPUT = False
                if options.scriptFile is not None:
                    from PDFConsole import PDFConsole

                    scriptFileObject = open(options.scriptFile, 'rb')
                    console = PDFConsole(pdf, VT_KEY, options.avoidColors, stdin=scriptFileObject)
                    try:
                        console.cmdloop()
                    except:
                        errorMessage = '*** Error: Exception not handled using the batch mode!!'
                        scriptFileObject.close()
                        traceback.print_exc(file=open(errorsFile, 'a'))
                        raise Exception('PeepException', 'Send me an email ;)')
                elif options.commands is not None:
                    from PDFConsole import PDFConsole

                    console = PDFConsole(pdf, VT_KEY, options.avoidColors)
                    try:
                        for command in options.commands:
                            console.onecmd(command)
                    except:
                        errorMessage = '*** Error: Exception not handled using the batch commands!!'
                        traceback.print_exc(file=open(errorsFile, 'a'))
                        raise Exception('PeepException', 'Send me an email ;)')
                else:
                    if statsDict is not None:
                        if COLORIZED_OUTPUT and not options.avoidColors:
                            beforeStaticLabel = staticColor
                        else:
                            beforeStaticLabel = ''

                        if not JS_MODULE:
                            warningMessage = 'Warning: PyV8 is not installed!!'
                            stats += warningColor + warningMessage + resetColor + newLine
                        if not EMU_MODULE:
                            warningMessage = 'Warning: pylibemu is not installed!!'
                            stats += warningColor + warningMessage + resetColor + newLine
                        if not PIL_MODULE:
                            warningMessage = 'Warning: Python Imaging Library (PIL) is not installed!!'
                            stats += warningColor + warningMessage + resetColor + newLine
                        errors = statsDict['Errors']
                        for error in errors:
                            if error.find('Decryption error') != -1:
                                stats += errorColor + error + resetColor + newLine
                        if stats != '':
                            stats += newLine
                        statsDict = pdf.getStats()

                        stats += beforeStaticLabel + 'File: ' + resetColor + statsDict['File'] + newLine
                        stats += beforeStaticLabel + 'MD5: ' + resetColor + statsDict['MD5'] + newLine
                        stats += beforeStaticLabel + 'SHA1: ' + resetColor + statsDict['SHA1'] + newLine
                        stats += beforeStaticLabel + 'SHA256: ' + resetColor + statsDict['SHA256'] + newLine
                        stats += beforeStaticLabel + 'Size: ' + resetColor + statsDict['Size'] + ' bytes' + newLine
                        pagesCount = statsDict['Pages Number']
                        stats += beforeStaticLabel + 'Pages Number: ' + resetColor + str(pagesCount) + newLine
                        if options.checkOnVT:
                            if statsDict['Detection'] != []:
                                detectionReportInfo = ''
                                if statsDict['Detection'] != None:
                                    detectionColor = ''
                                    if COLORIZED_OUTPUT and not options.avoidColors:
                                        detectionLevel = statsDict['Detection'][0] / (statsDict['Detection'][1] / 3)
                                        if detectionLevel == 0:
                                            detectionColor = alertColor
                                        elif detectionLevel == 1:
                                            detectionColor = warningColor
                                    detectionRate = '%s%d%s/%d' % (
                                        detectionColor, statsDict['Detection'][0], resetColor, statsDict['Detection'][1])
                                    if statsDict['Detection report'] != '':
                                        detectionReportInfo = beforeStaticLabel + 'Detection report: ' + resetColor + \
                                                            statsDict['Detection report'] + newLine
                                else:
                                    detectionRate = 'File not found on VirusTotal'
                                stats += beforeStaticLabel + 'Detection: ' + resetColor + detectionRate + newLine
                                stats += detectionReportInfo
                        stats += beforeStaticLabel + 'Version: ' + resetColor + statsDict['Version'] + newLine
                        stats += beforeStaticLabel + 'Binary: ' + resetColor + statsDict['Binary'] + newLine
                        stats += beforeStaticLabel + 'Linearized: ' + resetColor + statsDict['Linearized'] + newLine
                        stats += beforeStaticLabel + 'Encrypted: ' + resetColor + statsDict['Encrypted']
                        if statsDict['Encryption Algorithms'] != []:
                            stats += ' ('
                            for algorithmInfo in statsDict['Encryption Algorithms']:
                                stats += algorithmInfo[0] + ' ' + str(algorithmInfo[1]) + ' bits, '
                            stats = stats[:-2] + ')'
                        stats += newLine
                        stats += beforeStaticLabel + 'Updates: ' + resetColor + statsDict['Updates'] + newLine
                        stats += beforeStaticLabel + 'Objects: ' + resetColor + statsDict['Objects'] + newLine
                        stats += beforeStaticLabel + 'Streams: ' + resetColor + statsDict['Streams'] + newLine
                        stats += beforeStaticLabel + 'URIs: ' + resetColor + statsDict['URIs'] + newLine
                        stats += beforeStaticLabel + 'Comments: ' + resetColor + statsDict['Comments'] + newLine
                        stats += beforeStaticLabel + 'Errors: ' + resetColor + str(len(statsDict['Errors'])) + newLine
                        suspiciousProperties = statsDict['suspiciousProperties']
                        if suspiciousProperties is not None:
                            if COLORIZED_OUTPUT and not options.avoidColors:
                                beforeStaticLabel = warningColor
                            stats += beforeStaticLabel + 'Suspicious Properties:' + resetColor + newLine
                            for suspiciousProperty in suspiciousProperties:
                                stats += '\t' + beforeStaticLabel + suspiciousProperty + resetColor + newLine
                            if COLORIZED_OUTPUT and not options.avoidColors:
                                beforeStaticLabel = staticColor
                        stats += newLine
                        for version in range(len(statsDict['Versions'])):
                            statsVersion = statsDict['Versions'][version]
                            stats += beforeStaticLabel + 'Version ' + resetColor + str(version) + ':' + newLine
                            if statsVersion['Catalog'] != None:
                                stats += beforeStaticLabel + '\tCatalog: ' + resetColor + statsVersion['Catalog'] + newLine
                            else:
                                stats += beforeStaticLabel + '\tCatalog: ' + resetColor + 'No' + newLine
                            if statsVersion['Info'] != None:
                                stats += beforeStaticLabel + '\tInfo: ' + resetColor + statsVersion['Info'] + newLine
                            else:
                                stats += beforeStaticLabel + '\tInfo: ' + resetColor + 'No' + newLine
                            stats += beforeStaticLabel + '\tObjects (' + statsVersion['Objects'][
                                0] + '): ' + resetColor + str(statsVersion['Objects'][1]) + newLine
                            if statsVersion['Compressed Objects'] != None:
                                stats += beforeStaticLabel + '\tCompressed objects (' + statsVersion['Compressed Objects'][
                                    0] + '): ' + resetColor + str(statsVersion['Compressed Objects'][1]) + newLine
                            if statsVersion['Errors'] != None:
                                stats += beforeStaticLabel + '\t\tErrors (' + statsVersion['Errors'][
                                    0] + '): ' + resetColor + str(statsVersion['Errors'][1]) + newLine
                            stats += beforeStaticLabel + '\tStreams (' + statsVersion['Streams'][
                                0] + '): ' + resetColor + str(statsVersion['Streams'][1])
                            if statsVersion['Xref Streams'] != None:
                                stats += newLine + beforeStaticLabel + '\t\tXref streams (' + statsVersion['Xref Streams'][
                                    0] + '): ' + resetColor + str(statsVersion['Xref Streams'][1])
                            if statsVersion['Object Streams'] != None:
                                stats += newLine + beforeStaticLabel + '\t\tObject streams (' + \
                                        statsVersion['Object Streams'][0] + '): ' + resetColor + str(
                                    statsVersion['Object Streams'][1])
                            if int(statsVersion['Streams'][0]) > 0:
                                stats += newLine + beforeStaticLabel + '\t\tEncoded (' + statsVersion['Encoded'][
                                    0] + '): ' + resetColor + str(statsVersion['Encoded'][1])
                                if statsVersion['Decoding Errors'] != None:
                                    stats += newLine + beforeStaticLabel + '\t\tDecoding errors (' + \
                                            statsVersion['Decoding Errors'][0] + '): ' + resetColor + str(
                                        statsVersion['Decoding Errors'][1])
                            if statsVersion['URIs'] is not None:
                                stats += newLine + beforeStaticLabel + '\tObjects with URIs (' + \
                                        statsVersion['URIs'][0] + '): ' + resetColor + str(statsVersion['URIs'][1])
                                stats += newLine + beforeStaticLabel + '\tFound URIs : ' + resetColor
                                for display in statsVersion['URIDisplay']:
                                    display=str(display)
                                    if "http" in display.lower():
                                        stats += newLine + beforeStaticLabel + '\t\t' + resetColor + display
                            if COLORIZED_OUTPUT and not options.avoidColors:
                                beforeStaticLabel = warningColor
                            if statsVersion['Objects with JS code'] != None:
                                stats += newLine + beforeStaticLabel + '\tObjects with JS code (' + \
                                        statsVersion['Objects with JS code'][0] + '): ' + resetColor + str(
                                    statsVersion['Objects with JS code'][1])
                            actions = statsVersion['Actions']
                            events = statsVersion['Events']
                            vulns = statsVersion['Vulns']
                            properties = statsVersion['Properties']
                            elements = statsVersion['Elements']
                            indicators = statsVersion['Indicators']
                            if events != None or actions != None or vulns != None or elements != None:
                                stats += newLine + beforeStaticLabel + '\tSuspicious elements:' + resetColor + newLine
                                if events != None:
                                    for event in events:
                                        stats += '\t\t' + beforeStaticLabel + event + ' (%d): ' % len(events[event]) + \
                                                resetColor + str(events[event]) + newLine
                                if actions != None:
                                    for action in actions:
                                        stats += '\t\t' + beforeStaticLabel + action + ' (%d): ' % len(actions[action]) + \
                                                resetColor + str(actions[action]) + newLine
                                if vulns != None:
                                    for vuln in vulns:
                                        if vulnsDict.has_key(vuln):
                                            vulnName = vulnsDict[vuln][0]
                                            vulnCVEList = vulnsDict[vuln][1]
                                            stats += '\t\t' + beforeStaticLabel + vulnName + ' ('
                                            for vulnCVE in vulnCVEList:
                                                stats += vulnCVE + ','
                                            stats = stats[:-1] + ') (%d): ' % len(vulns[vuln]) + resetColor + str(vulns[vuln]) + newLine
                                        else:
                                            stats += '\t\t' + beforeStaticLabel + vuln + ' (%d): ' % len(vulns[vuln]) + \
                                                    resetColor + str(vulns[vuln]) + newLine
                                if elements != None:
                                    for element in elements:
                                        if vulnsDict.has_key(element):
                                            vulnName = vulnsDict[element][0]
                                            vulnCVEList = vulnsDict[element][1]
                                            stats += '\t\t' + beforeStaticLabel + vulnName + ' ('
                                            for vulnCVE in vulnCVEList:
                                                stats += vulnCVE + ','
                                            stats = stats[:-1] + '): ' + resetColor + str(elements[element]) + newLine
                                        else:
                                            stats += '\t\t' + beforeStaticLabel + element + ': ' + resetColor + str(elements[element]) + newLine
                            if indicators is not None:
                                stats += newLine + beforeStaticLabel + '\tSuspicious Indicators:' + resetColor + newLine
                                for indicator in indicators:
                                    stats += '\t\t' + beforeStaticLabel + indicator + ': ' + resetColor + str(indicators[indicator]) + newLine
                            if properties is not None:
                                stats += newLine + beforeStaticLabel + '\tSuspicious Properties:' + resetColor + newLine
                                for prop in properties:
                                    stats += '\t\t' + beforeStaticLabel + prop + newLine
                                                    
                            unescapedBytes = statsVersion["unescapedBytes"]
                            urls = statsVersion['URLs']
                            if unescapedBytes != None or urls != None:
                                stats += newLine + beforeStaticLabel + '\tAutomatic JS analysis:' + resetColor + newLine
                            if unescapedBytes != None:
                                stats += beforeStaticLabel + '\t\tFound Unescaped bytes (%s)' % str(len(unescapedBytes)) + resetColor + newLine
                            if urls != None:
                                stats += beforeStaticLabel + '\t\tFound URLs (%s)' % str(len(urls)) + resetColor + newLine
                            stats += newLine * 2
                            # reset color
                            if COLORIZED_OUTPUT and not options.avoidColors:
                                beforeStaticLabel = staticColor
                                
                        scoreColor= ''
                        scoreMessage= ''
                        if COLORIZED_OUTPUT and not options.avoidColors:
                            if pdf.score >= 7:
                                beforeStaticLabel = alertColor
                                scoreColor = alertColor
                                scoreMessage="HIGH probability of being malicious"
                            elif pdf.score > 4 and pdf.score < 7:
                                beforeStaticLabel = warningColor
                                scoreColor = warningColor
                                scoreMessage="MEDIUM probability of being malicious"
                            else:
                                scoreColor = resetColor
                                beforeStaticLabel = staticColor
                                scoreMessage="LOW probability of being malicious"
                        score = '%s%.1f%s/%d%s - %s' % (scoreColor, pdf.score, resetColor, 10,scoreColor,scoreMessage)
                        stats += beforeStaticLabel + 'Maliciousness Score: ' + scoreColor + str(score) + resetColor + newLine
                    if fileName != None:
                        print stats
                    if options.isInteractive:
                        from PDFConsole import PDFConsole

                        console = PDFConsole(pdf, VT_KEY, options.avoidColors)
                        while not console.leaving:
                            try:
                                console.cmdloop()
                            except KeyboardInterrupt as e:
                                sys.exit()
                            except:
                                errorMessage = '*** Error: Exception not handled using the interactive console!! Please, report it to the author!!'
                                print errorColor + errorMessage + resetColor + newLine
                                traceback.print_exc(file=open(errorsFile, 'a'))
    except Exception as e:
        if len(e.args) == 2:
            excName, excReason = e.args
        else:
            excName = excReason = None
        if excName == None or excName != 'PeepException':
            errorMessage = '*** Error: Exception not handled!!'
            traceback.print_exc(file=open(errorsFile, 'a'))
        print errorColor + errorMessage + resetColor + newLine
    finally:
        if os.path.exists(errorsFile):
            message = newLine + "This is a modified version of peepdf (https://github.com/jesparza/peepdf)." + newLine
            message += 'Please, don\'t forget to report the errors found:' + newLine * 2
            message += '\t- Creating an issue and upload the file "%s" to the project webpage (https://github.com/tholep/mpeepdf/issues)' % errorsFile + newLine
            message = errorColor + message + resetColor
            sys.exit(message)
