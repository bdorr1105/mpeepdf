# **mpeepdf is a modified version of peepdf**

mpeepdf is a **Python tool to explore PDF files** which provides security analysts and researcher a single powerful platform to investigate PDF. The ultimate goal of (m)peepdf is to provide a unique, all-you-need framework for security researchers and analysts to investigate a PDF file.


## **Notable functionalities**:

**1. PDF Parser:** provide an advanced parser that supports multiple compression/filter mechanisms as well as presents a PDF in both local and physical views which allows analysts to investigate all information in a single platform

  * Decodings: hexadecimal, octal, name objects
  * More used filters
  * References in objects and where an object is referenced
  * Strings search (including streams)
  * Physical structure (offsets)
  * Logical tree structure
  * Metadata
  * Modifications between versions (changelog)
  * Compressed objects (object streams)
  * Extraction of old versions of the document
  * Easy extraction of objects, Javascript code, shellcodes (>, >>, $>, $>>)
  * Detect known vulnerabilities and exploits which are highligted in the output as well as contributed to the maliciousness score
  * Checking hashes on **VirusTotal**
  * Suspicious Elements
  * Maliciousness score (by [Rohit Dua](https://www.honeynet.org/node/1304)) 

**2. Javascript analysis:**

  * Analysis and modification of Javascript (PyV8): unescape, replace, join
  * Enrich Javascript analysis with information in Info object (e.g author, created date), annotation data (to suplement dat for getAnnot() and getAnnots()) and field names in XML used in /XFA and /Acroform
  * Automatic Javascript analysis based on [JSUnpack method](https://github.com/urule99/jsunpack-n)
  * Shellcode analysis (Libemu python wrapper, pylibemu)



**3. Powerful Interactive Console:** This makes peepdf stand out from other tools since it provides you a framework to work on a parsed PDF.

  * Allow examining all data of a PDF including objects, streams, byte offset, tree view, offset view as well as other metadata such as changelog and hashes. Data can be examined in both raw or decompressed/parsed forms.
  * Support examining relationship between objects/streams via tree view as well as from references to/from an identified object.
  * Support 1-byte XOR as well as bruteforce XOR to a defined content
  * Support 1-byte XOR bruteforce to look for PE files embedded
  * Support variables assignment (via set command and display a variable content via show command). This allows analysts to create varabiles, assign values during their investigation.

**4.Creation/Modification:**

  * Basic PDF creation
  * Creation of PDF with Javascript executed wen the document is opened
  * Creation of object streams to compress objects
  * Embedded PDFs
  * Strings and names obfuscation
  * Malformed PDF output: without endobj, garbage in the header, bad header...
  * Filters modification
  * Objects modification


## **Changes in mpeepdf**:

1. Javascript analysis: adopt the JSUnpack approach: 

    (a)) enriching Javascript analysis by data in PDF files: metadata, anotation (supporting for getAnnot and getAnnots)
    (b) using a post processing script to capture escaped/unescaped strings
    (c) Overwrite Eval function to print out

2. Maliciousness score: This is done by (by [Rohit Dua](https://www.honeynet.org/node/1304)) and was implemented as a branch in the peepdf repository. Since the factors used for scoring are thorough, the author decided to merge into mpeepdf.

3. tree command: was modified to display more information regarding objects/streams as well as highlight "interesting" artefacts.

4. Javascript code detection: was modified to make it less sensitive to texts that have a-like characteristics as Javascript codes

5. Add URIs display: /URI(s) found in PDF will be displayed in the main output.

**TODO:**

  * Adop the logging library and enrich more logging inforamtion
  * Adop YAML to store all configuration
  * Build a web server
  * Support Flash analysis
  * Support other common de-ofruscation technique a part from XOR (cunrretly only support XOR via xor_search_pe)
  * Support Shellcode search


**Related articles:**

  * [Spammed CVE-2013-2729 PDF exploit dropping ZeuS-P2P/Gameover](http://eternal-todo.com/blog/cve-2013-2729-exploit-zeusp2p-gameover)
  * [New peepdf v0.2 (Version Black Hat Vegas 2012)](http://eternal-todo.com/blog/peepdf-v0.2-black-hat-usa-arsenal-vegas)
  * [peepdf supports CCITTFaxDecode encoded streams](http://eternal-todo.com/blog/peepdf-ccittfaxdecode-support)
  * [Explanation of the changelog of peepdf for Black Hat Europe Arsenal 2012](http://eternal-todo.com/blog/peepdf-black-hat-arsenal-2012)
  * [How to extract streams and shellcodes from a PDF, the easy way](http://eternal-todo.com/blog/extract-streams-shellcode-peepdf)
  * [Static analysis of a CVE-2011-2462 PDF exploit](http://eternal-todo.com/blog/cve-2011-2462-exploit-analysis-peepdf)
  * [Analysis of a malicious PDF from a SEO Sploit Pack](http://eternal-todo.com/blog/seo-sploit-pack-pdf-analysis)
  * Analysing the [Honeynet Project challenge PDF file](http://www.honeynet.org/challenges/2010_6_malicious_pdf) with peepdf [Part 1](http://eternal-todo.com/blog/analysing-honeynet-pdf-challenge-peepdf-i) [Part 2](http://eternal-todo.com/blog/analysing-honeynet-pdf-challenge-peepdf-ii)
  * [Analyzing Suspicious PDF Files With Peepdf](http://blog.zeltser.com/post/6780160077/peepdf-malicious-pdf-analysis)



**You are free to contribute with feedback, bugs, patches, etc. Any help is welcome.
