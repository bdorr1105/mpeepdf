# **mpeepdf is a modified version of peepdf**

mpeepdf is a **Python tool to explore PDF files** which provides security analysts and researcher a single powerful platform to investigate PDF.


## **Notable functionalities**:

1. **PDF Explore: parsing a PDF file**

  * Decodings: hexadecimal, octal, name objects
  * More used filters
  * References in objects and where an object is referenced
  * Strings search (including streams)
  * Physical structure (offsets)
  * Logical tree structure
  * Metadata
  * Modifications between versions (changelog)
  * Compressed objects (object streams)
  * Analysis and modification of Javascript (PyV8): unescape, replace, join
  * Shellcode analysis (Libemu python wrapper, pylibemu)
  * Variables (set command)
  * Extraction of old versions of the document
  * Easy extraction of objects, Javascript code, shellcodes (>, >>, $>, $>>)
  * Checking hashes on **VirusTotal**
  * Suspicious Elements
  * Maliciousness score (by [Rohit Dua](https://www.honeynet.org/node/1304)) 


**Creation/Modification:**

  * Basic PDF creation
  * Creation of PDF with Javascript executed wen the document is opened
  * Creation of object streams to compress objects
  * Embedded PDFs
  * Strings and names obfuscation
  * Malformed PDF output: without endobj, garbage in the header, bad header...
  * Filters modification
  * Objects modification


**Execution modes:**

  * Simple command line execution
  * **Powerful interactive console** (colorized or not)
  * Batch mode


**TODO:**

  * Adop the logging library and enrich more logging inforamtion
  * Adop YAML to store all configuration
  * Build a web server
  


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
