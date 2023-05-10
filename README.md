Project Name
Broken Access Control 

Project Description

This Python script is designed to systematically test for Broken Access Control (BAC), Cross-Site Scripting (XSS), and Open Redirect vulnerabilities, three of the most prevalent web application security threats.

The script operates based on the principle of user role differentiation, particularly focusing on 'admin' and 'non-admin' roles. The 'admin' role typically has extensive privileges, granting access to more sensitive information and control over more critical functionalities. The 'non-admin' role, on the other hand, has more limited permissions.

The script works by first simulating actions as a 'non-admin' user and then as an 'admin' user. It attempts to perform various operations that should only be available to the 'admin' user while in the 'non-admin' role. If these operations are successful, it indicates a Broken Access Control vulnerability.

In addition to BAC, the script also tests for Cross-Site Scripting and Open Redirect vulnerabilities. It attempts to inject malicious scripts and redirect requests to untrusted sites, respectively, to check if the web application is susceptible to such attacks.

By proactively identifying these vulnerabilities, we can rectify them before they're exploited, providing a much-needed layer of security for web applications. Remember, however, this script is part of a more extensive cybersecurity strategy and should be used in conjunction with other security measures for optimal protection.

Installation

beautifulsoup4==4.9.3
httpx==0.16.1
requests==2.26.0



License
This script is released under the MIT License, which allows users to modify, distribute, and use the software for commercial purposes, provided that the original copyright notice and license are included. 
However, the software is provided as-is, without any warranty or guarantee of fitness for a particular purpose or performance.
The owner of the software is not liable for any damages or legal claims that may arise from the use of the software.

