# Output Encoding Guide

## Purpose

Output encoding prevents user-controlled input from being interpreted as executable HTML, JavaScript, CSS, or URL content.

## HTML Body Encoding

Use HTML entity encoding when rendering untrusted input in the HTML body. Characters such as `<`, `>`, `&`, `"`, and `'` should be encoded.

## Attribute Encoding

When rendering user input inside HTML attributes, quote the attribute and encode quotes and special characters.

## JavaScript Encoding

Avoid placing user input directly into JavaScript. If required, use strict serialization and JavaScript string escaping.

## URL Encoding

When user input is placed into URLs, apply URL encoding and validate allowed schemes.

## Best Practice

Use framework-provided escaping functions and template engines that auto-escape by default.