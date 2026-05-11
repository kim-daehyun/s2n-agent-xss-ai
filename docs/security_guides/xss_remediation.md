# XSS Remediation Guide

## Reflected XSS

Reflected XSS occurs when user-controlled input is included in an HTTP response without proper output encoding. If the browser interprets the reflected input as HTML or JavaScript, an attacker may execute script in the victim's browser context.

## HTML Body Context

When untrusted input is rendered inside the HTML body, apply HTML entity encoding before rendering the value.

For example, `<script>alert(1)</script>` should be rendered as `&lt;script&gt;alert(1)&lt;/script&gt;`.

## HTML Attribute Context

When untrusted input is rendered inside an HTML attribute, apply attribute encoding and quote escaping. Attribute context requires careful handling of quotes, spaces, and event handler injection.

## JavaScript Context

When untrusted input is inserted into a JavaScript string or script context, avoid direct script generation. If unavoidable, apply JavaScript string escaping and validate the value strictly.

## Recommended Fix

- Apply context-aware output encoding.
- Escape HTML body output using HTML entity encoding.
- Escape HTML attribute values.
- Avoid inserting user input directly into JavaScript context.
- Prefer safe DOM APIs such as textContent instead of innerHTML.
- Validate and normalize input on the server side.
- Use Content Security Policy as a defense-in-depth control.

## CWE

CWE-79 describes improper neutralization of input during web page generation.

## Retest

Submit a harmless validation payload to the affected parameter and verify that it is encoded or not executed in the browser context.