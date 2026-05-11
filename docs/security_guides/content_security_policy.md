# Content Security Policy Guide

## Purpose

Content Security Policy, or CSP, is a defense-in-depth control that reduces the impact of XSS by restricting where scripts can be loaded from and whether inline scripts can execute.

## Recommended Policy Direction

- Avoid unsafe-inline where possible.
- Use nonce-based or hash-based script execution.
- Restrict script-src to trusted origins.
- Avoid wildcard sources.
- Monitor violations during rollout.

## Limitation

CSP should not replace output encoding. It should be used together with secure coding practices.