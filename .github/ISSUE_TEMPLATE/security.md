---
name: Security Vulnerability
about: Report a security vulnerability (READ CAREFULLY)
title: '[SECURITY] '
labels: ['security']
assignees: ''

---

# ⚠️ STOP - READ THIS FIRST ⚠️

**DO NOT create a public GitHub issue for security vulnerabilities.**

This template is for **NON-SENSITIVE** security discussions only:
- Security feature requests
- Questions about cryptographic design
- General security hardening suggestions
- Documentation improvements for security practices

## 🚨 For Actual Vulnerabilities

**If you've found a security vulnerability:**

### ✅ DO THIS:
1. **Email the maintainers directly** (do not post publicly)
2. Include: vulnerability description, severity assessment, reproduction steps
3. Allow 48 hours for initial response
4. Follow responsible disclosure practices

### ❌ DO NOT:
- Create public GitHub issues
- Discuss on social media
- Share exploit code publicly
- Test on production instances you don't own

## 🔒 Responsible Disclosure Process

**Our commitment:**
- **48-hour response** to security reports
- **Coordinated disclosure** with reporter
- **Credit** to researchers (if desired)
- **Fix timeline:** Critical (24-48h), High (1 week), Medium (2-4 weeks)

**Timeline:**
1. You report privately
2. We acknowledge within 48h
3. We assess and develop fix
4. We coordinate public disclosure
5. We release fix and advisory
6. Public discussion is safe

## 🎯 What We Consider Security Issues

**Critical:**
- Remote code execution
- Cryptographic vulnerabilities
- Authentication bypasses
- Privilege escalation

**High:**
- Information disclosure
- Cross-site scripting (XSS)
- Server-side request forgery (SSRF)
- Denial of service (DoS)

**Medium:**
- Minor information leaks
- Security misconfigurations
- Missing security headers

## 🔍 Security Research Guidelines

**Allowed:**
- Testing on your own instances
- Cryptographic analysis of public protocols
- Code review and static analysis
- Documentation of theoretical attacks

**Not allowed:**
- Testing on public instances you don't control
- Social engineering of users or developers
- Physical attacks on infrastructure
- Automated scanning without permission

## 🏆 Recognition

We believe in recognizing security researchers:
- Public credit in security advisories (if desired)
- Mention in release notes
- Addition to security.txt Hall of Fame
- Potential bug bounty (when program launches)

## 📝 Security Feature Discussion

**If this is NOT a vulnerability but a security-related feature request or discussion, please describe below:**

### Security Enhancement Description
What security improvement are you suggesting?

### Impact Assessment
How would this enhance Accord's security posture?

### Implementation Considerations
Any thoughts on how this could be implemented?

---

**Remember: When in doubt, email privately. It's better to over-communicate security concerns than to under-report them.**