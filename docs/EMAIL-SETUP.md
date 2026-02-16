# Developer Email Setup Guide

This document outlines the setup process for dev@accord.chat as the official contact email for the Accord project.

## Email Provider Choice: Proton Mail

After evaluating options, we recommend **Proton Mail** for the following reasons:
- **Privacy-focused**: End-to-end encryption by default
- **Custom domain support**: Professional email addresses
- **Reliable**: Swiss-based, strong privacy laws
- **Cost-effective**: $4-8/month for professional use
- **Brand alignment**: Matches Accord's privacy-first mission

### Alternative Options Considered:
- **FastMail**: $5/month, excellent technical features, but less privacy-focused
- **Gmail/Google Workspace**: Cheap but privacy concerns
- **Self-hosted**: Full control but requires maintenance
- **Email forwarding**: Simple but less professional

## Setup Process

### Prerequisites
1. **Domain**: Ensure you own `accord.chat` domain
2. **DNS access**: Ability to modify DNS records
3. **Proton account**: Create Proton Mail account if needed

### 1. Proton Mail Business Setup
1. Sign up for **Proton Mail Professional** ($8/month/user)
2. Choose annual billing for discount
3. Add custom domain `accord.chat`
4. Verify domain ownership via DNS

### 2. DNS Configuration
Add these DNS records to `accord.chat`:

```dns
# MX Records (Mail Exchange)
accord.chat.    MX    10    mailsec.protonmail.ch.
accord.chat.    MX    20    mailsecfallback.protonmail.ch.

# TXT Records (Verification & Security)
accord.chat.    TXT   "protonmail-verification=xxxxxxxxx"
accord.chat.    TXT   "v=spf1 include:_spf.protonmail.ch mx ~all"

# CNAME Records (DKIM)
protonmail._domainkey.accord.chat.    CNAME    protonmail.domainkey.dh7pmr5szccgl8zzvlxigfw5gz4hpwf2rx3t3cj6a6.domains.proton.ch.
protonmail2._domainkey.accord.chat.   CNAME    protonmail2.domainkey.dh7pmr5szccgl8zzvlxigfw5gz4hpwf2rx3t3cj6a6.domains.proton.ch.
protonmail3._domainkey.accord.chat.   CNAME    protonmail3.domainkey.dh7pmr5szccgl8zzvlxigfw5gz4hpwf2rx3t3cj6a6.domains.proton.ch.

# TXT Record (DMARC - Optional but recommended)
_dmarc.accord.chat.    TXT    "v=DMARC1; p=none; rua=mailto:dev@accord.chat"
```

### 3. Create Email Addresses
Set up these email addresses:
- **dev@accord.chat**: Main development contact
- **security@accord.chat**: Security vulnerability reports
- **hello@accord.chat**: General inquiries (optional)

### 4. Access Configuration
**Option A: Shared Mailbox**
- Create `dev@accord.chat` as shared mailbox
- Grant access to 2-3 core maintainers
- Use Proton's sharing features

**Option B: Email Forwarding**
- Set up `dev@accord.chat` to forward to maintainer emails
- Less secure but easier to manage initially
- Can upgrade to shared mailbox later

### 5. Email Signature Template
```
Best regards,
Accord Development Team

Accord - Privacy-first community communications
🔒 End-to-end encrypted • 🏠 Self-hostable • 🔓 Open source

GitHub: https://github.com/your-org/accord
Matrix: #accord-dev:matrix.org
Website: https://accord.chat (coming soon)

Security vulnerabilities: security@accord.chat
General development: dev@accord.chat
```

## Security Considerations

### Email Security Settings
- **Enable 2FA** on Proton account
- **Use strong passwords** (or password manager)
- **Enable all security features** in Proton
- **Regular access review** (quarterly)

### Response Guidelines
Set up these automated responses:

**dev@accord.chat autoresponder:**
```
Thank you for contacting Accord development!

For fastest response:
• Bug reports: https://github.com/your-org/accord/issues
• Feature requests: GitHub Discussions
• Development chat: #accord-dev:matrix.org
• Security vulnerabilities: security@accord.chat

We aim to respond to emails within 48 hours.

-Accord Dev Team
```

## Maintenance

### Regular Tasks
- **Weekly**: Check and respond to emails
- **Monthly**: Review email security settings
- **Quarterly**: Audit access permissions
- **Annually**: Review email provider and costs

### Backup Strategy
- **Export important emails** quarterly
- **Document email access** in secure location
- **Have multiple maintainers** with access
- **Regular password updates**

## Integration

### GitHub Integration
- Update GitHub organization email
- Set notification forwarding
- Configure security alert emails

### Matrix Integration
- Consider Matrix-email bridge for notifications
- Keep channels synced with email updates

### Future Considerations
- Custom email client/interface once Accord is mature
- Self-hosted email migration path
- Automated email processing for certain inquiries