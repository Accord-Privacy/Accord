# Matrix Channel Setup Guide

This document outlines the setup process for the #accord-dev Matrix channel for Accord project development discussions.

## Server Choice: Matrix.org

After evaluating options, we chose **matrix.org** for the following reasons:
- **No cost**: Free public homeserver
- **Reliable**: Maintained by the Matrix foundation
- **Federated**: Works with all Matrix clients
- **Simple**: No server administration required
- **Professional**: Used by major open source projects

### Alternative Options Considered:
- **Element.io hosted**: $5/month minimum, better for organizations
- **Self-hosted**: Requires maintenance, better for full control
- **etke.cc**: FOSS hosting service, good middle ground

## Channel Setup Steps

### 1. Create the Room
1. Open Element client (web.element.io or desktop app)
2. Click "Create Room"
3. **Room name**: `Accord Development`
4. **Room address**: `#accord-dev:matrix.org`
5. **Visibility**: Public (discoverable)
6. **Privacy**: Anyone can join
7. **Encryption**: Enabled for security

### 2. Configure Room Settings
- **Topic**: "Development discussion for Accord - privacy-first community communications platform"
- **Avatar**: Upload Accord logo
- **Power levels**: 
  - Room creator: 100 (admin)
  - Moderators: 50
  - Default users: 0

### 3. Room Guidelines
Set the following as room description/pinned message:

```
Welcome to #accord-dev! 

This is the official Matrix channel for Accord development discussion.

Guidelines:
• Development discussions, feature requests, and technical questions
• Be respectful and constructive
• For bug reports: prefer GitHub issues
• For security vulnerabilities: email dev@accord.chat (never post here)
• For general support: use GitHub Discussions

Resources:
• GitHub: https://github.com/your-org/accord
• Documentation: Coming soon
• Website: Coming soon

New here? Introduce yourself! 👋
```

### 4. Moderation Setup
- Enable message retention (90 days for development chat)
- Set up bridge bots if desired (GitHub notifications)
- Configure spam protection
- Add trusted community members as moderators

### 5. Integration Options
- **GitHub webhook**: Post PR/issue notifications
- **CI notifications**: Build status updates  
- **Release notifications**: New version announcements

## Connection Details

Once set up, developers can join via:
- **Web**: https://app.element.io/#/room/#accord-dev:matrix.org
- **Room address**: `#accord-dev:matrix.org`
- **Matrix URI**: `matrix:r/accord-dev:matrix.org`

## Client Recommendations

For developers:
- **Element Web**: https://app.element.io (easiest)
- **Element Desktop**: Cross-platform app
- **FluffyChat**: Mobile-friendly
- **Nheko**: Lightweight desktop client

## Maintenance

Regular maintenance tasks:
- Review and update room guidelines quarterly
- Clean up inactive bridges/bots
- Update room topic for major milestones
- Archive old messages if storage becomes an issue

## Future Considerations

As Accord grows:
- Consider moving to dedicated Matrix server
- Set up Accord server space for multiple rooms
- Integrate with Accord's own communication once ready
- Bridge with Discord if community requires it