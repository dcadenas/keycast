# OpenVine: Adapting Keycast for Mass Nostr Identity Management

**Date**: January 9, 2025  
**Project**: OpenVine - Reviving Vine content on Nostr  
**Base Technology**: Keycast by Jeff Gardner (@erskingardner)  
**Scale Target**: Millions to hundreds of millions of users

---

## Executive Summary

OpenVine aims to revive millions of archived Vine accounts and publish them to Nostr, then allow users to claim their accounts through OAuth-like authentication. This requires adapting Jeff Gardner's Keycast project from team-based key management to individual user management at massive scale.

**Key Transformation**: Team collaboration → Individual user management  
**Scale Challenge**: Hundreds of teams → Millions of individual users  
**Authentication**: Team-based → OAuth-like (username/password)  
**Permissions**: Team policies → Google-style granular app permissions

---

## Project Overview

### OpenVine Goals
1. **Archive Revival**: Publish millions of historical Vine accounts to Nostr
2. **User Onboarding**: Allow former Vine users to claim their accounts via familiar OAuth flow
3. **New User Growth**: Enable new users to register @openvine.co identities
4. **Seamless Integration**: Provide bunker:// URLs for all Nostr apps
5. **Scale**: Handle millions of users with enterprise-grade security

### Two-Phase User Lifecycle
1. **Phase 1 - Programmatic Publishing**: Bulk publish archived Vine content with generated keys
2. **Phase 2 - User Claiming**: Allow users to claim accounts via OAuth authentication

---

## Technical Architecture

### Current Keycast Architecture
```
Team Creation → Key Generation → Policy Assignment → Member Invitation
```

### Required OpenVine Architecture
```
Bulk Key Generation → Content Publishing → User Registration → Account Claiming
```

### Infrastructure Components

#### **Authentication System**
- **Current**: Team-based authentication with collaborative access
- **Required**: OAuth-like flow similar to Bluesky
  - Username/password login at auth.openvine.co
  - Returns bunker:// URLs for app integration
  - NIP-05 identifier support (@openvine.co)

#### **Key Management**
- **Current**: Team-created keys with collaborative policies
- **Required**: Individual user keys with personal permissions
  - Bulk pre-generation for archived Vine users
  - On-demand generation for new users
  - Integration with Google Cloud processing pipeline

#### **Permission System**
- **Current**: Team-based policies with custom permissions
- **Required**: Google-style granular app permissions
  - Per-app authorization (Damus, Amethyst, Primal, etc.)
  - Granular permissions (post, DM, react, zap, etc.)
  - User-controlled revocation and management

---

## Required Keycast Modifications

### 1. User Management System

#### **Database Schema Changes**
```sql
-- Current team-focused schema
CREATE TABLE teams (
  id UUID PRIMARY KEY,
  name VARCHAR NOT NULL,
  created_at TIMESTAMP
);

-- Required individual user schema
CREATE TABLE users (
  id UUID PRIMARY KEY,
  username VARCHAR UNIQUE NOT NULL,  -- vine username or new user
  email VARCHAR UNIQUE,
  password_hash VARCHAR NOT NULL,
  vine_user_id VARCHAR,              -- for claimed vine accounts
  account_status ENUM('programmatic', 'claimed', 'active'),
  created_at TIMESTAMP,
  claimed_at TIMESTAMP
);
```

#### **Authentication Flow**
```typescript
// Current: Team-based authentication
interface TeamAuth {
  teamId: string;
  memberRole: 'admin' | 'member';
  permissions: TeamPermission[];
}

// Required: Individual OAuth authentication
interface UserAuth {
  userId: string;
  username: string;
  accountType: 'vine_claimed' | 'new_user';
  sessions: AppSession[];
}
```

### 2. Bulk Key Generation System

#### **Integration Points**
- **BigQuery**: User data and content metadata
- **Google Cloud Dataproc**: Bulk processing pipeline
- **Keycast**: Key generation and storage

#### **Bulk Generation Workflow**
```typescript
interface BulkKeyGeneration {
  // Step 1: Extract users from BigQuery
  extractUsers(): Promise<VineUser[]>;
  
  // Step 2: Generate keys in batches
  generateKeys(users: VineUser[]): Promise<UserKey[]>;
  
  // Step 3: Store in Keycast database
  storeKeys(keys: UserKey[]): Promise<void>;
  
  // Step 4: Publish content using generated keys
  publishContent(user: VineUser, content: VineContent[]): Promise<void>;
}
```

### 3. OAuth Integration

#### **New Authentication Endpoints**
```typescript
// OAuth-like flow endpoints
app.post('/auth/login', handleUserLogin);
app.post('/auth/register', handleUserRegistration);
app.post('/auth/claim', handleVineAccountClaim);
app.get('/auth/bunker/:userId', generateBunkerURL);
```

#### **Session Management**
```typescript
interface AppSession {
  sessionId: string;
  userId: string;
  appName: string;           // "Damus", "Amethyst", etc.
  appDomain: string;         // "damus.io"
  permissions: Permission[]; // granular permissions
  createdAt: Date;
  lastUsed: Date;
  expiresAt: Date;
}
```

### 4. Granular Permissions System

#### **Google-Style App Permissions**
```typescript
type AppPermission = 
  | 'read_profile'          // Read user profile
  | 'post_notes'            // Create kind 1 events
  | 'post_reactions'        // Create kind 7 events
  | 'post_reposts'          // Create kind 6 events
  | 'send_dms'              // Create kind 4 events
  | 'receive_dms'           // Decrypt kind 4 events
  | 'zap_send'              // Create zap events
  | 'zap_receive'           // Receive zap events
  | 'manage_follows'        // Modify follow lists
  | 'manage_relays'         // Modify relay lists
  | 'decrypt_nip04'         // Legacy DM decryption
  | 'encrypt_nip44'         // Modern encryption
  | 'sign_arbitrary';       // Sign non-standard events
```

#### **Permission Management UI**
```typescript
interface PermissionGrant {
  appName: string;
  requestedPermissions: AppPermission[];
  grantedPermissions: AppPermission[];
  userApproved: boolean;
  approvedAt: Date;
}
```

---

## Implementation Roadmap

### Phase 1: Core Infrastructure (Weeks 1-4)
- **Fork Keycast**: Create OpenVine-specific branch
- **Database Migration**: Adapt schema for individual users
- **Authentication**: Implement OAuth-like endpoints
- **Basic UI**: User login/registration interface

### Phase 2: Bulk Processing (Weeks 5-8)
- **BigQuery Integration**: Connect to Vine data pipeline
- **Bulk Key Generation**: Implement batch processing
- **Content Publishing**: Staged publishing system (posts → comments)
- **Performance Optimization**: Handle millions of keys efficiently

### Phase 3: User Experience (Weeks 9-12)
- **Account Claiming**: Vine user verification and claiming
- **Permission System**: Google-style granular permissions
- **Session Management**: Per-app authorization and revocation
- **User Dashboard**: Account management interface

### Phase 4: Production Deployment (Weeks 13-16)
- **Load Testing**: Validate performance at scale
- **Security Audit**: Comprehensive security review
- **Monitoring**: Production observability and alerting
- **Documentation**: User and developer documentation

---

## Technical Challenges and Solutions

### Challenge 1: Scale (Millions of Users)
**Problem**: Keycast designed for teams (10s-100s of users)  
**Solution**: 
- Database sharding for user data
- Horizontal scaling of key storage
- Caching layer for frequent operations
- Bulk operation optimization

### Challenge 2: Key Storage Architecture
**Problem**: Team keys vs individual user keys  
**Solution**:
- Maintain Keycast's AES-256 + KMS approach
- Optimize for individual key retrieval
- Implement key derivation for related operations
- Add backup/recovery mechanisms

### Challenge 3: Authentication Integration
**Problem**: Team-based auth vs OAuth flow  
**Solution**:
- Extend existing auth system
- Add OAuth-compatible endpoints
- Maintain backward compatibility
- Implement session management

### Challenge 4: Permission Granularity
**Problem**: Team policies vs app permissions  
**Solution**:
- Extend current permission system
- Add app-specific permission types
- Implement permission inheritance
- Create user-friendly permission UI

---

## Integration with Existing Infrastructure

### Google Cloud Pipeline Integration
```typescript
// Integration points with existing Vine processing
interface VineProcessingIntegration {
  // BigQuery connection
  bigQueryClient: BigQuery;
  
  // Dataproc job submission
  dataprocClient: DataprocClient;
  
  // Key generation coordination
  keycastClient: KeycastClient;
  
  // Publishing coordination
  nostrPublisher: NostrPublisher;
}
```

### Staged Publishing System
```typescript
interface StagedPublishing {
  // Phase 1: Historical posts (backdated)
  publishPosts(user: VineUser): Promise<void>;
  
  // Phase 2: Comments and interactions (ordered)
  publishComments(user: VineUser): Promise<void>;
  
  // Phase 3: Profile and metadata
  publishProfile(user: VineUser): Promise<void>;
}
```

---

## Security Considerations

### Key Security
- **Encryption**: Maintain AES-256 encryption for stored keys
- **Access Control**: Individual user access controls
- **Audit Logging**: Track all key usage and access
- **Backup**: Secure key backup and recovery procedures

### Authentication Security
- **Password Security**: Argon2 hashing for user passwords
- **Session Management**: Secure session tokens with expiration
- **OAuth Security**: Standard OAuth 2.0 security practices
- **Rate Limiting**: Prevent brute force attacks

### Scale Security
- **DDoS Protection**: Handle large-scale attacks
- **Database Security**: Protect user data at scale
- **Monitoring**: Real-time security monitoring
- **Incident Response**: Procedures for security incidents

---

## Success Metrics

### Technical Metrics
- **User Scale**: Support 1M+ users initially, 10M+ eventually
- **Performance**: <100ms response time for signing operations
- **Availability**: 99.9% uptime for authentication services
- **Security**: Zero key compromises or unauthorized access

### Business Metrics
- **User Adoption**: % of Vine users who claim accounts
- **App Integration**: Number of Nostr apps supporting OpenVine
- **Content Migration**: % of Vine content successfully published
- **User Retention**: Monthly active users post-claiming

---

## Resource Requirements

### Development Resources
- **Backend Development**: 2-3 developers for Keycast adaptation
- **Frontend Development**: 1-2 developers for user interface
- **DevOps**: 1 developer for infrastructure and deployment
- **Security**: 1 security engineer for audit and compliance

### Infrastructure Resources
- **Database**: Scaled PostgreSQL for user and key data
- **Key Storage**: AWS KMS or similar for encryption keys
- **Compute**: Kubernetes cluster for API services
- **Storage**: S3 for backups and static assets

---

## Collaboration with Jeff Gardner

### Contribution Strategy
- **Upstream Contributions**: Improvements that benefit both projects
- **Code Sharing**: Common infrastructure and utilities
- **Standards Development**: Collaborate on NIP-46 improvements
- **Knowledge Sharing**: Regular technical discussions and reviews

### Areas of Collaboration
- **Performance Optimization**: Scale improvements for key operations
- **Security Enhancements**: Shared security best practices
- **Protocol Extensions**: NIP-46 session management improvements
- **Testing**: Shared testing frameworks and methodologies

---

## Conclusion

Adapting Keycast for OpenVine represents a significant but achievable technical challenge. The core architecture and security model of Keycast provide an excellent foundation for individual user management at scale.

**Key Success Factors**:
1. **Incremental Development**: Build on Keycast's proven foundation
2. **Performance Focus**: Optimize for scale from the beginning
3. **User Experience**: Maintain familiar OAuth-like authentication
4. **Security**: Preserve enterprise-grade security practices
5. **Collaboration**: Work closely with Jeff Gardner to share improvements

**Expected Outcome**: A production-ready system capable of managing millions of Nostr identities with enterprise-grade security and user-friendly authentication, serving as the foundation for Vine content revival and new user onboarding.

The project bridges the gap between enterprise key management (Keycast) and mass consumer adoption (OpenVine), creating a scalable solution for Nostr identity management that benefits the entire ecosystem.