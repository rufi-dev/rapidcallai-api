# CRM Module - Architecture & Future Extraction Guide

## Current Architecture (Modular Monolith)

The CRM module is currently integrated into the main Express server but organized as a separate module:

```
server/src/crm/
├── store.js      # Data access layer (PostgreSQL)
├── routes.js     # Express router (API endpoints)
└── README.md     # This file
```

**Benefits of current approach:**
- ✅ Shared authentication (`requireAuth` middleware)
- ✅ Shared database connection pool
- ✅ Simple deployment (single Docker container)
- ✅ Easy cross-module queries (e.g., fetching calls for contacts)
- ✅ No network latency between modules
- ✅ Single codebase to maintain

## When to Extract to Separate Service

Consider extracting CRM when you hit **2+** of these:

1. **Scale**: CRM needs 10x more instances than main API
2. **Complexity**: CRM has 50+ endpoints, complex business logic
3. **Team**: Different team owns CRM vs main API
4. **Performance**: CRM queries are slow and affecting main API
5. **Database**: Need separate DB for CRM (e.g., read replicas, different schema)
6. **Deployment**: Need to deploy CRM independently (daily vs weekly)

## Extraction Strategy (When Ready)

### Phase 1: Prepare for Extraction (Do Now)

1. **Keep CRM self-contained** ✅ (Already done)
   - All CRM code in `server/src/crm/`
   - No direct imports from main server

2. **Add service boundary interfaces**
   ```javascript
   // server/src/crm/service.js
   // Abstract CRM operations that other modules might call
   module.exports = {
     upsertContactFromCall: async (workspaceId, phone, name, source) => {
       // This can later become an HTTP call
       return contactStore.upsertContactFromCall(...);
     }
   };
   ```

3. **Document dependencies**
   - CRM currently depends on: `store.listCalls()`, `store.listOutboundJobs()`
   - These would become HTTP calls or events in microservice architecture

### Phase 2: Extract to Separate Service (Future)

**New structure:**
```
crm-service/                    # New separate repo
├── src/
│   ├── index.js              # Express server
│   ├── routes.js             # CRM routes
│   ├── store.js              # CRM data access
│   └── auth.js               # JWT validation (shared secret)
├── Dockerfile
├── package.json
└── README.md

server/src/                    # Main API
├── crm/
│   └── client.js              # HTTP client to CRM service
└── index.js                   # Uses crm/client instead of crm/routes
```

**Changes needed:**

1. **Create CRM service** (`crm-service/`)
   - Copy `server/src/crm/` to new repo
   - Add Express server with JWT auth
   - Deploy as separate Docker container

2. **Update main server**
   - Replace `createCrmRouter()` with HTTP client
   - Call CRM service via HTTP instead of direct DB

3. **Shared authentication**
   - Both services validate same JWT tokens
   - Or use service-to-service API keys

4. **Database options:**
   - **Option A**: Shared PostgreSQL (simpler, single source of truth)
   - **Option B**: Separate CRM DB (better isolation, can optimize separately)

## Recommendation: Stay Modular for Now

**Keep current structure** because:

1. **You're not at scale yet** - Wait until you have real performance issues
2. **Simpler operations** - One deployment, one codebase, easier debugging
3. **Faster development** - No service boundaries, direct DB queries
4. **Lower cost** - Single EC2 instance, single DB connection pool

**Extract later when:**
- CRM has 100k+ contacts and queries are slow
- CRM team needs independent deployments
- CRM needs specialized infrastructure (e.g., Elasticsearch for search)

## Current Best Practices (Already Following)

✅ **Modular structure** - Easy to extract later  
✅ **Separate routes** - Clean API boundaries  
✅ **Self-contained store** - No tight coupling  
✅ **Type safety** - Client/server types match  

## Future Enhancements (Without Extraction)

Before extracting, consider:

1. **Database optimizations**
   - Add indexes for CRM queries
   - Use read replicas for heavy read workloads
   - Partition contacts table by workspace_id

2. **Caching layer**
   - Redis for frequently accessed contacts
   - Cache contact lookups by phone number

3. **Background jobs**
   - Move CSV import to background queue
   - Async contact enrichment/updates

4. **API pagination**
   - Currently limited to 1000 contacts
   - Add cursor-based pagination for large datasets

## Migration Checklist (When Ready)

- [ ] Create `crm-service` repository
- [ ] Copy CRM code to new service
- [ ] Add JWT authentication to CRM service
- [ ] Create HTTP client in main server
- [ ] Update auto-create hooks to use HTTP client
- [ ] Deploy CRM service separately
- [ ] Update client to point to CRM service
- [ ] Monitor performance and errors
- [ ] Remove CRM code from main server

---

**TL;DR**: Current modular structure is perfect. Extract only when you have concrete scaling/team needs. The current organization makes extraction straightforward when needed.
