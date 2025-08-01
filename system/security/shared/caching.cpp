/*##############################################################################

    HPCC SYSTEMS software Copyright (C) 2012 HPCC Systems®.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
############################################################################## */

#include "caching.hpp"
#include "jtime.hpp"
#include "digisign.hpp"

using namespace cryptohelper;


//define a container for multiple instances of a security manager cache
typedef map<string, CPermissionsCache*> MapCache;
static CriticalSection mapCacheCS;//guards modifications to the cache map
static MapCache g_mapCache;

/**********************************************************
 *     CResPermissionsCache                               *
 *     (used by CPermissionsCache defined below)          *
 **********************************************************/

CResPermissionsCache::~CResPermissionsCache()
{
    MapResAccess::const_iterator i;
    MapResAccess::const_iterator iEnd = m_resAccessMap.end(); 

    for (i = m_resAccessMap.begin(); i != iEnd; i++)
    {
        ISecResource* ptr = ((*i).second).second;
        if(ptr)
        {
            ptr->Release();
        }
    }   
}

//called from within a ReadLockBlock
int CResPermissionsCache::lookup( IArrayOf<ISecResource>& resources, bool* pFound )
{
    time_t tstamp;
    time(&tstamp);

    int nresources = resources.ordinality();
    int nFound = 0;

    for (int i = 0; i < nresources; i++)
    {
        ISecResource& secResource = resources.item(i);
        const char* resource = secResource.getName();
        if(resource == NULL)
        {
            *pFound++ = false;
            continue;
        }
#ifdef _DEBUG
        DBGLOG("CACHE: CResPermissionsCache Looking up resource(%d of %d) %s:%s", i, nresources, m_user.c_str(), resource);
#endif
        MapResAccess::iterator it = m_resAccessMap.find(SecCacheKeyEntry(resource, secResource.getResourceType()));
        if (it != m_resAccessMap.end())//exists in cache
        {
            ResPermCacheEntry& resParamCacheEntry = (*it).second;
            const time_t timeExpiry = resParamCacheEntry.first + m_pParentCache->getCacheTimeout();

            if (timeExpiry < tstamp)//entry was not stale during last cleanup but is stale now
                *pFound++ = false;
            else
            {
                secResource.copy(resParamCacheEntry.second);
#ifdef _DEBUG
                DBGLOG("CACHE: CResPermissionsCache Found %s:%s=>%d", m_user.c_str(), resource, ((ISecResource*)resParamCacheEntry.second)->getAccessFlags());
#endif
                *pFound++ = true;
                nFound++;
            }
        }
        else
            *pFound++ = false;
    }
    return nFound;
}

//called from within a WriteLockBlock
void CResPermissionsCache::add( IArrayOf<ISecResource>& resources )
{
    time_t tstamp;
    time(&tstamp);

    int nresources = resources.ordinality();
    for (int i = 0; i < nresources; i++)
    {
        ISecResource* secResource = &resources.item(i);
        if(!secResource)
            continue;
        const char* resource = secResource->getName();
        SecResourceType resourcetype = secResource->getResourceType();
        if(resource == NULL)
            continue;
        int permissions = secResource->getAccessFlags();
        if(permissions == SecAccess_Unavailable)
            continue;

        MapResAccess::iterator it = m_resAccessMap.find(SecCacheKeyEntry(resource, resourcetype));
        if (it != m_resAccessMap.end())//already exists so overwrite it but first remove existing timestamp info
        {
            ResPermCacheEntry& resParamCacheEntry = (*it).second;
            time_t oldtstamp = resParamCacheEntry.first;


            //there may be multiple resources associated with the same timestamp 
            //in the multimap so find this entry
            //
            MapTimeStamp::iterator itL = m_timestampMap.lower_bound( oldtstamp );
            MapTimeStamp::iterator itU = m_timestampMap.upper_bound( oldtstamp );
            MapTimeStamp::iterator its;
            for ( its = itL; its != itU; its++)
            {
                SecCacheKeyEntry& cachekey = (*its).second;
                if (cachekey.first == resource && cachekey.second == resourcetype)
                {
                    m_timestampMap.erase(its);
                    break;
                }
            }
            resParamCacheEntry.second->Release();
            m_resAccessMap.erase(SecCacheKeyEntry(resource, resourcetype));
        }
#ifdef _DEBUG
        DBGLOG("CACHE: CResPermissionsCache Adding %s:%s(%d)", m_user.c_str(), resource, permissions);
#endif
        m_resAccessMap.insert( pair<SecCacheKeyEntry, ResPermCacheEntry>(SecCacheKeyEntry(resource, resourcetype),  ResPermCacheEntry(tstamp, secResource->clone())));
        m_timestampMap.insert( pair<time_t, SecCacheKeyEntry>(tstamp, SecCacheKeyEntry(resource, resourcetype)));
    }
}

//called from within a WriteLockBlock
void CResPermissionsCache::removeStaleEntries(time_t tstamp)
{
    if (needsCleanup(tstamp, m_pParentCache->getCacheTimeout()))
    {
        MapTimeStamp::iterator i;
        MapTimeStamp::iterator itL    = m_timestampMap.lower_bound(tstamp);
        MapTimeStamp::iterator iBegin = m_timestampMap.begin();

        for (i = iBegin; i != itL; i++)
        {
            SecCacheKeyEntry& cachekey = (*i).second;
            MapResAccess::iterator it = m_resAccessMap.find(cachekey);
            if (it != m_resAccessMap.end())//exists in cache
            {
                ResPermCacheEntry& entry = (*it).second;
                if(entry.second)
                    entry.second->Release();
            }
            m_resAccessMap.erase(cachekey);
        }

        m_timestampMap.erase(iBegin, itL);
        m_tLastCleanup = tstamp;
    }
}

//called from within a WriteLockBlock
void CResPermissionsCache::remove(SecResourceType rtype, const char* resourcename)
{
    SecCacheKeyEntry key(resourcename, rtype);
    MapResAccess::iterator it = m_resAccessMap.find(key);
    if (it != m_resAccessMap.end())//exists in cache
    {
        ResPermCacheEntry& entry = (*it).second;
        if(entry.second)
            entry.second->Release();
    }
    m_resAccessMap.erase(key);
}

/**********************************************************
 *     CPermissionsCache                                  *
 **********************************************************/

CPermissionsCache::~CPermissionsCache()
{
    if (!m_secMgrClass.isEmpty())
    {
        CriticalBlock block(mapCacheCS);
        g_mapCache.erase(m_secMgrClass.str());
    }

    // If the fill thread was started, stop it.
    if (m_fileScopeCacheFillThread.joinable())
    {
        m_exitFileScopeCacheFillThreadSem.signal();
        m_fileScopeCacheFillThread.join();
        DBGLOG("CACHE: CPermissionsCache managedFileScopesCacheFillThread stopped");
    }

    {
        WriteLockBlock writeLock(m_scopesRWLock);
        removeAllManagedFileScopes();
    }

    clearPermissionsCache();
    clearUsersCache();
}

int CPermissionsCache::lookup( ISecUser& sec_user, IArrayOf<ISecResource>& resources, bool* pFound)
{
    time_t tstamp;
    time(&tstamp);

    const char* userId = sec_user.getName();

    //First check if matching cache entry is stale
    bool needsCleanup = false;
    {
        ReadLockBlock readLock(m_resPermCacheRWLock);
        MapResPermissionsCache::const_iterator i = m_resPermissionsMap.find( userId );
        if (i != m_resPermissionsMap.end())
        {
            CResPermissionsCache* pResPermissionsCache = (*i).second;
            needsCleanup = pResPermissionsCache->needsCleanup(tstamp, getCacheTimeout());
        }
    }

    //clear stale cache entries for this CResPermissionsCache entry
    if (needsCleanup)
    {
        WriteLockBlock writeLock(m_resPermCacheRWLock);
        MapResPermissionsCache::const_iterator i = m_resPermissionsMap.find( userId );
        if (i != m_resPermissionsMap.end())//Entry could have been deleted by another thread
        {
            CResPermissionsCache* pResPermissionsCache = (*i).second;
            pResPermissionsCache->removeStaleEntries(tstamp);
        }
    }

    //Lookup all user/resources
    int nFound;
    ReadLockBlock readLock(m_resPermCacheRWLock);
    MapResPermissionsCache::const_iterator i = m_resPermissionsMap.find( userId ); 
    if (i != m_resPermissionsMap.end())
    {
        CResPermissionsCache* pResPermissionsCache = (*i).second;
        nFound = pResPermissionsCache->lookup( resources, pFound );
    }
    else
    {
        nFound = 0;
        memset(pFound, 0, sizeof(bool)*resources.ordinality());
    }

#ifdef _DEBUG
    DBGLOG("CACHE: CPermissionsCache Looked up resources for %s:*, found %d of %d matches", userId, nFound, resources.ordinality());
#endif
    return nFound;
}



void CPermissionsCache::add( ISecUser& sec_user, IArrayOf<ISecResource>& resources )
{
    const char* user = sec_user.getName();
    WriteLockBlock writeLock(m_resPermCacheRWLock);
    MapResPermissionsCache::const_iterator i = m_resPermissionsMap.find( user ); 
    CResPermissionsCache* pResPermissionsCache;

    if (i == m_resPermissionsMap.end())
    {
#ifdef _DEBUG
        DBGLOG("CACHE: CPermissionsCache Adding resources to cache for new user %s", user);
#endif
        pResPermissionsCache = new CResPermissionsCache(this, user);
        m_resPermissionsMap.insert(pair<string, CResPermissionsCache*>(user, pResPermissionsCache));
    }
    else
    {
#ifdef _DEBUG
        DBGLOG("CACHE: CPermissionsCache Adding resources to cache for existing user %s", user);
#endif
        pResPermissionsCache = (*i).second;
    }
    pResPermissionsCache->add( resources );
}

void CPermissionsCache::removePermissions( ISecUser& sec_user)
{
    const char* user = sec_user.getName();
    if(user != NULL && *user != '\0')
    {
#ifdef _DEBUG
        DBGLOG("CACHE: CPermissionsCache Removing permissions for user %s", user);
#endif
        WriteLockBlock writeLock(m_resPermCacheRWLock);
        m_resPermissionsMap.erase(user); 
    }
}

void CPermissionsCache::remove(SecResourceType rtype, const char* resourcename)
{
    MapResPermissionsCache::const_iterator i;
    WriteLockBlock writeLock(m_resPermCacheRWLock);
    MapResPermissionsCache::const_iterator iEnd = m_resPermissionsMap.end(); 

    for (i = m_resPermissionsMap.begin(); i != iEnd; i++)
    {
        i->second->remove(rtype, resourcename);
    }
}


bool CPermissionsCache::lookup(ISecUser& sec_user)
{
    if(!isCacheEnabled())
        return false;

    const char* username = sec_user.getName();
    if(!username || !*username)
        return false;

    bool deleteEntry = false;
    {
        ReadLockBlock readLock(m_userCacheRWLock );

        MapUserCache::iterator it = m_userCache.find(username);
        if (it == m_userCache.end())
            return false;
        CachedUser* user = (CachedUser*)(it->second);

        time_t now;
        time(&now);
        if(0==sec_user.credentials().getSessionToken()  &&  (now - user->getTimestamp()) > m_cacheTimeoutInSeconds)//don't delete session based users
        {
            deleteEntry = true;
        }
        else
        {
            const char* cachedpw = user->queryUser()->credentials().getPassword();
            const char * pw = sec_user.credentials().getPassword();

            if ((sec_user.credentials().getSessionToken() != 0) || !isEmptyString(sec_user.credentials().getSignature()) || !isEmptyString(user->queryUser()->credentials().getSignature()) )
            {//presence of session token or signature means user is authenticated
#ifdef _DEBUG
                DBGLOG("CACHE: CPermissionsCache Found validated user %s", username);
#endif
                user->queryUser()->copyTo(sec_user);
                return true;
            }
            else if(cachedpw && pw && *pw != '\0')
            {
                if(strcmp(cachedpw, pw) == 0)
                {
#ifdef _DEBUG
                    DBGLOG("CACHE: CPermissionsCache Found validated user %s", username);
#endif
                    user->queryUser()->copyTo(sec_user);
                    return true;
                }
                else
                {
                    deleteEntry = true;
                }
            }
        }
    }

    if (deleteEntry)
    {
        WriteLockBlock writeLock(m_userCacheRWLock);
        MapUserCache::iterator it = m_userCache.find(username);
        if (it != m_userCache.end())
        {
            CachedUser* user = (CachedUser*)(it->second);
            m_userCache.erase(username);
            delete user;
        }
    }

    return false;
}

ISecUser* CPermissionsCache::getCachedUser( ISecUser& sec_user)
{
    if(!isCacheEnabled())
        return NULL;

    const char* username = sec_user.getName();
    if(!username || !*username)
        return NULL;

    ReadLockBlock readLock(m_userCacheRWLock );
    MapUserCache::iterator it = m_userCache.find(username);
    if (it == m_userCache.end())
        return NULL;
    CachedUser* user = (CachedUser*)(it->second);
    return LINK(user->queryUser());
}

void CPermissionsCache::add(ISecUser& sec_user)
{
    if(!isCacheEnabled())
        return;
    
    const char* username = sec_user.getName();
    if(!username || !*username)
        return;
    
    WriteLockBlock writeLock(m_userCacheRWLock );
    MapUserCache::iterator it = m_userCache.find(username);
    CachedUser* user = NULL;
    if (it != m_userCache.end())
    {
        user = (CachedUser*)(it->second);
        m_userCache.erase(username);
        delete user;
    }
#ifdef _DEBUG
    DBGLOG("CACHE: CPermissionsCache Adding cached user %s", username);
#endif
    if (isEmptyString(sec_user.credentials().getPassword()) && (0 == sec_user.credentials().getSessionToken()) && isEmptyString(sec_user.credentials().getSignature()))
    {
        //No need to sign if password or authenticated session based user
        IDigitalSignatureManager * pDSM = queryDigitalSignatureManagerInstanceFromEnv();
        if (pDSM && pDSM->isDigiSignerConfigured())
        {
            //Set user digital signature
            StringBuffer b64Signature;
            pDSM->digiSign(b64Signature, sec_user.getName());
            sec_user.credentials().setSignature(b64Signature);//callers sec_user will now contain signature
        }
    }
    m_userCache[username] = new CachedUser(LINK(&sec_user));
}

void CPermissionsCache::removeFromUserCache(ISecUser& sec_user)
{
    const char* username = sec_user.getName();
    if(username && *username)
    {
        WriteLockBlock writeLock(m_userCacheRWLock );
        MapUserCache::iterator it = m_userCache.find(username);
        if (it != m_userCache.end())
        {
            CachedUser* user = (CachedUser*)(it->second);
            m_userCache.erase(username);
            delete user;
#ifdef _DEBUG
            DBGLOG("CACHE: CPermissionsCache Removing cached user %s", username);
#endif
        }
    }
}

bool CPermissionsCache::addManagedFileScopes(const IArrayOf<ISecResource>& scopes)
{
    // Caller must lock m_scopesRWLock for writing
    ForEachItemIn(x, scopes)
    {
        ISecResource* scope = &scopes.item(x);
        if(!scope)
            continue;
        const char* cachekey = scope->getName();
        if(cachekey == NULL)
            continue;
        map<string, ISecResource*>::iterator it = m_managedFileScopesMap.find(cachekey);
        if (it != m_managedFileScopesMap.end())
        {
            ISecResource *res = (*it).second;
            res->Release();
            m_managedFileScopesMap.erase(it);
        }
#ifdef _DEBUG
        DBGLOG("Caching Managed File Scope %s",cachekey);
#endif
        m_managedFileScopesMap.insert( pair<string, ISecResource*>(cachekey, LINK(scope)));
    }
    return true;
}


inline void CPermissionsCache::removeAllManagedFileScopes()
{
    // Caller must lock m_scopesRWLock for writing if required
    map<string, ISecResource*>::const_iterator cit;
    map<string, ISecResource*>::const_iterator iEnd = m_managedFileScopesMap.end();

    for (cit = m_managedFileScopesMap.begin(); cit != iEnd; cit++)
    {
        ISecResource *res = (*cit).second;
        res->Release();
    }
    m_managedFileScopesMap.clear();
}

/*
    if perms set on 'scopeA::scopeB' only and lookup of 'scopeA::scopeB::scopeC::scopeD'
    need to lookup:
        'scopeA'
    no match=>continue
    match=>continue if read permissions (if no read, implies can't "see" child scopes)
        'scopeA::scopeB'
    no match=>continue
    match=>continue if read permissions (if no read, implies can't "see" child scopes)

    etc. Until full scope path checked, or no read permissions hit on ancestor scope.
*/
bool CPermissionsCache::queryPermsManagedFileScope(ISecUser& sec_user, const char * fullScope, StringBuffer& managedScope, SecAccessFlags * accessFlags)
{
    unsigned start = msTick();
    if (!fullScope || !*fullScope)
    {
        *accessFlags = queryDefaultPermission(sec_user);
        OWARNLOG("FileScope empty for %s, applying default permissions %s(%d), took %dms", sec_user.getName(), getSecAccessFlagName(*accessFlags), *accessFlags,  msTick()-start);
        return true;
    }

    // If the cache is not ready, then no initial fill has been done. Do the
    // initial fill and start the fill thread
    if (!m_fileScopeCacheReady)
    {
        WriteLockBlock lock(m_scopesRWLock);
        if (!m_fileScopeCacheReady)
        {
            fillManagedFileScopesCache(true);
            m_fileScopeCacheFillThread = std::thread(&CPermissionsCache::managedFileScopesCacheFillThread, this);
            m_fileScopeCacheReady = true;
        }
    }

    StringArray scopes;
    {
        StringBuffer scope;
        const char * p = fullScope;
        while (*p)
        {
            if (*p == ':')
            {
                if (*(p+1) != ':')
                    return false;//Malformed scope string, let LDAP figure it out
                scopes.append(scope.str());
                scope.append(*(p++));
            }
            scope.append(*(p++));
        }
        scopes.append(scope.str());
    }

    ISecResource *matchedRes = NULL;
    ISecResource *res = NULL;
    bool isManaged = false;

    ReadLockBlock readLock(m_scopesRWLock);

    if (m_managedFileScopesMap.empty())
    {
        readLock.clear();   // no longer needed
        *accessFlags = queryDefaultPermission(sec_user);
        return true;
    }

    for(unsigned i = 0; i < scopes.length(); i++)
    {
        const char* scope = scopes.item(i);
        map<string, ISecResource*>::const_iterator it = m_managedFileScopesMap.find(scope);
        if (it != m_managedFileScopesMap.end())
        {
            isManaged = true;
            res = (*it).second;
            res->setResourceType(RT_FILE_SCOPE);
            LINK(res);
            IArrayOf<ISecResource> secResArr;
            secResArr.append(*res);
            bool found;
            int nFound = lookup(sec_user, secResArr, &found);
            if (nFound && found)
            {
                if (0 == (res->getAccessFlags() & SecAccess_Read))
                {
                    *accessFlags = res->getAccessFlags();
                    managedScope.append(const_cast<char *>(res->getName()));
                    LOG(MCoperatorProgress, "FileScope %s for %s(%s) access denied %s(%d) at scope %s, took %dms", fullScope, sec_user.getName(), res->getName(), getSecAccessFlagName(*accessFlags), *accessFlags, scope, msTick()-start);
                    return true;
                }
                else
                {
                    matchedRes = res;//allowed at this scope, but must also look at child scopes
                }
            }
            else
            {
                matchedRes = nullptr;//don't use parent scope permissions for managed child scope, need to get from LDAP
            }
        }
    }
    bool rc;
    if (isManaged)
    {
        if (matchedRes)
        {
            *accessFlags = matchedRes->getAccessFlags();
            managedScope.append(const_cast<char *>(matchedRes->getName()));
#ifdef _DEBUG
            DBGLOG("FileScope %s for %s(%s) access granted %d, took %dms", fullScope, sec_user.getName(), matchedRes->getName(), *accessFlags, msTick()-start);
#endif
            rc = true;
        }
        else
        {
            managedScope.append(const_cast<char *>(res->getName()));//return deepest managed scope
#ifdef _DEBUG
            DBGLOG("FileScope %s for %s(%s) managed but not cached, took %dms", fullScope, sec_user.getName(), res->getName(), msTick()-start);
#endif
            rc = false;//need to go to LDAP to check
        }
    }
    else
    {
        *accessFlags = queryDefaultPermission(sec_user);
        if (isDebugBuild())
            OWARNLOG("FileScope %s for %s not managed, using default %s(%d), took %dms", fullScope, sec_user.getName(), getSecAccessFlagName(*accessFlags), *accessFlags, msTick()-start);
        rc = true;
    }
    return rc;
}


static CriticalSection syncDefaultScopePermissions;//for cached default file scope permissions
void CPermissionsCache::managedFileScopesCacheFillThread()
{
    DBGLOG("CACHE: CPermissionsCache managedFileScopesCacheFillThread starting");

    time_t waitTimeSeconds = m_cacheTimeoutInSeconds;
    while (true)
    {
        // Start the fill loop by waiting the timeout period. If the semaphone is
        // signalled, then the thread is to exit, so break out of the loop.
        if (m_exitFileScopeCacheFillThreadSem.wait(waitTimeSeconds * 1000))
            break;

        time_t now;
        time(&now);

        // How long since the last fill
        time_t elapsedTimeSinceLastFill = now - m_lastCacheFillTime.load();

        // If the timeout period has elapsed, refill the cache. Note that it is possible that a flush
        // completes after now is set which could result in elapsedTimeSinceLastFill being negative.
        if (elapsedTimeSinceLastFill >= m_cacheTimeoutInSeconds)
        {
            try
            {
                fillManagedFileScopesCache(false);
                {
                    CriticalBlock defaultScopePermissionBlock(syncDefaultScopePermissions);
                    m_userDefaultFileScopePermissions.clear();
                }
            }
            catch (IException *e)
            {
                StringBuffer errorMsg;
                e->errorMessage(errorMsg);
                OERRLOG("CACHE: Exception retrieving managed scopes in fill thread, error=%d, message=%s", e->errorCode(), errorMsg.str());
                e->Release();
            }
            catch (...)
            {
                OERRLOG("CACHE: Unknown exception retrieving managed scopes in fill thread");
            }

            waitTimeSeconds = m_cacheTimeoutInSeconds;
        }
        else
        {
            // clamp the wait time to the cache timeout (elapsed time could be negative, see above)
            waitTimeSeconds = std::min<time_t>(m_cacheTimeoutInSeconds - elapsedTimeSinceLastFill, m_cacheTimeoutInSeconds);
        }
    }
    DBGLOG("CACHE: CPermissionsCache managedFileScopesCacheFillThread exiting");
}

// if lockAlreadyAcquired is true, the caller must have already acquired
// the m_scopesRWLock for writing and is responsible for releasing the lock as well,
// including if an exception is thrown
//
// If lockAlreadyAcquired is false, the lock is acquired for writing only while
// the cache is replaced with newly read values.
void CPermissionsCache::fillManagedFileScopesCache(bool lockAlreadyAcquired)
{
    IArrayOf<ISecResource> scopes;
    m_secMgr->getManagedScopeTree(RT_FILE_SCOPE, nullptr, scopes);

    if (lockAlreadyAcquired)
    {
        replaceManagedFileScopesCache(scopes);
    }
    else
    {
        WriteLockBlock writeLock(m_scopesRWLock);
        replaceManagedFileScopesCache(scopes);
    }
}


void CPermissionsCache::replaceManagedFileScopesCache(const IArrayOf<ISecResource> &scopes)
{
    removeAllManagedFileScopes();
    if (scopes.length())
        addManagedFileScopes(scopes);
    time_t now;
    time(&now);
    m_lastCacheFillTime = now;
}


SecAccessFlags CPermissionsCache::queryDefaultPermission(ISecUser& user)
{
    SecAccessFlags defaultPermission = SecAccess_None;
    const std::string username(user.getName());
    bool addedToCache = false;
    bool needToAdd = false;

    {
        CriticalBlock defaultScopePermissionBlock(syncDefaultScopePermissions);
        auto it = m_userDefaultFileScopePermissions.find(username);
        if (it == m_userDefaultFileScopePermissions.end())
            needToAdd = true;
        else
            defaultPermission = it->second;
    }

    if (needToAdd)
    {
        defaultPermission = m_secMgr->queryDefaultPermission(user);   // retrieve w/o locking
        CriticalBlock defaultScopePermissionBlock(syncDefaultScopePermissions);
        auto it = m_userDefaultFileScopePermissions.find(username);
        if (it == m_userDefaultFileScopePermissions.end())
        {
            m_userDefaultFileScopePermissions.emplace(username, defaultPermission);
            addedToCache = true;  // no logging while in critical section
        }
        else
            defaultPermission = it->second;  // extremely unlikely it changed, but just in case use the stored value
    }

    if (addedToCache)
    {
        DBGLOG("Added user '%s' to default file scope permissions with access %s(%d)", username.c_str(), getSecAccessFlagName(defaultPermission),
               defaultPermission);
    }

    return defaultPermission;
}

void CPermissionsCache::flush()
{
    // Permissions and Users caches are each protected by their own
    // RW locks which lockout access by other threads.
    // Once cleared, if a caller does not find a result in either of these caches, it will do an LDAP lookup
    // and call back into the cache manager to add the result. This is how the cache is rebuilt (cache misses are not
    // considered a no access error)
    clearPermissionsCache();
    clearUsersCache();

    {
        CriticalBlock defaultScopePermissionBlock(syncDefaultScopePermissions);
        m_userDefaultFileScopePermissions.clear();
    }

    // If the file scope cache is not ready, no need for a flush.
    if (m_fileScopeCacheReady)
    {
        WriteLockBlock writeLock(m_scopesRWLock);
        fillManagedFileScopesCache(true);
    }
}

void CPermissionsCache::clearPermissionsCache()
{
    WriteLockBlock writeLock(m_resPermCacheRWLock);
    MapResPermissionsCache::const_iterator i;
    MapResPermissionsCache::const_iterator iEnd = m_resPermissionsMap.end();
    for (i = m_resPermissionsMap.begin(); i != iEnd; i++)
        delete (*i).second;
    m_resPermissionsMap.clear();
}

void CPermissionsCache::clearUsersCache()
{
    WriteLockBlock writeLock(m_userCacheRWLock );
    MapUserCache::const_iterator ui;
    MapUserCache::const_iterator uiEnd = m_userCache.end();
    for (ui = m_userCache.begin(); ui != uiEnd; ui++)
        delete (*ui).second;
    m_userCache.clear();
}

CPermissionsCache* CPermissionsCache::getInstance(const char * _secMgrClass, ISecManager *secMgr, unsigned cacheTimeoutMinutes)
{
    const char * secMgrClass = (_secMgrClass != nullptr  &&  *_secMgrClass) ? _secMgrClass : "genericSecMgrClass";

    CriticalBlock block(mapCacheCS);
    MapCache::iterator it = g_mapCache.find(secMgrClass);
    if (it != g_mapCache.end())//exists in cache
    {
        // Always save the last secMgr passed in to maintain existing behavior
        it->second->setSecManager(secMgr);
        LINK((*it).second);
        return (*it).second;
    }
    else
    {
        CPermissionsCache * instance = new CPermissionsCache(_secMgrClass, secMgr, cacheTimeoutMinutes);
        g_mapCache.insert(pair<string, CPermissionsCache*>(secMgrClass, instance));
        return instance;
    }
}
