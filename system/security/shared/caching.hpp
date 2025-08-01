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

#ifndef _CACHING_HPP__
#define _CACHING_HPP__
#ifdef _MSC_VER
#pragma warning (push)
#pragma warning(disable:4786)
#endif

#include "jliball.hpp"
#include "seclib.hpp"
#undef new
#include <map>
#include <string>
#if defined(_DEBUG) && defined(_WIN32) && !defined(USING_MPATROL)
 #define new new(_NORMAL_BLOCK, __FILE__, __LINE__)
#endif

using std::pair;
using std::map;
using std::multimap;
using std::string;

//Define type of cache entry stored for each resource (in each user specific cache).
//This is a pair of timestamp when this was fetched and the permission itself.
//

typedef pair<time_t, ISecResource*> ResPermCacheEntry;
typedef pair<string, SecResourceType> SecCacheKeyEntry;
//this a cache for a given user that stores permissions for individual resources
//along with their timestamps when they were fetched.  The cache is periodically
//cleaned up to remove stale (older than 5 minutes) entries - triggered by a lookup
//itself.  Note that each user has an instance of this cache, which is stored in
//another map (CPermissionsCache) as defined below.
//
//
// CPermissionsCache(user) -> CResPermissionsCache|(resource) -> pair<timeout, permission>
//                                                |(timestamp)->resource

class CResPermissionsCache
{
public:
    CResPermissionsCache(class CPermissionsCache* parentCache, const char* user)
        : m_user(user), m_pParentCache(parentCache)
    {
        time( &m_tLastCleanup );
    }

    virtual ~CResPermissionsCache();

    //finds cached permissions for a number of resources and sets them in
    //and also returns status in the boolean array passed in
    //
    virtual int  lookup( IArrayOf<ISecResource>& resources, bool* found );

    //fetch permissions from resources passed in and store them in the cache
    //
    virtual void add( IArrayOf<ISecResource>& resources );
    virtual void remove(SecResourceType rtype, const char* resourcename);

    //removes entries older than tstamp passed in
    //
    virtual void removeStaleEntries(time_t tstamp);
    virtual bool needsCleanup(time_t now, unsigned timeout)
    {
        return m_tLastCleanup < (now - timeout);
    }
private:


    //type definitions
    //define mapping from resource name to pair<timeout, permission>
    //
    //typedef map<string,  ResPermCacheEntry> MapResAccess;
    typedef map<SecCacheKeyEntry,  ResPermCacheEntry> MapResAccess;

    //define mapping from timeout to resource name (used for cleanup)
    //
    typedef multimap<time_t, SecCacheKeyEntry>        MapTimeStamp;

    //attributes
    time_t       m_tLastCleanup; //last time the cache was cleaned up
    MapResAccess m_resAccessMap; //map of resource to pair<timeout, permission>
    MapTimeStamp m_timestampMap; //map of timeout to resource name
    string       m_user;
    class CPermissionsCache* m_pParentCache;
};

class CachedUser
{
private:
    Owned<ISecUser> m_user;
    time_t          m_timestamp;
public:
    CachedUser(ISecUser* user)
    {
        if(!user)
            throw MakeStringException(-1, "can't create CachedUser, NULL user pointer");
        m_user.setown(user);
        time(&m_timestamp);
    }

    time_t getTimestamp()
    {
        return m_timestamp;
    }

    ISecUser* queryUser()
    {
        return m_user.get();
    }

    void setTimeStamp(time_t timestamp)
    {
        m_timestamp = timestamp;
    }
};

// main cache that stores all user-specific caches (defined by CResPermissionsCache above)
//

#define DEFAULT_RESOURCE_CACHE_TIMEOUT_MINUTES 60 //by default, resource cache times out every hour

class CPermissionsCache : public CInterface
{
public:
    CPermissionsCache(const char * _secMgrClass, ISecManager *secMgr, unsigned cacheTimeoutMinutes = 0)
    {
        m_cacheTimeoutInSeconds = cacheTimeoutMinutes * 60;
        m_secMgr = secMgr;
        m_defaultPermission = SecAccess_Unknown;    // TO BE DEPRECATED
        m_secMgrClass.set(_secMgrClass);
    }

    CPermissionsCache(ISecManager *secMgr, unsigned cacheTimeoutMinutes = 0) : CPermissionsCache(nullptr, secMgr, cacheTimeoutMinutes) {}

    virtual ~CPermissionsCache();

    //Returns an owned reference to a shared cache of a given Sec Mgr class type.
    //Call this method with a unique class string ("LDAP", "MyOtherSecMgr")
    //to create a cache shared amongst security managers of the same class
    static CPermissionsCache* getInstance(const char * _secMgrClass, ISecManager *secMgr, unsigned cacheTimeoutMinutes = 0);

    //finds cached permissions for a number of resources and sets them in
    //and also returns status in the boolean array passed in
    //
    virtual int lookup( ISecUser& sec_user, IArrayOf<ISecResource>& resources, bool* found );

    //fetch permissions from resources passed in and store them in the cache
    //
    virtual void add   ( ISecUser& sec_user, IArrayOf<ISecResource>& resources );
    virtual void removePermissions( ISecUser& sec_user);
    virtual void remove   (SecResourceType rtype, const char* resourcename);

    virtual bool lookup( ISecUser& sec_user);
    virtual ISecUser* getCachedUser( ISecUser& sec_user);

    virtual void add (ISecUser& sec_user);
    virtual void removeFromUserCache(ISecUser& sec_user);
    int getCacheTimeout() { return m_cacheTimeoutInSeconds; }
    bool  isCacheEnabled() { return m_cacheTimeoutInSeconds > 0; }
    void managedFileScopesCacheFillThread();
    void flush();
    bool addManagedFileScopes(const IArrayOf<ISecResource>& scopes);
    void removeAllManagedFileScopes();
    bool queryPermsManagedFileScope(ISecUser& sec_user, const char * fullScope, StringBuffer& managedScope, SecAccessFlags * accessFlags);

    SecAccessFlags  queryDefaultPermission(ISecUser& user);

private:

    void clearPermissionsCache();
    void clearUsersCache();
    void fillManagedFileScopesCache(bool lockAlreadyAcquired);
    void replaceManagedFileScopesCache(const IArrayOf<ISecResource> &scopes);
    void setSecManager(ISecManager * secMgr) { m_secMgr = secMgr; }
    typedef std::map<string, CResPermissionsCache*> MapResPermissionsCache;
    typedef std::map<string, CachedUser*> MapUserCache;

    MapResPermissionsCache m_resPermissionsMap;  //user specific resource permissions cache
    mutable ReadWriteLock m_resPermCacheRWLock; //guards m_resPermissionsMap

    time_t m_cacheTimeoutInSeconds;

    MapUserCache m_userCache;
    mutable ReadWriteLock m_userCacheRWLock;    //guards m_userCache

    StringAttr                  m_secMgrClass;

    //Managed File Scope support
    std::map<std::string, SecAccessFlags> m_userDefaultFileScopePermissions;
    SecAccessFlags              m_defaultPermission;    // TO BE DEPRECATED - SECURITY HOLE
    map<string, ISecResource*>  m_managedFileScopesMap;
    mutable ReadWriteLock       m_scopesRWLock;//guards m_managedFileScopesMap
    ISecManager *               m_secMgr;

    Semaphore m_exitFileScopeCacheFillThreadSem;

    std::thread m_fileScopeCacheFillThread;
    std::atomic<bool> m_fileScopeCacheReady = false;         // initial fill complete
    std::atomic<time_t> m_lastCacheFillTime = 0;             // time of last cache fill
};


#ifdef _MSC_VER
#pragma warning (pop)
#endif
#endif
