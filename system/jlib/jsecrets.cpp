/*##############################################################################

    HPCC SYSTEMS software Copyright (C) 2020 HPCC Systems®.

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

#include "platform.h"
#include "jlog.hpp"
#include "jutil.hpp"
#include "jexcept.hpp"
#include "jmutex.hpp"
#include "jfile.hpp"
#include "jptree.hpp"
#include "jerror.hpp"
#include "jsecrets.hpp"
#include "jthread.hpp"

//including cpp-httplib single header file REST client
//  doesn't work with format-nonliteral as an error
//
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"

//httplib also generates warning about access outside of array bounds in gcc
#pragma GCC diagnostic ignored "-Warray-bounds"
#endif

#if defined(_USE_OPENSSL) || defined(EMSCRIPTEN)
#define CPPHTTPLIB_OPENSSL_SUPPORT
#endif

#undef INVALID_SOCKET
#include "httplib.h"

#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#ifdef _USE_OPENSSL
#include <opensslcommon.hpp>
#include <openssl/x509v3.h>
#endif

//#define TRACE_SECRETS
#include <vector>

// AKeyless does not require different kinds like Vault's kv_v1/kv_v2
// Keep enum for backward compatibility but it's no longer used
enum class CVaultKind { kv_v1, kv_v2 };

CVaultKind getSecretType(const char *s)
{
    // AKeyless uses a unified API, but maintain for compatibility
    if (isEmptyString(s))
        return CVaultKind::kv_v2;
    if (streq(s, "kv_v1"))
        return CVaultKind::kv_v1;
    return CVaultKind::kv_v2;
}
interface IVaultManager : extends IInterface
{
    virtual bool requestSecretFromVault(const char *category, const char *vaultId, CVaultKind &kind, StringBuffer &content, const char *secret, const char *version) = 0;
    virtual bool requestSecretByCategory(const char *category, CVaultKind &kind, StringBuffer &content, const char *secret, const char *version) = 0;
};

static Owned<IVaultManager> vaultManager;
static MemoryAttr udpKey;
static bool udpKeyInitialized = false;

static const IPropertyTree *getLocalSecret(const char *category, const char * name)
{
    return getSecret(category, name, "k8s", nullptr);
}

// based on kubernetes secret / key names. Even if some vault backends support additional characters we'll restrict to this subset for now
// isKeyName is not currently used, but may be in the future
inline static bool isValidSecretOrKeyNameChr(char c, bool firstOrLastChar, bool isKeyName)
{
    if (c == '\0')
        return false;
    if (isalnum(c))
        return true;
    if (firstOrLastChar)
        return false;

    switch (c)
    {
    case '.':
    case '-':
    case '_':   //keyname supports '_', relax restrictions for all - since supported by vaults
        return true;
    default:
        return false;
    }
}

static bool isValidSecretOrKeyName(const char *name, bool isKeyName)
{
    if (!isValidSecretOrKeyNameChr(*name, true, isKeyName))
        return false;
    ++name;
    while ('\0' != *name)
    {
        bool lastChar = ('\0' == *(name+1));
        if (!isValidSecretOrKeyNameChr(*name, lastChar, isKeyName))
            return false;
        ++name;
    }
    return true;
}

static void validateCategoryName(const char *category)
{
    if (!isValidSecretOrKeyName(category, true))
      throw makeStringExceptionV(-1, "Invalid secret category %s", category);
}

static void validateSecretName(const char *secret)
{
    if (!isValidSecretOrKeyName(secret, false))
      throw makeStringExceptionV(-1, "Invalid secret name %s", secret);
}

static void validateKeyName(const char *key)
{
    if (!isValidSecretOrKeyName(key, true))
      throw makeStringExceptionV(-1, "Invalid secret key name %s", key);
}

static void splitUrlAddress(const char *address, size_t len, StringBuffer &host, StringBuffer &port)
{
    if (!address || len==0)
        return;
    const char *sep = (const char *)memchr(address, ':', len);
    if (!sep)
        host.append(len, address);
    else
    {
        host.append(sep - address, address);
        len = len - (sep - address) - 1;
        port.append(len, sep+1);
    }
}

static void splitUrlAuthority(const char *authority, size_t authorityLen, StringBuffer &user, StringBuffer &password, StringBuffer &host, StringBuffer &port)
{
    if (!authority || authorityLen==0)
        return;
    const char *at = (const char *) memchr(authority, '@', authorityLen);
    if (!at)
        splitUrlAddress(authority, authorityLen, host, port);
    else
    {
        size_t userinfoLen = (at - authority);
        splitUrlAddress(at+1, authorityLen - userinfoLen - 1, host, port);
        const char *sep = (const char *) memchr(authority, ':', at - authority);
        if (!sep)
            user.append(at-authority, authority);
        else
        {
            user.append(sep-authority, authority);
            size_t passwordLen = (at - sep - 1);
            password.append(passwordLen, sep+1);
        }
    }
}

static void splitUrlAuthorityHostPort(const char *authority, size_t authorityLen, StringBuffer &user, StringBuffer &password, StringBuffer &hostPort)
{
    StringBuffer port;
    splitUrlAuthority(authority, authorityLen, user, password, hostPort, port);
    if (port.length())
        hostPort.append(':').append(port);
}

static inline void extractUrlProtocol(const char *&url, StringBuffer *scheme)
{
    if (!url)
        throw makeStringException(-1, "Invalid empty URL");
    if (0 == strnicmp(url, "HTTPS://", 8))
    {
        url+=8;
        if (scheme)
            scheme->append("https://");
    }
    else if (0 == strnicmp(url, "HTTP://", 7))
    {
        url+=7;
        if (scheme)
            scheme->append("http://");
    }
    else
        throw MakeStringException(-1, "Invalid URL, protocol not recognized %s", url);
}

static void splitUrlSections(const char *url, const char * &authority, size_t &authorityLen, StringBuffer &fullpath, StringBuffer *scheme)
{
    extractUrlProtocol(url, scheme);
    const char* path = strchr(url, '/');
    authority = url;
    if (!path)
        authorityLen = strlen(authority);
    else
    {
        authorityLen = path-url;
        if (!streq(path, "/")) // treat empty trailing path as equal to no path
            fullpath.append(path);
    }
}

extern jlib_decl void splitFullUrl(const char *url, StringBuffer &user, StringBuffer &password, StringBuffer &host, StringBuffer &port, StringBuffer &path)
{
    const char *authority = nullptr;
    size_t authorityLen = 0;
    splitUrlSections(url, authority, authorityLen, path, nullptr);
    splitUrlAuthority(authority, authorityLen, user, password, host, port);
}

extern jlib_decl void splitUrlSchemeHostPort(const char *url, StringBuffer &user, StringBuffer &password, StringBuffer &schemeHostPort, StringBuffer &path)
{
    const char *authority = nullptr;
    size_t authorityLen = 0;
    splitUrlSections(url, authority, authorityLen, path, &schemeHostPort);
    splitUrlAuthorityHostPort(authority, authorityLen, user, password, schemeHostPort);
}

extern jlib_decl void splitUrlIsolateScheme(const char *url, StringBuffer &user, StringBuffer &password, StringBuffer &scheme, StringBuffer &host, StringBuffer &port, StringBuffer &path)
{
    const char *authority = nullptr;
    size_t authorityLen = 0;
    splitUrlSections(url, authority, authorityLen, path, &scheme);
    splitUrlAuthority(authority, authorityLen, user, password, host, port);
}


static StringBuffer &replaceExtraHostAndPortChars(StringBuffer &s)
{
    size_t l = s.length();
    for (size_t i = 0; i < l; i++)
    {
        if (s.charAt(i) == '.' || s.charAt(i) == ':')
            s.setCharAt(i, '-');
    }
    return s;
}


extern jlib_decl StringBuffer &generateDynamicUrlSecretName(StringBuffer &secretName, const char *scheme, const char *userPasswordPair, const char *host, unsigned port, const char *path)
{
    secretName.set("http-connect-");
    //Having the host and port visible will help with manageability wherever the secret is stored
    if (scheme)
    {
        if (!strnicmp("http", scheme, 4))
        {
            if ('s' == scheme[4])
            {
                if (443 == port)
                    port = 0; // suppress default port, such that with or without, the generated secret name will be the same
                secretName.append("ssl-");
            }
            else if (':' == scheme[4])
            {
                if (80 == port)
                    port = 0; // suppress default port, such that with or without, the generated secret name will be the same
            }
        }
    }
    secretName.append(host);
    //port is optionally already part of host
    replaceExtraHostAndPortChars(secretName);
    if (port)
        secretName.append('-').append(port);
    //Path and username are both sensitive and shouldn't be accessible in the name, include both in the hash to give us the uniqueness we need
    unsigned hashvalue = 0;
    if (!isEmptyString(path))
        hashvalue = hashcz((const unsigned char *)path, hashvalue);
    if (!isEmptyString(userPasswordPair))
    {
        const char *delim = strchr(userPasswordPair, ':');
        //Make unique for a given username, but not the current password.  The pw provided could change but what's in the secret (if there is one) wins
        if (delim)
            hashvalue = hashc((const unsigned char *)userPasswordPair, delim-userPasswordPair, hashvalue);
        else
            hashvalue = hashcz((const unsigned char *)userPasswordPair, hashvalue);
    }
    if (hashvalue)
        secretName.appendf("-%x", hashvalue);
    return secretName;
}

extern jlib_decl StringBuffer &generateDynamicUrlSecretName(StringBuffer &secretName, const char *url, const char *inputUsername)
{
    StringBuffer username;
    StringBuffer urlPassword;
    StringBuffer scheme;
    StringBuffer host;
    StringBuffer port;
    StringBuffer path;
    splitUrlIsolateScheme(url, username, urlPassword, scheme, host, port, path);
    if (!isEmptyString(inputUsername))
        username.set(inputUsername);
    unsigned portNum = port.length() ? atoi(port) : 0;
    return generateDynamicUrlSecretName(secretName, scheme, username, host, portNum, path);
}

//---------------------------------------------------------------------------------------------------------------------

static StringBuffer secretDirectory;
static CriticalSection secretCS;

//there are various schemes for renewing kubernetes secrets and they are likely to vary greatly in how often
//  a secret gets updated this timeout determines the maximum amount of time before we'll pick up a change
//  10 minutes for now we can change this as we gather more experience and user feedback
static unsigned __int64 secretTimeoutNs = 10 * 60 * 1000000000LL;

extern jlib_decl unsigned getSecretTimeout()
{
    return secretTimeoutNs / 1000000;
}

extern jlib_decl void setSecretTimeout(unsigned timeoutMs)
{
    secretTimeoutNs = (unsigned __int64)timeoutMs * 1000000;
}

extern jlib_decl void setSecretMount(const char * path)
{
    if (!path)
    {
        getPackageFolder(secretDirectory);
        addPathSepChar(secretDirectory).append("secrets");
    }
    else
        secretDirectory.set(path);
}

static const char *ensureSecretDirectory()
{
    CriticalBlock block(secretCS);
    if (secretDirectory.isEmpty())
        setSecretMount(nullptr);
    return secretDirectory;
}

static StringBuffer &buildSecretPath(StringBuffer &path, const char *category, const char * name)
{
    return addPathSepChar(path.append(ensureSecretDirectory())).append(category).append(PATHSEPCHAR).append(name).append(PATHSEPCHAR);
}


// AKeyless authentication types - similar to Vault but with unified approach
enum class VaultAuthType {unknown, k8s, apiKey, token, clientcert};

static void setTimevalMS(timeval &tv, time_t ms)
{
    if (!ms)
        tv = {0, 0};
    else
    {
        tv.tv_sec = ms / 1000;
        tv.tv_usec = (ms % 1000)*1000;
    }
}

static bool isEmptyTimeval(const timeval &tv)
{
    return (tv.tv_sec==0 && tv.tv_usec==0);
}

//---------------------------------------------------------------------------------------------------------------------

//The secret key has the form category/name[@vaultId][#version]

static std::string buildSecretKey(const char * category, const char * name, const char * optVaultId, const char * optVersion)
{
    std::string key;
    key.append(category).append("/").append(name);
    if (optVaultId)
        key.append("@").append(optVaultId);
    if (optVersion)
        key.append("#").append(optVersion);
    return key;
}

static void expandSecretKey(std::string & category, std::string & name, std::string & optVaultId, std::string & optVersion, const char * key)
{
    const char * slash = strchr(key, '/');
    assertex(slash);
    const char * at = strchr(slash, '@');
    const char * hash = strchr(slash, '#');

    const char * end = nullptr;
    if (hash)
    {
        optVersion.assign(hash+1);
        end = hash;
    }
    if (at)
    {
        if (end)
            optVaultId.assign(at+1, end-at-1);
        else
            optVaultId.assign(at+1);
        end = at;
    }
    if (end)
        name.assign(slash+1, end-slash-1);
    else
        name.assign(slash+1);
    category.assign(key, slash-key);
}

//---------------------------------------------------------------------------------------------------------------------

//Represents an entry in the secret cache.  Once created it is always used for the secret.
using cache_timestamp = unsigned __int64;
using cache_timestamp_diff = __int64;
inline cache_timestamp getCacheTimestamp() { return nsTick(); }

class SecretCacheEntry : public CInterface
{
    friend class SecretCache;

public:
    //A cache entry is initally created that has a create and access,and check time of now
    SecretCacheEntry(cache_timestamp _now, const char * _secretKey)
    : secretKey(_secretKey), contentTimestamp(_now), accessedTimestamp(_now), checkedTimestamp(_now)
    {
    }

    unsigned getHash() const
    {
        return contentHash;
    }

    void getSecretOptions(std::string & category, std::string & name, std::string & optVaultId, std::string & optVersion)
    {
        expandSecretKey(category, name, optVaultId, optVersion, secretKey.c_str());
    }

    // We should never replace known contents for unknown contents
    // so once this returns true it should always return true
    bool hasContents() const
    {
        return contents != nullptr;
    }

    //Has the secret value been used since it was last checked for an update?
    bool isActive() const
    {
        return (cache_timestamp_diff)(accessedTimestamp - checkedTimestamp) >= 0;
    }

    //Is the secret potentially out of date?
    bool isStale() const
    {
        cache_timestamp now = getCacheTimestamp();
        cache_timestamp elapsed = (now - contentTimestamp);
        return (elapsed > secretTimeoutNs);
    }

    // Is it time to check if there is a new value for this secret?
    bool needsRefresh(cache_timestamp now) const
    {
        if (!initialized)
            return true;
        cache_timestamp elapsed = (now - checkedTimestamp);
        return (elapsed > secretTimeoutNs);
    }

    void noteAccessed(cache_timestamp now)
    {
        accessedTimestamp = now;
    }

    void noteFailedUpdate(cache_timestamp now, bool accessed)
    {
        //Update the checked timestamp - so that we do not continually check for updates to secrets which
        //are stale because the vault or other source of values in inaccessible.
        //Keep using the last good value
        initialized = true;
        checkedTimestamp = now;
        if (accessed)
            accessedTimestamp = now;
    }

    const char * queryTraceName() const { return secretKey.c_str(); }

    //The following functions can only be called from member functions of SecretCache
private:
    void updateContents(IPropertyTree * _contents, cache_timestamp now, bool accessed)
    {
        initialized = true;
        contents.set(_contents);
        updateHash();
        contentTimestamp = now;
        checkedTimestamp = now;
        if (accessed)
            accessedTimestamp = now;
    }

    void updateHash()
    {
        if (contents)
            contentHash = getPropertyTreeHash(*contents, 0x811C9DC5);
        else
            contentHash = 0;
    }
private:
    const std::string secretKey; // Duplicate of the key used to find this entry in the cache
    Linked<IPropertyTree> contents;// Can only be accessed when SecretCache::cs is held
    cache_timestamp contentTimestamp = 0;  // When was this secret read from disk/vault
    cache_timestamp accessedTimestamp = 0; // When was this secret last accessed?
    cache_timestamp checkedTimestamp = 0;  // When was this last checked for updates?
    unsigned contentHash = 0;
    bool initialized = false;
};


// A cache of (secret[:version] to a secret cache entry)
// Once a hash table entry has been created for a secret it is never removed and the associated
// value is never replaced.  This means it is safe to keep a pointer to the entry in another class.
class SecretCache
{
public:
    const IPropertyTree * getContents(SecretCacheEntry * match)
    {
        //Return contents within the critical section so no other thread can modify it
        CriticalBlock block(cs);
        return LINK(match->contents);
    }

    //Check to see if a secret exists, and if not add a null entry that has expired.
    SecretCacheEntry * getSecret(const std::string & secretKey, cache_timestamp now, bool & isNewEntry)
    {
        SecretCacheEntry * result;
        isNewEntry = false;
        CriticalBlock block(cs);
        auto match = secrets.find(secretKey);
        if (match != secrets.cend())
        {
            result = match->second.get();
            result->accessedTimestamp = now;
        }
        else
        {
            //Insert an entry with a null value
            result = new SecretCacheEntry(now, secretKey.c_str());
            secrets.emplace(secretKey, result);
            isNewEntry = true;
        }
        return result;
    }


    void gatherPendingRefresh(std::vector<SecretCacheEntry *> & pending, cache_timestamp when)
    {
        CriticalBlock block(cs);
        for (auto & entry : secrets)
        {
            SecretCacheEntry * secret = entry.second.get();
            //Only refresh secrets that have been used since the last time they were refreshed, otherwise the vault
            //may be overloaed with unnecessary requests - since secrets are never removed from the hash table.
            if (secret->isActive() && secret->needsRefresh(when))
                pending.push_back(secret);
        }
    }

    void updateSecret(SecretCacheEntry * match, IPropertyTree * value, cache_timestamp now, bool accessed)
    {
        CriticalBlock block(cs);
        match->updateContents(value, now, accessed);
    }

private:
    CriticalSection cs;
    std::unordered_map<std::string, std::unique_ptr<SecretCacheEntry>> secrets;
};

//---------------------------------------------------------------------------------------------------------------------

class CAKeyless
{
private:
    VaultAuthType authType = VaultAuthType::unknown;

    CVaultKind kind; // Kept for compatibility but not used by AKeyless
    CriticalSection akeylessCS;

    std::string clientCertPath;
    std::string clientKeyPath;

    StringBuffer category;
    StringBuffer schemeHostPort;
    StringBuffer path;
    StringBuffer akeylessNamespace; // Optional path prefix
    StringBuffer username;
    StringBuffer password;
    StringAttr name;

    StringAttr accessId; // AKeyless access ID (used for all auth types)
    StringBuffer accessKeySecretName; // For API key auth - secret containing access key
    
    StringBuffer clientToken;
    time_t clientTokenExpiration = 0;
    bool clientTokenRenewable = false;
    bool verify_server = true;
    unsigned retries = 3;
    unsigned retryWait = 1000;
    timestamp_type backoffTimeoutUs = 0; // Default to no backoff
    std::atomic<timestamp_type> backoffFailureTs{0};
    timeval connectTimeout = {0, 0};
    timeval readTimeout = {0, 0};
    timeval writeTimeout = {0, 0};

public:
    CAKeyless(IPropertyTree *vault)
    {
        category.appendLower(vault->queryName());

        StringBuffer clientTlsPath;
        buildSecretPath(clientTlsPath, "certificates", "akeylessclient");

        clientCertPath.append(clientTlsPath.str()).append(category.str()).append("/tls.crt");
        clientKeyPath.append(clientTlsPath.str()).append(category.str()).append("/tls.key");

        if (!checkFileExists(clientCertPath.c_str()))
            WARNLOG("akeyless: client cert not found, %s", clientCertPath.c_str());
        if (!checkFileExists(clientKeyPath.c_str()))
            WARNLOG("akeyless: client key not found, %s", clientKeyPath.c_str());

        StringBuffer url;
        replaceEnvVariables(url, vault->queryProp("@url"), false);
        PROGLOG("akeyless url %s", url.str());
        if (url.length())
            splitUrlSchemeHostPort(url.str(), username, password, schemeHostPort, path);

        if (username.length() || password.length())
            WARNLOG("akeyless: unexpected use of basic auth in url, user=%s", username.str());

        name.set(vault->queryProp("@name"));
        kind = getSecretType(vault->queryProp("@kind")); // Kept for compatibility

        akeylessNamespace.set(vault->queryProp("@namespace"));
        if (akeylessNamespace.length())
        {
            addPathSepChar(akeylessNamespace, '/');
            PROGLOG("akeyless: namespace (path prefix) %s", akeylessNamespace.str());
        }
        verify_server = vault->getPropBool("@verify_server", true);
        retries = (unsigned) vault->getPropInt("@retries", retries);
        retryWait = (unsigned) vault->getPropInt("@retryWait", retryWait);

        if (vault->hasProp("@backoffTimeout"))
            backoffTimeoutUs = vault->getPropInt64("@backoffTimeout") * 1000ULL;

        setTimevalMS(connectTimeout, (time_t) vault->getPropInt("@connectTimeout"));
        setTimevalMS(readTimeout, (time_t) vault->getPropInt("@readTimeout"));
        setTimevalMS(writeTimeout, (time_t) vault->getPropInt("@writeTimeout"));

        PROGLOG("AKeyless: httplib verify_server=%s", boolToStr(verify_server));

        // Set up AKeyless client auth [API Key, pre-provisioned token, kubernetes, or certificate]
        // Priority: accessId + accessKey > token > cert > kubernetes
        accessId.set(vault->queryProp("@accessId"));
        if (accessId.length())
        {
            // API Key authentication (equivalent to Vault's appRole)
            authType = VaultAuthType::apiKey;
            if (vault->hasProp("@accessKeySecret"))
                accessKeySecretName.set(vault->queryProp("@accessKeySecret"));
            if (accessKeySecretName.isEmpty())
                accessKeySecretName.set("accessKeySecret");
            PROGLOG("using AKeyless API key auth with access-id");
        }
        else if (vault->hasProp("@client-secret"))
        {
            // Pre-provisioned token authentication
            Owned<const IPropertyTree> clientSecret = getLocalSecret("system", vault->queryProp("@client-secret"));
            if (clientSecret)
            {
                StringBuffer tokenText;
                if (getSecretKeyValue(clientToken, clientSecret, "token"))
                {
                    authType = VaultAuthType::token;
                    PROGLOG("using a pre-provisioned token for AKeyless auth");
                }
            }
        }
        else if (vault->getPropBool("@useTLSCertificateAuth", false))
        {
            // Certificate authentication
            authType = VaultAuthType::clientcert;
            accessId.set(vault->queryProp("@accessId")); // Access ID required for cert auth
            PROGLOG("using TLS certificate auth for AKeyless");
        }
        else if (isContainerized())
        {
            // Kubernetes authentication
            authType = VaultAuthType::k8s;
            accessId.set(vault->queryProp("@accessId")); // Access ID required for k8s auth
            if (accessId.isEmpty())
                accessId.set("hpcc-akeyless-access");
            PROGLOG("using kubernetes AKeyless auth");
        }
    }
    inline const char *queryAuthType()
    {
        switch (authType)
        {
            case VaultAuthType::apiKey:
                return "apikey";
            case VaultAuthType::k8s:
                return "kubernetes";
            case VaultAuthType::token:
                return "token";
            case VaultAuthType::clientcert:
                return "clientcert";
        }
        return "unknown";
    }
    void akeylessAuthError(const char *msg)
    {
        Owned<IException> e = makeStringExceptionV(0, "AKeyless [%s] %s auth error %s", name.str(), queryAuthType(), msg);
        OERRLOG(e);
        throw e.getClear();
    }
    void akeylessAuthErrorV(const char* format, ...) __attribute__((format(printf, 2, 3)))
    {
        va_list args;
        va_start(args, format);
        StringBuffer msg;
        msg.valist_appendf(format, args);
        va_end(args);
        akeylessAuthError(msg);
    }
    void processClientTokenResponse(httplib::Result &res)
    {
        if (!res)
            akeylessAuthErrorV("login communication error %d", res.error());
        if (res.error()!=0)
            OERRLOG("JSECRETS login calling HTTPLIB POST returned error %d", res.error());
        if (res->status != 200)
            akeylessAuthErrorV("[%d](%d) - response: %s", res->status, res.error(), res->body.c_str());
        const char *json = res->body.c_str();
        if (isEmptyString(json))
            akeylessAuthError("empty login response");

        Owned<IPropertyTree> respTree = createPTreeFromJSONString(json);
        if (!respTree)
            akeylessAuthError("parsing JSON response");
        
        // AKeyless returns token directly in the response, not nested in "auth"
        const char *token = respTree->queryProp("token");
        if (isEmptyString(token))
            akeylessAuthError("response missing token");

        clientToken.set(token);
        
        // AKeyless tokens typically don't have explicit expiration in response
        // They are short-lived and refreshed as needed
        clientTokenRenewable = false; // AKeyless handles token refresh automatically
        unsigned ttl = respTree->getPropInt("ttl", 0);
        if (ttl==0)
            clientTokenExpiration = 0; // No expiration
        else
            clientTokenExpiration = time(nullptr) + ttl;
        PROGLOG("AKEYLESS TOKEN ttl=%d", ttl);
    }
    bool isClientTokenExpired()
    {
        if (clientTokenExpiration==0)
            return false;

        double remaining = difftime(clientTokenExpiration, time(nullptr));
        if (remaining <= 0)
        {
            PROGLOG("akeyless auth client token expired");
            return true;
        }
        //TBD check renewal
        return false;
    }

    CVaultKind getVaultKind() const { return kind; }

    void initClient(httplib::Client &cli, httplib::Headers &headers, unsigned &numRetries)
    {
        numRetries = retries;
        cli.enable_server_certificate_verification(verify_server);
        if (!isEmptyTimeval(connectTimeout))
            cli.set_connection_timeout(connectTimeout.tv_sec, connectTimeout.tv_usec);
        if (!isEmptyTimeval(readTimeout))
            cli.set_read_timeout(readTimeout.tv_sec, readTimeout.tv_usec);
        if (!isEmptyTimeval(writeTimeout))
            cli.set_write_timeout(writeTimeout.tv_sec, writeTimeout.tv_usec);
        if (username.length() && password.length())
            cli.set_basic_auth(username, password);
        // AKeyless doesn't use namespace header, it's part of the path
    }

    // AKeyless Kubernetes authentication
    void kubernetesLogin(bool permissionDenied)
    {
        CriticalBlock block(akeylessCS);
        if (!permissionDenied && (clientToken.length() && !isClientTokenExpired()))
            return;
        DBGLOG("kubernetesLogin%s", permissionDenied ? " because existing token permission denied" : "");
        StringBuffer login_token;
        login_token.loadFile("/var/run/secrets/kubernetes.io/serviceaccount/token");
        if (login_token.isEmpty())
            akeylessAuthError("missing k8s auth token");

        // AKeyless auth uses unified /auth endpoint with access-type
        std::string json;
        json.append("{\"access-id\": \"").append(accessId.str()).append("\"");
        json.append(", \"access-type\": \"k8s\"");
        json.append(", \"k8s_service_account_token\": \"").append(login_token.str()).append("\"}");
        
        httplib::Client cli(schemeHostPort.str());
        httplib::Headers headers;

        unsigned numRetries = 0;
        initClient(cli, headers, numRetries);
        // AKeyless uses unified /auth endpoint
        httplib::Result res = cli.Post("/auth", headers, json, "application/json");
        while (!res && numRetries--)
        {
            OERRLOG("Retrying akeyless %s kubernetes auth, communication error %d", name.str(), res.error());
            if (retryWait)
                Sleep(retryWait);
            res = cli.Post("/auth", headers, json, "application/json");
        }

        processClientTokenResponse(res);
    }

    // AKeyless certificate authentication
    void clientCertLogin(bool permissionDenied)
    {
        CriticalBlock block(akeylessCS);
        if (!permissionDenied && (clientToken.length() && !isClientTokenExpired()))
            return;
        DBGLOG("clientCertLogin%s", permissionDenied ? " because existing token permission denied" : "");

        // AKeyless cert auth uses unified /auth endpoint with access-type
        std::string json;
        json.append("{\"access-id\": \"").append(accessId.str()).append("\"");
        json.append(", \"access-type\": \"cert\"}");

        httplib::Client cli(schemeHostPort.str(), clientCertPath, clientKeyPath);
        httplib::Headers headers;

        unsigned numRetries = 0;
        initClient(cli, headers, numRetries);
        httplib::Result res = cli.Post("/auth", headers, json, "application/json");
        while (!res && numRetries--)
        {
            OERRLOG("Retrying akeyless %s client cert auth, communication error %d", name.str(), res.error());
            if (retryWait)
                Sleep(retryWait);
            res = cli.Post("/auth", headers, json, "application/json");
        }

        processClientTokenResponse(res);
    }

    // AKeyless API Key authentication (replaces Vault's appRole)
    void apiKeyLogin(bool permissionDenied)
    {
        CriticalBlock block(akeylessCS);
        if (!permissionDenied && (clientToken.length() && !isClientTokenExpired()))
            return;
        DBGLOG("apiKeyLogin%s", permissionDenied ? " because existing token permission denied" : "");
        StringBuffer accessKey;
        Owned<const IPropertyTree> accessKeySecret = getLocalSecret("system", accessKeySecretName);
        if (!accessKeySecret)
            akeylessAuthErrorV("access key secret %s not found", accessKeySecretName.str());
        else if (!getSecretKeyValue(accessKey, accessKeySecret, "access-key"))
            akeylessAuthErrorV("access key not found at '%s/access-key'", accessKeySecretName.str());
        if (accessKey.isEmpty())
            akeylessAuthError("missing access-key");

        // AKeyless API key auth
        std::string json;
        json.append("{\"access-id\": \"").append(accessId.str()).append("\"");
        json.append(", \"access-key\": \"").append(accessKey.str()).append("\"}");

        httplib::Client cli(schemeHostPort.str());
        httplib::Headers headers;

        unsigned numRetries = 0;
        initClient(cli, headers, numRetries);
        // AKeyless uses unified /auth endpoint
        httplib::Result res = cli.Post("/auth", headers, json, "application/json");
        while (!res && numRetries--)
        {
            OERRLOG("Retrying akeyless %s API key auth, communication error %d", name.str(), res.error());
            if (retryWait)
                Sleep(retryWait);
            res = cli.Post("/auth", headers, json, "application/json");
        }

        processClientTokenResponse(res);
    }
    void checkAuthentication(bool permissionDenied)
    {
        if (authType == VaultAuthType::apiKey)
            apiKeyLogin(permissionDenied);
        else if (authType == VaultAuthType::k8s)
            kubernetesLogin(permissionDenied);
        else if (authType == VaultAuthType::clientcert)
            clientCertLogin(permissionDenied);
        else if (permissionDenied && authType == VaultAuthType::token)
            akeylessAuthError("token permission denied"); //don't permanently invalidate token. Try again next time because it could be permissions for a particular secret rather than invalid token
        if (clientToken.isEmpty())
            akeylessAuthError("no akeyless access token");
    }
    bool requestSecretAtLocation(CVaultKind &rkind, StringBuffer &content, const char *location, const char *secretCacheKey, const char *version, bool permissionDenied)
    {
        //If a previous request failed, then do not retry until backoffTimeoutUs has passed.
        if (backoffFailureTs)
        {
            if (getTimeStampNowValue() - backoffFailureTs < backoffTimeoutUs)
                return false;

            //Clear the last failure - to avoid the check on the timestamp.
            backoffFailureTs = 0;
        }

        bool backoff = false;
        try
        {
            checkAuthentication(permissionDenied);
            if (isEmptyString(location))
            {
                OERRLOG("AKeyless %s cannot get secret at location without a location", name.str());
                return false;
            }

            httplib::Client cli(schemeHostPort.str());
            httplib::Headers headers = {
                { "Authorization", StringBuffer("Bearer ").append(clientToken.str()).str() }
            };

            unsigned numRetries = 0;
            initClient(cli, headers, numRetries);
            
            // AKeyless uses POST for secret retrieval with JSON payload
            std::string requestJson;
            requestJson.append("{\"names\": [\"").append(location).append("\"]}");
            
            httplib::Result res = cli.Post("/get-secret-value", headers, requestJson, "application/json");
            while (!res && numRetries--)
            {
                OERRLOG("Retrying akeyless %s get secret, communication error %d location %s", name.str(), res.error(), location);
                if (retryWait)
                    Sleep(retryWait);
                res = cli.Post("/get-secret-value", headers, requestJson, "application/json");
            }

            if (res)
            {
                if (res->status == 200)
                {
                    rkind = kind;
                    content.append(res->body.c_str());
                    return true;
                }
                else if (res->status == 403 || res->status == 401)
                {
                    //try again forcing relogin, but only once.  Just in case the token was invalidated but hasn't passed expiration time (for example max usage count exceeded).
                    if (permissionDenied==false)
                        return requestSecretAtLocation(rkind, content, location, secretCacheKey, version, true);
                    OERRLOG("AKeyless %s permission denied accessing secret (check namespace=%s?) %s.%s location %s [%d](%d) - response: %s", name.str(), akeylessNamespace.str(), secretCacheKey, version ? version : "", location, res->status, res.error(), res->body.c_str());
                }
                else if (res->status == 404)
                {
                    OERRLOG("AKeyless %s secret not found %s.%s location %s", name.str(), secretCacheKey, version ? version : "", location);
                }
                else
                {
                    OERRLOG("AKeyless %s error accessing secret %s.%s location %s [%d](%d) - response: %s", name.str(), secretCacheKey, version ? version : "", location, res->status, res.error(), res->body.c_str());
                }
            }
            else
                OERRLOG("Error: AKeyless %s http error (%d) accessing secret %s.%s location %s", name.str(), res.error(), secretCacheKey, version ? version : "", location);
        }
        catch (IException * e)
        {
            backoff = true;
            OERRLOG(e);
            e->Release();
        }

        //If authentication failed (or another serious error), then record when that failure occurred
        if (backoff && backoffTimeoutUs)
            backoffFailureTs = getTimeStampNowValue();

        return false;
    }
    bool requestSecret(CVaultKind &rkind, StringBuffer &content, const char *secret, const char *version)
    {
        if (isEmptyString(secret))
            return false;

        // Build secret path, prepending namespace if configured
        StringBuffer location;
        if (akeylessNamespace.length())
            location.append(akeylessNamespace);
        
        location.append(path);
        location.replaceString("${secret}", secret);
        location.replaceString("${version}", version ? version : "1");

        return requestSecretAtLocation(rkind, content, location, secret, version, false);
    }
};

class CAKeylessSet
{
private:
    std::map<std::string, std::unique_ptr<CAKeyless>> akeylessInstances;
public:
    CAKeylessSet()
    {
    }
    void addAKeyless(IPropertyTree *akeyless)
    {
        const char *name = akeyless->queryProp("@name");
        if (!isEmptyString(name))
            akeylessInstances.emplace(name, std::unique_ptr<CAKeyless>(new CAKeyless(akeyless)));
    }
    bool requestSecret(CVaultKind &kind, StringBuffer &content, const char *secret, const char *version)
    {
        auto it = akeylessInstances.begin();
        for (; it != akeylessInstances.end(); it++)
        {
            if (it->second->requestSecret(kind, content, secret, version))
                return true;
        }
        return false;
    }
    bool requestSecretFromAKeyless(const char *akeylessId, CVaultKind &kind, StringBuffer &content, const char *secret, const char *version)
    {
        if (isEmptyString(akeylessId))
            return false;
        auto it = akeylessInstances.find(akeylessId);
        if (it == akeylessInstances.end())
            return false;
        return it->second->requestSecret(kind, content, secret, version);
    }
};

class CAKeylessManager : public CInterfaceOf<IVaultManager>
{
private:
    std::map<std::string, std::unique_ptr<CAKeylessSet>> categories;
public:
    CAKeylessManager()
    {
        Owned<const IPropertyTree> config;
        try
        {
            config.setown(getComponentConfigSP()->getPropTree("vaults"));
        }
        catch (IException * e)
        {
            EXCLOG(e);
            e->Release();
        }
        if (!config)
            return;
        Owned<IPropertyTreeIterator> iter = config->getElements("*");
        ForEach (*iter)
        {
            IPropertyTree &akeyless = iter->query();
            const char *category = akeyless.queryName();
            auto it = categories.find(category);
            if (it == categories.end())
            {
                auto placed = categories.emplace(category, std::unique_ptr<CAKeylessSet>(new CAKeylessSet()));
                if (placed.second)
                    it = placed.first;
            }
            if (it != categories.end())
                it->second->addAKeyless(&akeyless);
        }
    }
    bool requestSecretFromVault(const char *category, const char *akeylessId, CVaultKind &kind, StringBuffer &content, const char *secret, const char *version) override
    {
        if (isEmptyString(category))
            return false;
        auto it = categories.find(category);
        if (it == categories.end())
            return false;
        return it->second->requestSecretFromAKeyless(akeylessId, kind, content, secret, version);
    }

    bool requestSecretByCategory(const char *category, CVaultKind &kind, StringBuffer &content, const char *secret, const char *version) override
    {
        if (isEmptyString(category))
            return false;
        auto it = categories.find(category);
        if (it == categories.end())
            return false;
        return it->second->requestSecret(kind, content, secret, version);
    }
};

static CConfigUpdateHook akeylessManagerUpdateHook;
static void akeylessManagerConfigUpdate(const IPropertyTree *oldComponentConfiguration, const IPropertyTree *oldGlobalConfiguration)
{
    Owned<IVaultManager> newAKeylessManager = new CAKeylessManager();
    {
        CriticalBlock block(secretCS);
        vaultManager.swap(newAKeylessManager);
    }
}
IVaultManager *getVaultManager()
{
    CriticalBlock block(secretCS);
    if (!vaultManager)
    {
        vaultManager.setown(new CAKeylessManager());
        akeylessManagerUpdateHook.installOnce(akeylessManagerConfigUpdate, false);
    }
    return LINK(vaultManager);
}

//---------------------------------------------------------------------------------------------------------------------

static SecretCache globalSecretCache;
static CriticalSection mtlsInfoCacheCS;
static std::unordered_map<std::string, Linked<ISyncedPropertyTree>> mtlsInfoCache;

MODULE_INIT(INIT_PRIORITY_SYSTEM)
{
    return true;
}

MODULE_EXIT()
{
    vaultManager.clear();
    udpKey.clear();
}


static IPropertyTree * resolveLocalSecret(const char *category, const char * name)
{
    StringBuffer path;
    buildSecretPath(path, category, name);

    Owned<IDirectoryIterator> entries = createDirectoryIterator(path);
    if (!entries || !entries->first())
        return nullptr;

    Owned<IPropertyTree> tree(createPTree(name));
    ForEach(*entries)
    {
        if (entries->isDir())
            continue;
        StringBuffer secretKeyName;   // filename is used as the secret key name
        entries->getName(secretKeyName);
        if (!validateXMLTag(secretKeyName))
            continue;

        Owned<IFileIO> io = entries->query().open(IFOread);
        if (!io)
            continue;

        offset_t sz = io->size();
        if (sz == 0)
            continue;

        StringBuffer value;
        char *valuePtr = value.reserveTruncate(sz);
        if (sz != io->read(0, sz, valuePtr))
            continue;

        // Remove trailing whitespace
        value.clip();

        tree->setProp(secretKeyName, value);
    }

    return tree.getClear();
}

static IPropertyTree *createPTreeFromAKeylessSecret(const char *content, CVaultKind kind, const char *secretPath)
{
    if (isEmptyString(content))
        return nullptr;

    Owned<IPropertyTree> tree = createPTreeFromJSONString(content);
    if (!tree)
        return nullptr;
    
    // AKeyless returns secrets in a different format than Vault
    // Response format: {"/path/to/secret": "value"} or {"/path/to/secret": {"key1": "val1", ...}}
    
    // Try to get the secret by its path
    if (!isEmptyString(secretPath))
    {
        IPropertyTree *secretData = tree->queryPropTree(secretPath);
        if (secretData)
        {
            tree.setown(LINK(secretData));
            return tree.getClear();
        }
    }
    
    // If secretPath doesn't work, check if there's a single property that contains the secret
    // This handles both string values and object values
    Owned<IPropertyTreeIterator> props = tree->getElements("*");
    if (props->first())
    {
        IPropertyTree &prop = props->query();
        // If it's a simple property with a string value, return it
        if (!props->next())
        {
            const char *val = prop.queryProp(nullptr);
            if (val)
            {
                // Simple string value
                Owned<IPropertyTree> result = createPTree();
                result->setProp("value", val);
                return result.getClear();
            }
            else
            {
                // Object value - return as is
                return LINK(&prop);
            }
        }
    }
    
    // Fallback to returning the tree as-is for backward compatibility
    return tree.getClear();
}

static IPropertyTree *resolveAKeylessSecret(const char *category, const char * name, const char *akeylessId, const char *version)
{
    CVaultKind kind;
    StringBuffer json;
    Owned<IVaultManager> akeylessmgr = getVaultManager();
    if (isEmptyString(akeylessId))
    {
        if (!akeylessmgr->requestSecretByCategory(category, kind, json, name, version))
            return nullptr;
    }
    else
    {
        if (!akeylessmgr->requestSecretFromVault(category, akeylessId, kind, json, name, version))
            return nullptr;
    }
    // Build the expected secret path for parsing response
    StringBuffer secretPath("/");
    secretPath.append(category).append("/").append(name);
    return createPTreeFromAKeylessSecret(json.str(), kind, secretPath.str());
}

static IPropertyTree * resolveSecret(const char *category, const char * name, const char * optAKeylessId, const char * optVersion)
{
    if (!isEmptyString(optAKeylessId))
    {
        if (strieq(optAKeylessId, "k8s"))
            return resolveLocalSecret(category, name);
        else
            return resolveAKeylessSecret(category, name, optAKeylessId, optVersion);
    }
    else
    {
        Owned<IPropertyTree> resolved(resolveLocalSecret(category, name));
        if (!resolved)
            resolved.setown(resolveAKeylessSecret(category, name, nullptr, optVersion));
        return resolved.getClear();
    }
}

static SecretCacheEntry * getSecretEntry(const char * category, const char * name, const char * optVaultId, const char * optVersion)
{
    cache_timestamp now = getCacheTimestamp();

    std::string key(buildSecretKey(category, name, optVaultId, optVersion));

    bool isNewEntry;
    SecretCacheEntry * match = globalSecretCache.getSecret(key, now, isNewEntry);
    if (!isNewEntry && !match->needsRefresh(now))
        return match;

    Owned<IPropertyTree> resolved(resolveSecret(category, name, optVaultId, optVersion));

    //If the secret could no longer be resolved (e.g. a vault has gone down) then keep the old one
    if (resolved)
        globalSecretCache.updateSecret(match, resolved, now, true);
    else
        match->noteFailedUpdate(now, true);

    return match;
}

static void refreshSecret(SecretCacheEntry * secret, bool accessed)
{
    cache_timestamp now = getCacheTimestamp();

    std::string category;
    std::string name;
    std::string optVaultId;
    std::string optVersion;
    secret->getSecretOptions(category, name, optVaultId, optVersion);

    Owned<IPropertyTree> resolved(resolveSecret(category.c_str(), name.c_str(), optVaultId.c_str(), optVersion.c_str()));

    //If the secret could no longer be resolved (e.g. a vault has gone down) then keep the old one
    if (resolved)
        globalSecretCache.updateSecret(secret, resolved, now, accessed);
    else
        secret->noteFailedUpdate(now, accessed);
}

static const IPropertyTree *getSecretTree(const char *category, const char * name, const char * optVaultId, const char * optVersion)
{
    SecretCacheEntry * secret = getSecretEntry(category, name, optVaultId, optVersion);
    if (secret)
        return globalSecretCache.getContents(secret);
    return nullptr;
}


//Public interface to the secrets

const IPropertyTree *getSecret(const char *category, const char * name, const char * optVaultId, const char * optVersion)
{
    validateCategoryName(category);
    validateSecretName(name);

    return getSecretTree(category,  name, optVaultId, optVersion);
}


bool getSecretKeyValue(MemoryBuffer & result, const IPropertyTree *secret, const char * key)
{
    validateKeyName(key);
    if (!secret)
        return false;
    return secret->getPropBin(key, result);
}

bool getSecretKeyValue(StringBuffer & result, const IPropertyTree *secret, const char * key)
{
    validateKeyName(key);
    if (!secret)
        return false;
    return secret->getProp(key, result);
}

extern jlib_decl bool getSecretValue(StringBuffer & result, const char *category, const char * name, const char * key, bool required)
{
    Owned<const IPropertyTree> secret = getSecret(category, name);
    if (required && !secret)
        throw MakeStringException(-1, "secret %s.%s not found", category, name);
    bool found = getSecretKeyValue(result, secret, key);
    if (required && !found)
        throw MakeStringException(-1, "secret %s.%s missing key %s", category, name, key);
    return true;
}

//---------------------------------------------------------------------------------------------------------------------

class CSecret final : public CInterfaceOf<ISyncedPropertyTree>
{
public:
    CSecret(SecretCacheEntry * _secret)
    : secret(_secret)
    {
    }

    virtual const IPropertyTree * getTree() const override;

    virtual bool getProp(MemoryBuffer & result, const char * key) const override
    {
        CriticalBlock block(secretCs);
        checkUptoDate();
        Owned<const IPropertyTree> contents = globalSecretCache.getContents(secret);
        return getSecretKeyValue(result, contents, key);
    }
    virtual bool getProp(StringBuffer & result, const char * key) const override
    {
        CriticalBlock block(secretCs);
        checkUptoDate();
        Owned<const IPropertyTree> contents = globalSecretCache.getContents(secret);
        return getSecretKeyValue(result, contents, key);
    }
    virtual bool isStale() const override
    {
        return secret->isStale();
    }
    virtual unsigned getVersion() const override
    {
        CriticalBlock block(secretCs);
        checkUptoDate();
        return secret->getHash();
    }
    virtual bool isValid() const override
    {
        return secret->hasContents();
    }

protected:
    void checkUptoDate() const;

protected:
    mutable CriticalSection secretCs;
    mutable SecretCacheEntry * secret;
};


const IPropertyTree * CSecret::getTree() const
{
    CriticalBlock block(secretCs);
    checkUptoDate();
    return globalSecretCache.getContents(secret);
}

void CSecret::checkUptoDate() const
{
    cache_timestamp now = getCacheTimestamp();
    if (secret->needsRefresh(now))
    {
#ifdef TRACE_SECRETS
        DBGLOG("Secret %s is stale updating...", secret->queryTraceName());
#endif
        //MORE: This could block or fail - in roxie especially it would be better to return the old value
        try
        {
            refreshSecret(secret, true);
        }
        catch (IException * e)
        {
            VStringBuffer msg("Failed to update secret %s", secret->queryTraceName());
            EXCLOG(e, msg.str());
            e->Release();
        }
    }
    else
        secret->noteAccessed(now);
}

ISyncedPropertyTree * getSyncedSecret(const char *category, const char * name, const char * optVaultId, const char * optVersion)
{
    validateCategoryName(category);
    validateSecretName(name);

    SecretCacheEntry * resolved = getSecretEntry(category, name, optVaultId, optVersion);
    return new CSecret(resolved);
}

//---------------------------------------------------------------------------------------------------------------------

//Manage a background thread, that checks which of the secrets have been accessed recently and refreshes them if they
//are going to go out of date soon.

static cache_timestamp refreshLookaheadNs = 0;
class SecretRefreshThread : public Thread
{
public:
    virtual int run() override
    {
        std::vector<SecretCacheEntry *> pending;
        while (!abort)
        {
#ifdef TRACE_SECRETS
            DBGLOG("Check for expired secrets...");
#endif
            cache_timestamp now = getCacheTimestamp();
            globalSecretCache.gatherPendingRefresh(pending, now + refreshLookaheadNs);
            for (auto secret : pending)
            {
#ifdef TRACE_SECRETS
                DBGLOG("Refreshing secret %s", secret->queryTraceName());
#endif
                refreshSecret(secret, false);
            }
            pending.clear();

            unsigned intervalMs = refreshLookaheadNs/4/1000000;
            if (sem.wait(intervalMs))
                break;
        }
        return 0;
    }

    void stop()
    {
        abort = true;
        sem.signal();
        join();
    }

public:
    std::atomic<bool> abort{false};
    Semaphore sem;
};
static Owned<SecretRefreshThread> refreshThread;

void startSecretUpdateThread(const unsigned lookaheadMs)
{
    cache_timestamp lookaheadNs = (cache_timestamp)lookaheadMs * 1000000;
    if (lookaheadNs == 0)
        lookaheadNs = secretTimeoutNs / 5;
    if (lookaheadNs > secretTimeoutNs / 2)
        lookaheadNs = secretTimeoutNs / 2;
    refreshLookaheadNs = lookaheadNs;
    if (!refreshThread)
    {
        refreshThread.setown(new SecretRefreshThread());
        refreshThread->start(false);
    }
}

void stopSecretUpdateThread()
{
    if (refreshThread)
    {
        refreshThread->stop();
        refreshThread->join();
        refreshThread.clear();
    }
}

MODULE_INIT(INIT_PRIORITY_SYSTEM)
{
    return true;
}
MODULE_EXIT()
{
    //This should have been called already, but for safety ensure the thread is terminated.
    stopSecretUpdateThread();
}

//---------------------------------------------------------------------------------------------------------------------

void initSecretUdpKey()
{
    if (udpKeyInitialized)
        return;

//can find alternatives for old openssl in the future if necessary
#if defined(_USE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    StringBuffer path;
    BIO *in = BIO_new_file(buildSecretPath(path, "certificates", "udp").append("tls.key"), "r");
    if (in == nullptr)
        return;
    EC_KEY *eckey = PEM_read_bio_ECPrivateKey(in, nullptr, nullptr, nullptr);
    if (eckey)
    {
        unsigned char *priv = NULL;
        size_t privlen = EC_KEY_priv2buf(eckey, &priv);
        if (privlen != 0)
        {
            udpKey.set(privlen, priv);
            OPENSSL_clear_free(priv, privlen);
        }
        EC_KEY_free(eckey);
    }
    BIO_free(in);
#endif
    udpKeyInitialized = true;
}

void setTestUdpKey()
{
    // Used in unit tests etc
    constexpr unsigned char key[] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                                      0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                                      0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                                      0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31
                                    };
    udpKey.set(32, key);
    udpKeyInitialized = true;
}

const MemoryAttr &getSecretUdpKey(bool required)
{
    if (!udpKeyInitialized)
        throw makeStringException(-1, "UDP Key not initialized.");
    if (required && !udpKey.length())
        throw makeStringException(-1, "UDP Key not found, cert-manager integration/configuration required.");
    return udpKey;
}

jlib_decl bool containsEmbeddedKey(const char *certificate)
{
    // look for any of:
    // -----BEGIN PRIVATE KEY-----
    // -----BEGIN RSA PRIVATE KEY-----
    // -----BEGIN CERTIFICATE-----
    // -----BEGIN PUBLIC KEY-----
    // or maybe just:
    // -----BEGIN

    if ( (strstr(certificate, "-----BEGIN PRIVATE KEY-----")) ||
         (strstr(certificate, "-----BEGIN RSA PRIVATE KEY-----")) ||
         (strstr(certificate, "-----BEGIN PUBLIC KEY-----")) ||
         (strstr(certificate, "-----BEGIN CERTIFICATE-----")) )
        return true;

    return false;
}


//---------------------------------------------------------------------------------------------------------------------

class CSyncedCertificateBase : public CInterfaceOf<ISyncedPropertyTree>
{
public:
    CSyncedCertificateBase(const char *_issuer)
    : issuer(_issuer)
    {
    }

    virtual const IPropertyTree * getTree() const override final;

    virtual bool getProp(MemoryBuffer & result, const char * key) const override final
    {
        CriticalBlock block(secretCs);
        checkUptoDate();
        return getSecretKeyValue(result, config, key);
    }
    virtual bool getProp(StringBuffer & result, const char * key) const override final
    {
        CriticalBlock block(secretCs);
        checkUptoDate();
        return getSecretKeyValue(result, config, key);
    }
    virtual bool isStale() const override final
    {
        return secret->isStale();
    }
    virtual bool isValid() const override
    {
        return secret->isValid();

    }
    virtual unsigned getVersion() const override final
    {
        CriticalBlock block(secretCs);
        checkUptoDate();
        //If information that is combined with the secret (e.g. trusted peers) can also change dynamically this would
        //need to be a separate hash calculated from the config tree
        return secretHash;
    }

protected:
    virtual void updateConfigFromSecret(const IPropertyTree * secretInfo) const = 0;

protected:
    void checkUptoDate() const;
    void createConfig() const;
    void createDefaultConfigFromSecret(const IPropertyTree * secretInfo, bool addCertificates, bool addCertificateAuthority) const;
    void updateCertificateFromSecret(const IPropertyTree * secretInfo) const;
    void updateCertificateAuthorityFromSecret(const IPropertyTree * secretInfo) const;

protected:
    StringAttr issuer;
    Owned<ISyncedPropertyTree> secret;
    mutable CriticalSection secretCs;
    mutable Linked<IPropertyTree> config;
    mutable std::atomic<unsigned> secretHash{0};
};


const IPropertyTree * CSyncedCertificateBase::getTree() const
{
    CriticalBlock block(secretCs);
    checkUptoDate();
    return LINK(config);
}

void CSyncedCertificateBase::checkUptoDate() const
{
    if (secretHash != secret->getVersion())
        createConfig();
}

void CSyncedCertificateBase::createConfig() const
{
    //Update before getting the tree to avoid potential race condition updating the tree at the same time.
    //Could alternatively return the version number from the getTree() call.
    secretHash = secret->getVersion();

    Owned<const IPropertyTree> secretInfo = secret->getTree();
    if (secretInfo)
    {
        config.setown(createPTree(issuer));
        ensurePTree(config, "verify");
        updateConfigFromSecret(secretInfo);
    }
    else
        config.clear();
}


void CSyncedCertificateBase::updateCertificateFromSecret(const IPropertyTree * secretInfo) const
{
    StringBuffer value;
    config->setProp("@issuer", issuer); // server only?
    if (secretInfo->getProp("tls.crt", value.clear()))
        config->setProp("certificate", value.str());
    if (secretInfo->getProp("tls.key", value.clear()))
        config->setProp("privatekey", value.str());
}

void CSyncedCertificateBase::updateCertificateAuthorityFromSecret(const IPropertyTree * secretInfo) const
{
    StringBuffer value;
    if (secretInfo->getProp("ca.crt", value.clear()))
    {
        IPropertyTree *verify = config->queryPropTree("verify");
        IPropertyTree *ca = ensurePTree(verify, "ca_certificates");
        ca->setProp("pem", value.str());
    }
}


//---------------------------------------------------------------------------------------------------------------------

class CIssuerConfig final : public CSyncedCertificateBase
{
public:
    CIssuerConfig(const char *_issuer, const char * _trustedPeers, bool _isClientConnection, bool _acceptSelfSigned, bool _addCACert, bool _disableMTLS)
    : CSyncedCertificateBase(_issuer), trustedPeers(_trustedPeers), isClientConnection(_isClientConnection), acceptSelfSigned(_acceptSelfSigned), addCACert(_addCACert), disableMTLS(_disableMTLS)
    {
        secret.setown(getSyncedSecret("certificates", issuer, nullptr, nullptr));
        createConfig();
    }

    virtual void updateConfigFromSecret(const IPropertyTree * secretInfo) const override;

protected:
    StringAttr trustedPeers;
    bool isClientConnection; // required in constructor
    bool acceptSelfSigned; // required in constructor
    bool addCACert; // required in constructor
    bool disableMTLS;
};


void CIssuerConfig::updateConfigFromSecret(const IPropertyTree * secretInfo) const
{
    if (!isClientConnection || !strieq(issuer, "public"))
        updateCertificateFromSecret(secretInfo);


    // addCACert is usually true. A client hitting a public issuer is the case where we don't want the ca cert
    // defined. Otherwise, for MTLS we want control over our CACert using addCACert. When hitting public services
    // using public certificate authorities we want the well known (browser compatible) CA list installed on the
    // system instead.
    if (!isClientConnection || addCACert)
        updateCertificateAuthorityFromSecret(secretInfo);

    IPropertyTree *verify = config->queryPropTree("verify");
    assertex(verify); // Should always be defined by this point.

    //For now only the "public" issuer implies client certificates are not required
    verify->setPropBool("@enable", !disableMTLS && (isClientConnection || !strieq(issuer, "public")));
    verify->setPropBool("@address_match", false);
    verify->setPropBool("@accept_selfsigned", isClientConnection && acceptSelfSigned);
    if (trustedPeers) // Allow blank string to mean none, null means anyone
        verify->setProp("trusted_peers", trustedPeers);
    else
        verify->setProp("trusted_peers", "anyone");
}


ISyncedPropertyTree * createIssuerTlsConfig(const char * issuer, const char * optTrustedPeers, bool isClientConnection, bool acceptSelfSigned, bool addCACert, bool disableMTLS)
{
    return new CIssuerConfig(issuer, optTrustedPeers, isClientConnection, acceptSelfSigned, addCACert, disableMTLS);

}
//---------------------------------------------------------------------------------------------------------------------

class CCertificateConfig final : public CSyncedCertificateBase
{
public:
    CCertificateConfig(const char * _category, const char * _secretName, bool _addCACert)
    : CSyncedCertificateBase(nullptr), addCACert(_addCACert)
    {
        secret.setown(getSyncedSecret(_category, _secretName, nullptr, nullptr));
        if (!secret->isValid())
            throw makeStringExceptionV(-1, "secret %s.%s not found", _category, _secretName);
        createConfig();
    }

    virtual void updateConfigFromSecret(const IPropertyTree * secretInfo) const override;

protected:
    bool addCACert; // required in constructor
};

void CCertificateConfig::updateConfigFromSecret(const IPropertyTree * secretInfo) const
{
    updateCertificateFromSecret(secretInfo);

    if (addCACert)
        updateCertificateAuthorityFromSecret(secretInfo);
}


ISyncedPropertyTree * createStorageTlsConfig(const char * secretName, bool addCACert)
{
    return new CCertificateConfig("storage", secretName, addCACert);

}


const ISyncedPropertyTree * getIssuerTlsSyncedConfig(const char * issuer, const char * optTrustedPeers, bool disableMTLS)
{
    if (isEmptyString(issuer))
        return nullptr;

    const char * key;
    StringBuffer temp;
    if (!isEmptyString(optTrustedPeers) || disableMTLS)
    {
        temp.append(issuer).append("/").append(optTrustedPeers).append('/').append(disableMTLS);
        key = temp.str();
    }
    else
        key = issuer;

    CriticalBlock block(mtlsInfoCacheCS);
    auto match = mtlsInfoCache.find(key);
    if (match != mtlsInfoCache.cend())
        return LINK(match->second);

    Owned<ISyncedPropertyTree> config = createIssuerTlsConfig(issuer, optTrustedPeers, false, false, true, disableMTLS);
    mtlsInfoCache.emplace(key, config);
    return config.getClear();
}

bool hasIssuerTlsConfig(const char *issuer)
{
    Owned<const ISyncedPropertyTree> match = getIssuerTlsSyncedConfig(issuer, nullptr, false);
    return match && match->isValid();
}

enum UseMTLS { UNINIT, DISABLED, ENABLED };
static UseMTLS useMtls = UNINIT;

static CriticalSection queryMtlsCS;

jlib_decl bool queryMtls()
{
    CriticalBlock block(queryMtlsCS);
    if (useMtls == UNINIT)
    {
        useMtls = DISABLED;
#if defined(_USE_OPENSSL)
# ifdef _CONTAINERIZED
        // check component setting first, but default to global
        if (getComponentConfigSP()->getPropBool("@mtls", getGlobalConfigSP()->getPropBool("security/@mtls")))
            useMtls = ENABLED;
# else
        if (queryMtlsBareMetalConfig())
        {
            useMtls = ENABLED;
            const char *cert = nullptr;
            const char *pubKey = nullptr;
            const char *privKey = nullptr;
            const char *passPhrase = nullptr;
            if (queryHPCCPKIKeyFiles(&cert, &pubKey, &privKey, &passPhrase))
            {
                if ( (!isEmptyString(cert)) && (!isEmptyString(privKey)) )
                {
                    if (checkFileExists(cert) && checkFileExists(privKey))
                    {
                        CriticalBlock block(mtlsInfoCacheCS);
                        assertex(mtlsInfoCache.find("local") == mtlsInfoCache.cend());

                        Owned<IPropertyTree> info = createPTree("local");
                        info->setProp("certificate", cert);
                        info->setProp("privatekey", privKey);
                        if ( (!isEmptyString(pubKey)) && (checkFileExists(pubKey)) )
                            info->setProp("publickey", pubKey);
                        if (!isEmptyString(passPhrase))
                            info->setProp("passphrase", passPhrase); // encrypted

                        Owned<ISyncedPropertyTree> entry = createSyncedPropertyTree(info);
                        mtlsInfoCache.emplace("local", entry);
                    }
                }
            }
        }
# endif
#endif
    }
    if (useMtls == ENABLED)
        return true;
    else
        return false;
}


#ifdef _USE_CPPUNIT
std::string testBuildSecretKey(const char * category, const char * name, const char * optVaultId, const char * optVersion)
{
    return buildSecretKey(category, name, optVaultId, optVersion);
}

void testExpandSecretKey(std::string & category, std::string & name, std::string & optVaultId, std::string & optVersion, const char * key)
{
    expandSecretKey(category, name, optVaultId, optVersion, key);
}
#endif

/**
 * Masks a secret string by replacing a percentage of its characters with a mask character.
 *
 * @param maskedSecret      [out] StringBuffer to receive the masked secret.
 * @param originalSecret    [in]  The original secret string to be masked.
 * @param maskPercentage    [in]  Percentage of the string to mask (70-100). If below minimum, defaults to 70%.
 * @param maskRightSide     [in]  If true, mask the right side of the string; if false, mask the left side.
 * @param maskChar          [in]  Character to use for masking.
 *
 * If originalSecret is empty or nullptr, maskedSecret will be unchanged.
 * If originalSecret is length 1, the result will be a single maskChar.
 * If maskPercentage is out of bounds, it will be clamped to [MIN_MASK_PERCENTAGE, 100].
 */
void maskSecret(StringBuffer & maskedSecret, const char * originalSecret, unsigned maskPercentage, bool maskRightSide, char maskChar)
{
    if (isEmptyString(originalSecret))
        return;

    auto secretLen = strlen(originalSecret);
    if (secretLen == 1)
    {
        maskedSecret.append(maskChar);
        return;
    }

    if (maskPercentage < MIN_MASK_PERCENTAGE)
        maskPercentage = MIN_MASK_PERCENTAGE;

    if (maskPercentage > 100)
        maskPercentage = 100;

    size_t unmaskedCharsCount = static_cast<size_t>(((100 - maskPercentage) / 100.0) * secretLen);
    if (maskRightSide)
    {
        for (size_t i = 0; i < unmaskedCharsCount; ++i)
            maskedSecret.append(originalSecret[i]);

        for (size_t i = 0; i < secretLen - unmaskedCharsCount; ++i)
            maskedSecret.append(maskChar);
    }
    else
    {
        for (size_t i = 0; i < secretLen - unmaskedCharsCount; ++i)
            maskedSecret.append(maskChar);

        for (size_t i = secretLen - unmaskedCharsCount; i < secretLen; ++i)
            maskedSecret.append(originalSecret[i]);
    }
}
