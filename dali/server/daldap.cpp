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

#include "platform.h"
#include "jlib.hpp"
#include "jiface.hpp"
#include "jencrypt.hpp"
#include "thirdparty.h"

#include "dasds.hpp"
#include "daldap.hpp"
#include "mpbase.hpp"
#include "dautils.hpp"
#include "digisign.hpp"
#include "workunit.hpp"

using namespace cryptohelper;

#ifndef _NO_LDAP
#include "seclib.hpp"
#include "secloader.hpp"
#include "ldapsecurity.ipp"
#include "ldapsecurity.hpp"

static void ignoreSigPipe()
{
#ifndef _WIN32
    struct sigaction act;
    sigset_t blockset;
    sigemptyset(&blockset);
    act.sa_mask = blockset;
    act.sa_handler = SIG_IGN;
    act.sa_flags = 0;
    sigaction(SIGPIPE, &act, NULL);
#endif
}

class CDaliLdapConnection: implements IDaliLdapConnection, public CInterface
{
    Owned<ISecManager>      ldapsecurity;
    unsigned                ldapflags;
    IDigitalSignatureManager * pDSM = nullptr;

public:
    IMPLEMENT_IINTERFACE;

    CDaliLdapConnection(IPropertyTree *ldapprops)
    {
        ldapflags = 0;
        if (ldapprops) {
            if (ldapprops->getPropBool("@checkScopeScans",true))
                ldapflags |= DLF_SCOPESCANS;
            if (ldapprops->getPropBool("@safeLookup",true))
                ldapflags |= DLF_SAFE;
            const char *addr = ldapprops->queryProp("@ldapAddress");
            if (!addr || !*addr)
            {
                /* Do not give an error if blank ldap server provided (for backward compat of old configuration

                const char* pszErrMsg = "Invalid LDAP server address!";
                OERRLOG(pszErrMsg);
                throw MakeStringException(-1, pszErrMsg);
                */
            }
            else
            {
                try {
                    ignoreSigPipe(); // LDAP can generate
                    ldapprops->Link();
                    ISecManager *mgr=newLdapSecManager("", *ldapprops);
                    ldapsecurity.setown(mgr);
                    if (mgr)
                        ldapflags |= DLF_ENABLED;

                }
                catch (IException *e) {
                    EXCLOG(e,"LDAP server");
                    throw;
                }
            }
        }
    }


    SecAccessFlags getPermissions(const char *key,const char *obj,IUserDescriptor *udesc,unsigned auditflags)
    {
        if (!ldapsecurity||((getLDAPflags()&DLF_ENABLED)==0))
            return SecAccess_Full;

        bool filescope = key && stricmp(key,"Scope")==0;
        bool wuscope = key && stricmp(key,"workunit")==0;

        //
        // Missing scopes get full access
        if (!filescope && !wuscope)
            return SecAccess_Full;

        Owned<ISecUser> user;
        StringBuffer username;
        if (udesc)
        {
            udesc->getUserName(username);
            if (username.isEmpty())
            {
                OWARNLOG("Missing username in user descriptor for permission request, access denied for request key=%s object=%s", key, nullText(obj));
                return SecAccess_None; // no access if no default user or disabled
            }

            user.setown(ldapsecurity->createUser(username));
            user->setAuthenticateStatus(AS_AUTHENTICATED);  // treat caller passing user as trusted
        }
        else
        {
            DBGLOG("NULL UserDescriptor in daldap.cpp getPermissions('%s')", key);
            logNullUser(nullptr);
            OWARNLOG("NULL user for permission request, access denied for request key=%s object=%s", key, nullText(obj));
            return SecAccess_None; // no access if no default user or disabled
        }

        SecAccessFlags perm = SecAccess_None;
        unsigned start = msTick();
        if (filescope)
            perm = ldapsecurity->authorizeFileScope(*user, obj);
        else if (wuscope)
            perm = ldapsecurity->authorizeWorkunitScope(*user, obj);
        if (perm == SecAccess_Unavailable)
        {
            OWARNLOG("LDAP: getPermissions(%s) Unable to get perms for scope=%s user=%s, setting 'SecAccess_None'",
                     key, nullText(obj), username.str());
            perm = SecAccess_None;
        }
        unsigned taken = msTick() - start;
#ifndef _DEBUG
        if (taken>100)
#endif
        {
            PROGLOG("LDAP: getPermissions(%s) scope=%s user=%s returns %d in %d ms", key, nullText(obj),
                    username.str(), perm, taken);
        }
        if (auditflags & DALI_LDAP_AUDIT_REPORT)
        {
            StringBuffer auditstr;
            if ((auditflags & DALI_LDAP_READ_WANTED) && !HASREADPERMISSION(perm))
                auditstr.append("Lookup Access Denied");
            else if ((auditflags & DALI_LDAP_WRITE_WANTED) && !HASWRITEPERMISSION(perm))
                auditstr.append("Create Access Denied");
            if (auditstr.length())
            {
                auditstr.append(":\n\tProcess:\tdaserver");
                auditstr.appendf("\n\tUser:\t%s", username.str());
                auditstr.appendf("\n\tScope:\t%s\n", obj ? obj : "");
                SYSLOG(AUDIT_TYPE_ACCESS_FAILURE, auditstr.str());
            }
        }
        return perm;
    }

    bool clearPermissionsCache(IUserDescriptor *udesc)
    {
        if (!ldapsecurity || ((getLDAPflags() & DLF_ENABLED) == 0))
            return true;
        StringBuffer username;
        StringBuffer password;
        udesc->getUserName(username);
        udesc->getPassword(password);
        Owned<ISecUser> user = ldapsecurity->createUser(username);
        user->credentials().setPassword(password);
        return ldapsecurity->clearPermissionsCache(*user);
    }

    bool enableScopeScans(IUserDescriptor *udesc, bool enable, int * err)
    {
        bool superUser;
        StringBuffer username;
        StringBuffer password;
        udesc->getUserName(username);
        udesc->getPassword(password);
        Owned<ISecUser> user = ldapsecurity->createUser(username);

        //Check user's digital signature, if present
        bool authenticated = false;
        if (!isEmptyString(udesc->querySignature()))
        {
            if (nullptr == pDSM)
                pDSM = queryDigitalSignatureManagerInstanceFromEnv();
            if (pDSM && pDSM->isDigiVerifierConfigured())
            {
                StringBuffer b64Signature(udesc->querySignature());
                if (!pDSM->digiVerify(b64Signature, username))//digital signature valid?
                {
                    OERRLOG("LDAP: enableScopeScans(%s) : Invalid user digital signature", username.str());
                    *err = -1;
                    return false;
                }
                else
                    authenticated = true;
            }
        }

        if (!authenticated)
        {
            ILdapSecManager* ldapSecMgr = dynamic_cast<ILdapSecManager*>(ldapsecurity.get());
            if (!ldapSecMgr || !ldapSecMgr->isSuperUser(user))
            {
                DBGLOG("LDAP: EnableScopeScans caller %s must be an LDAP HPCC Admin", username.str());
                *err = -1;
                return false;
            }
        }

        unsigned flags = getLDAPflags();
        if (enable)
        {
            DBGLOG("Scope Scans Enabled by user %s",username.str());
            flags |= (unsigned)DLF_SCOPESCANS;
        }
        else
        {
            DBGLOG("Scope Scans Disabled by user %s",username.str());
            flags &= ~(unsigned)DLF_SCOPESCANS;
        }
        setLDAPflags(flags);
        *err = 0;
        return true;
    }

    bool checkScopeScans()
    {
        return (ldapflags&DLF_SCOPESCANS)!=0;
    }

    virtual unsigned getLDAPflags()
    {
        return ldapflags;
    }

    void setLDAPflags(unsigned flags)
    {
        ldapflags = flags;
    }


};


IDaliLdapConnection *createDaliSecMgrPluginConnection(IPropertyTree *propTree)
{
    if (propTree && propTree->hasProp("@type"))
    {
        IPropertyTree* secMgrCfg = propTree->queryPropTree(propTree->queryProp("@type"));
        return SecLoader::loadPluggableSecManager<IDaliLdapConnection>("dali", propTree, secMgrCfg);
    }
    else
    {
        return nullptr;
    }
}

IDaliLdapConnection *createDaliLdapConnection(IPropertyTree *proptree)
{
    return new CDaliLdapConnection(proptree);
}
#else
IDaliLdapConnection *createDaliLdapConnection(IPropertyTree *proptree)
{
    return NULL;
}
#endif
