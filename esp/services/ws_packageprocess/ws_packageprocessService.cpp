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

#pragma warning (disable : 4786)

#include "ws_packageprocessService.hpp"
#include "daclient.hpp"
#include "dalienv.hpp"
#include "dadfs.hpp"
#include "dfuutil.hpp"
#include "ws_fs.hpp"
#include "ws_workunits.hpp"
#include "packageprocess_errors.h"
#include "referencedfilelist.hpp"
#include "package.h"
#include "eclwatch_errorlist.hpp"
#include "exception_util.hpp"
#include "TpWrapper.hpp"


void CWsPackageProcessEx::init(IPropertyTree *cfg, const char *process, const char *service)
{
    packageMapAndSet.subscribe();
}

bool CWsPackageProcessEx::onEcho(IEspContext &context, IEspEchoRequest &req, IEspEchoResponse &resp)
{
    StringBuffer respMsg;
    ISecUser* user = context.queryUser();
    if(user != NULL)
    {
        const char* name = user->getName();
        if (name && *name)
            respMsg.appendf("%s: ", name);
    }

    const char* reqMsg = req.getRequest();
    if (reqMsg && *reqMsg)
        respMsg.append(reqMsg);
    else
        respMsg.append("??");

    resp.setResponse(respMsg.str());
    return true;
}

inline StringBuffer &buildPkgSetId(StringBuffer &id, const char *process)
{
    if (!process || !*process)
        process = "*";
    return id.append("default_").append(process).replace('*', '#').replace('?', '~');
}

IPropertyTree *getPkgSetRegistry(const char *process, bool readonly)
{
    Owned<IRemoteConnection> globalLock = querySDS().connect("/PackageSets/", myProcessSession(), RTM_LOCK_WRITE|RTM_CREATE_QUERY, SDS_LOCK_TIMEOUT);
    if (!globalLock)
        throw MakeStringException(PKG_DALI_LOOKUP_ERROR, "Unable to connect to PackageSet information in dali /PackageSets");
    IPropertyTree *pkgSets = globalLock->queryRoot();
    if (!pkgSets)
        throw MakeStringException(PKG_DALI_LOOKUP_ERROR, "Unable to open PackageSet information in dali /PackageSets");

    if (!process || !*process)
        process = "*";
    StringBuffer id;
    buildPkgSetId(id, process);

    //Only lock the branch for the target we're interested in.
    VStringBuffer xpath("/PackageSets/PackageSet[@id='%s']", id.str());
    Owned<IRemoteConnection> conn = querySDS().connect(xpath.str(), myProcessSession(), readonly ? RTM_LOCK_READ : RTM_LOCK_WRITE, SDS_LOCK_TIMEOUT);
    if (!conn)
    {
        if (readonly)
            return NULL;

        Owned<IPropertyTree> pkgSet = createPTree();
        pkgSet->setProp("@id", id.str());
        pkgSet->setProp("@process", process);
        pkgSets->addPropTree("PackageSet", pkgSet.getClear());
        globalLock->commit();

        conn.setown(querySDS().connect(xpath.str(), myProcessSession(), RTM_LOCK_WRITE, SDS_LOCK_TIMEOUT));
    }

    return (conn) ? conn->getRoot() : NULL;
}

////////////////////////////////////////////////////////////////////////////////////////
const unsigned roxieQueryRoxieTimeOut = 60000;

bool isFileKnownOnCluster(const char *logicalname, IConstWUClusterInfo *clusterInfo, IUserDescriptor* userdesc)
{
    Owned<IDistributedFile> dst = queryDistributedFileDirectory().lookup(logicalname, userdesc, AccessMode::tbdWrite, false, false, nullptr, defaultPrivilegedUser);
    if (dst)
    {
        SCMStringBuffer processName;
        clusterInfo->getRoxieProcess(processName);
        if (dst->findCluster(processName.str()) != NotFound)
            return true; // file already known for this cluster
    }
    return false;
}

bool isFileKnownOnCluster(const char *logicalname, const char *target, IUserDescriptor* userdesc)
{
    Owned<IConstWUClusterInfo> clusterInfo = getWUClusterInfoByName(target);
    if (!clusterInfo)
        throw MakeStringException(PKG_TARGET_NOT_DEFINED, "Could not find information about target cluster %s ", target);

    return isFileKnownOnCluster(logicalname, clusterInfo, userdesc);
}

//MORE: This should be a member function of PackageMapUpdator
void cloneFileInfoToDali(StringBuffer &publisherWuid, unsigned updateFlags, StringArray &notFound, IPropertyTree *packageMap, const char *remoteLocation, IConstWUClusterInfo *dstInfo, const char *srcCluster, const char *remotePrefix, IUserDescriptor* userdesc, bool allowForeignFiles, const char *jobname, const char * keyCompression)
{
    StringBuffer user;
    StringBuffer password;

    if (userdesc)
    {
        userdesc->getUserName(user);
        userdesc->getPassword(password);
    }

    Owned<IReferencedFileList> wufiles = createReferencedFileList(user, password, allowForeignFiles, false, jobname);
    if (keyCompression)
        wufiles->setKeyCompression(keyCompression);
    wufiles->addFilesFromPackageMap(packageMap);

    Owned<IDFUhelper> helper = createIDFUhelper();
#ifdef _CONTAINERIZED
    SCMStringBuffer clusterName;
    dstInfo->getName(clusterName);
    StringArray locations; //roxie won't make local copies of files on these planes
    StringBuffer targetPlane; //roxies default plane, where files will be copied if not found in locations
    getRoxieDirectAccessPlanes(locations, targetPlane, clusterName.str(), true);

    wufiles->resolveFiles(locations, remoteLocation, remotePrefix, srcCluster, !(updateFlags & (DALI_UPDATEF_REPLACE_FILE | DALI_UPDATEF_CLONE_FROM)), false, false, false, (updateFlags & DFU_UPDATEF_REMOTESTORAGE)!=0);
    wufiles->cloneAllInfo(publisherWuid, targetPlane, updateFlags, helper, true, false, 0, 1, 0, nullptr);
#else
    StringArray locations;
    SCMStringBuffer processName;
    dstInfo->getRoxieProcess(processName);
    locations.append(processName.str());
    wufiles->resolveFiles(locations, remoteLocation, remotePrefix, srcCluster, !(updateFlags & (DALI_UPDATEF_REPLACE_FILE | DALI_UPDATEF_CLONE_FROM)), false, false, false, (updateFlags & DFU_UPDATEF_REMOTESTORAGE)!=0);

    StringBuffer defReplicateFolder;
    getConfigurationDirectory(NULL, "data2", "roxie", processName.str(), defReplicateFolder);

    wufiles->cloneAllInfo(publisherWuid, processName.str(), updateFlags, helper, true, false, dstInfo->getRoxieRedundancy(), dstInfo->getChannelsPerNode(), dstInfo->getRoxieReplicateOffset(), defReplicateFolder);
#endif

    Owned<IReferencedFileIterator> iter = wufiles->getFiles();
    ForEach(*iter)
    {
        IReferencedFile &item = iter->query();
        if (item.getFlags() & (RefFileNotFound | RefFileNotOnSource))
            notFound.append(item.getLogicalName());
    }
}

void cloneFileInfoToDali(StringBuffer &publisherWuid, unsigned updateFlags, StringArray &notFound, IPropertyTree *packageMap, const char *lookupDaliIp, const char *dstCluster, const char *srcCluster, const char *prefix, IUserDescriptor* userdesc, bool allowForeignFiles, const char *jobname, const char * keyCompression)
{
    Owned<IConstWUClusterInfo> clusterInfo = getWUClusterInfoByName(dstCluster);
    if (!clusterInfo)
        throw MakeStringException(PKG_TARGET_NOT_DEFINED, "Could not find information about target cluster %s ", dstCluster);

    cloneFileInfoToDali(publisherWuid, updateFlags, notFound, packageMap, lookupDaliIp, clusterInfo, srcCluster, prefix, userdesc, allowForeignFiles, jobname, keyCompression);
}

void makePackageActive(IPropertyTree *pkgSet, IPropertyTree *psEntryNew, const char *target, bool activate)
{
    if (activate)
    {
        VStringBuffer xpath("PackageMap[@querySet='%s'][@active='1']", target);
        Owned<IPropertyTreeIterator> psEntries = pkgSet->getElements(xpath.str());
        ForEach(*psEntries)
        {
            IPropertyTree &entry = psEntries->query();
            if (psEntryNew != &entry)
                entry.setPropBool("@active", false);
        }
    }
    if (psEntryNew->getPropBool("@active") != activate)
        psEntryNew->setPropBool("@active", activate);
}

void fixPackageMapFileIds(IPropertyTreeIterator *iter, bool preloadAll)
{
    if (!iter)
        return;
    ForEach(*iter)
    {
        IPropertyTree &item = iter->query();
        if (preloadAll)
            item.setPropBool("@preload", true);
        Owned<IPropertyTreeIterator> superFiles = item.getElements("SuperFile");
        ForEach(*superFiles)
        {
            IPropertyTree &superFile = superFiles->query();
            StringBuffer lc(superFile.queryProp("@id"));
            const char *id = lc.toLowerCase().str();
            if (*id == '~')
                id++;
            superFile.setProp("@id", id);

            Owned<IPropertyTreeIterator> subFiles = superFile.getElements("SubFile");
            ForEach(*subFiles)
            {
                IPropertyTree &subFile = subFiles->query();
                id = subFile.queryProp("@value");
                if (id && *id == '~')
                {
                    StringAttr value(id+1);
                    subFile.setProp("@value", value.get());
                }
            }
        }
    }
}

void fixPackageMapFileIds(IPropertyTree *pm, bool preloadAll)
{
    if (!pm)
        return;
    Owned<IPropertyTreeIterator> iter = pm->getElements("Package");
    fixPackageMapFileIds(iter, preloadAll);

    iter.setown(pm->getElements("Part/Package"));
    fixPackageMapFileIds(iter, preloadAll);
}

//////////////////////////////////////////////////////////

#define PKGADD_DFS_OVERWRITE    0x0001
#define PKGADD_ALLOW_FOREIGN    0x0002
#define PKGADD_PRELOAD_ALL      0x0004
#define PKGADD_MAP_ACTIVATE     0x0100
#define PKGADD_MAP_CREATE       0x0200
#define PKGADD_MAP_REPLACE      0x0400
#define PKGADD_SEG_ADD          0x1000
#define PKGADD_SEG_REPLACE      0x2000

class PackageMapUpdater
{
public:
    Owned<IRemoteConnection> globalLock;
    Owned<IUserDescriptor> userdesc;
    Owned<IConstWUClusterInfo> clusterInfo;
    Owned<IPropertyTree> pmPart;
    IPropertyTree *packageMaps;
    IPropertyTree *pmExisting;

    StringBuffer remoteLocation;
    StringBuffer srcCluster;
    StringBuffer prefix;
    StringBuffer pmid;
    StringBuffer pkgSetId;
    StringBuffer publisherWuid;
    StringBuffer publisherState;

    StringAttr process;
    StringAttr target;
    StringAttr dfuQueue;
    StringAttr keyCompression;
    unsigned flags;
    unsigned dfuWait = 1800000; //wait for DFU Copy, default 30 minutes (only used if !req.getOnlyCopyFiles() and !req.getStopIfFilesCopied())

    PackageMapUpdater() : packageMaps(NULL), pmExisting(NULL), flags(0) {}

    inline bool checkFlag(unsigned check)
    {
        return (flags & check) != 0;
    }

    inline void setFlag(unsigned flag, bool on=true)
    {
        if (on)
            flags |= flag;
    }
    IConstWUClusterInfo *ensureClusterInfo()
    {
        clusterInfo.setown(getWUClusterInfoByName(target));
        if (!clusterInfo)
            throw MakeStringException(PKG_TARGET_NOT_DEFINED, "Could not find information about target cluster %s ", target.str());
        return clusterInfo;
    }
    void setPMID(const char *_target, const char *name, bool globalScope)
    {
        if (!name || !*name)
            throw MakeStringExceptionDirect(PKG_MISSING_PARAM, "PackageMap name parameter required");
        if (!globalScope)
        {
            target.set(_target);
            if (target.isEmpty())
                throw MakeStringExceptionDirect(PKG_MISSING_PARAM, "Target cluster parameter required");

            if (!streq(target.get(), "*"))
                ensureClusterInfo();
            pmid.append(target).append("::");
        }
        pmid.append(name);
        pmid.toLowerCase();
    }
    void setProcess(const char *name)
    {
        process.set(name);
        buildPkgSetId(pkgSetId, process);
    }
    void setUser(const char *user, const char *password, IEspContext *context)
    {
        if (user && *user)
        {
            userdesc.setown(createUserDescriptor());
            userdesc->set(user, password);
            return;
        }
        if (!context)
            return;
        setUser(context->queryUserId(), context->queryPassword(), nullptr);
    }
    void setDerivedDfsLocation(const char *dfsLocation, const char *srcProcess)
    {
        splitDerivedDfsLocation(dfsLocation, srcCluster, remoteLocation, prefix, srcProcess, srcProcess, NULL, NULL);
        if (srcCluster.length())
        {
            if (!validateDataPlaneName(remoteLocation, srcCluster))
                throw MakeStringException(PKG_INVALID_CLUSTER_TYPE, "Process cluster %s not found on %s remote", srcCluster.str(), remoteLocation.length() ? remoteLocation.str() : "local");
        }
    }
    void convertExisting()
    {
        Linked<IPropertyTree> pmPart = pmExisting;
        const char *s = strstr(pmid.str(), "::");
        if (s)
            pmPart->addProp("@id", s+2);
        packageMaps->removeTree(pmExisting);

        Owned<IPropertyTree> pmTree = createPTree("PackageMap", ipt_ordered);
        pmTree->setProp("@id", pmid);
        pmTree->setPropBool("@multipart", true);
        pmTree->addPropTree("Part", pmPart.getClear());
        pmExisting = packageMaps->addPropTree("PackageMap", pmTree.getClear());
    }
    void init()
    {
        VStringBuffer xpath("PackageMap[@id='%s']", pmid.str());
        globalLock.setown(querySDS().connect("/PackageMaps", myProcessSession(), RTM_LOCK_WRITE|RTM_CREATE_QUERY, SDS_LOCK_TIMEOUT));
        packageMaps = globalLock->queryRoot();
        pmExisting = packageMaps->queryPropTree(xpath);
        if (pmExisting && !pmExisting->getPropBool("@multipart", false))
            convertExisting();
    }
    void createPart(const char *partname, IPropertyTree *pTree)
    {
        if (!partname || !*partname)
            throw MakeStringExceptionDirect(PKG_INFO_NOT_DEFINED, "No PackageMap Part name provided");
        if (!pTree)
            throw MakeStringExceptionDirect(PKG_INFO_NOT_DEFINED, "No PackageMap content provided");

        pmPart.set(pTree);
        if (!pmPart)
            throw MakeStringExceptionDirect(PKG_INFO_NOT_DEFINED, "Invalid PackageMap content");
        pmPart->addProp("@id", partname);

        StringBuffer lcPmid(pmid);
        pmid = lcPmid.toLowerCase().str();

        fixPackageMapFileIds(pmPart, checkFlag(PKGADD_PRELOAD_ALL));
    }
    void cloneDfsInfo(unsigned updateFlags, StringArray &filesNotFound, IPropertyTree *pt)
    {
        const char *jobname = pmPart ? pmPart->queryProp("@id") : nullptr;
        if (isEmptyString(jobname))
            jobname = pmid.str();
        if (!streq(target.get(), "*"))
            cloneFileInfoToDali(publisherWuid, updateFlags, filesNotFound, pt, remoteLocation, ensureClusterInfo(), srcCluster, prefix, userdesc, checkFlag(PKGADD_ALLOW_FOREIGN), jobname, keyCompression);
        else
        {
            CConstWUClusterInfoArray clusters;
            getWUClusterInfo(clusters);
            ForEachItemIn(i, clusters)
            {
                IConstWUClusterInfo &cluster = clusters.item(i);
                if (cluster.getPlatform() == RoxieCluster)
                    cloneFileInfoToDali(publisherWuid, updateFlags, filesNotFound, pt, remoteLocation, &cluster, srcCluster, prefix, userdesc, checkFlag(PKGADD_ALLOW_FOREIGN), jobname, keyCompression);
            }
        }
    }
    void cloneDfsInfo(unsigned updateFlags, StringArray &filesNotFound)
    {
        cloneDfsInfo(updateFlags, filesNotFound, pmPart);
    }
    bool updateDfuPublisherState(bool waitForCompletion)
    {
        DFUstate state = DFUstate_unknown;
        if (!publisherWuid.isEmpty())
        {
            Owned<IDFUWorkUnitFactory> factory = getDFUWorkUnitFactory();
            Owned<IConstDFUWorkUnit> dfuPublisherWu = factory->openWorkUnit(publisherWuid, false);
            if (dfuPublisherWu)
            {
                if (waitForCompletion)
                    state = dfuPublisherWu->pollForCompletion(dfuWait);
                else
                {
                    IConstDFUprogress *progress = dfuPublisherWu->queryProgress();
                    if (progress)
                        state = progress->getState();
                }
            }
        }
        encodeDFUstate(state, publisherState);
        return (state == DFUstate_finished);
    }
    bool waitForDfuWorkunit()
    {
        if (!publisherWuid.isEmpty())
            return updateDfuPublisherState(true);
        return true;
    }

    bool doCreate(const char *partname, IPropertyTree *pTree, unsigned updateFlags, StringArray &filesNotFound, bool copyonly, bool stopifcopy)
    {
        if (!pTree)
            throw MakeStringExceptionDirect(PKG_INFO_NOT_DEFINED, "No PackageMap content provided");
        Linked<IPropertyTree> pmTree = pTree;
        if (pmExisting)
        {
            if (!checkFlag(PKGADD_MAP_REPLACE))
                throw MakeStringException(PKG_NAME_EXISTS, "PackageMap %s already exists, either delete it or specify overwrite", pmid.str());
        }

        if (pmTree->hasProp("Part"))
        {
            fixPackageMapFileIds(pmTree, checkFlag(PKGADD_PRELOAD_ALL));
            cloneDfsInfo(updateFlags, filesNotFound, pmTree);
        }
        else
        {
            createPart(partname, pmTree.getClear()); //this is a part, not a whole packagemap
            cloneDfsInfo(updateFlags, filesNotFound, pmPart);
        }

        if (copyonly || (stopifcopy && !publisherWuid.isEmpty()))
        {
            updateDfuPublisherState(false);
            return false;
        }
        if (!waitForDfuWorkunit())
            return false;
        if (pmExisting)
            packageMaps->removeTree(pmExisting);

        if (!pmTree)
        {
            //wrap part in full PackageMap
            pmTree.setown(createPTree("PackageMap", ipt_ordered));
            pmTree->setPropBool("@multipart", true);
            pmTree->addPropTree("Part", pmPart.getClear());
        }
        pmTree->setProp("@id", pmid);
        packageMaps->addPropTree("PackageMap", pmTree.getClear());

        VStringBuffer xpath("PackageMap[@id='%s'][@querySet='%s']", pmid.str(), target.get());
        Owned<IPropertyTree> pkgSet = getPkgSetRegistry(process, false);
        IPropertyTree *psEntry = pkgSet->queryPropTree(xpath);

        if (!psEntry)
        {
            psEntry = pkgSet->addPropTree("PackageMap", createPTree("PackageMap"));
            psEntry->setProp("@id", pmid);
            psEntry->setProp("@querySet", target);
        }
        makePackageActive(pkgSet, psEntry, target, checkFlag(PKGADD_MAP_ACTIVATE));
        return true;
    }
    bool doCreate(const char *partname, const char *xml, unsigned updateFlags, StringArray &filesNotFound, bool copyonly, bool stopifcopy)
    {
        Owned<IPropertyTree> pTree = createPTreeFromXMLString(xml, ipt_ordered);
        return doCreate(partname, pTree, updateFlags, filesNotFound, copyonly, stopifcopy);
    }
    bool create(const char *partname, const char *xml, unsigned updateFlags, StringArray &filesNotFound, bool copyonly, bool stopifcopy)
    {
        init();
        return doCreate(partname, xml, updateFlags, filesNotFound, copyonly, stopifcopy);
    }
    bool copy(IPropertyTree *pm, const char *name, unsigned updateFlags, StringArray &filesNotFound, bool copyonly, bool stopifcopy)
    {
        init();
        return doCreate(name, pm, updateFlags, filesNotFound, copyonly, stopifcopy);
    }
    bool copy(const char *srcAddress, const char *srcTarget, const char *name, unsigned updateFlags, StringArray &filesNotFound, bool copyonly, bool stopifcopy)
    {
        VStringBuffer url("http://%s/WsPackageProcess", (srcAddress && *srcAddress) ? srcAddress : ".:8010");
        Owned<IClientWsPackageProcess> client = createWsPackageProcessClient();
        StringBuffer user, pw;
        if (userdesc)
            client->setUsernameToken(userdesc->getUserName(user), userdesc->getPassword(pw), nullptr);
        client->addServiceUrl(url);

        StringBuffer scopedPMID;
        if (srcTarget && *srcTarget)
            scopedPMID.append(srcTarget).append("::");
        scopedPMID.append(name);
        Owned<IClientGetPackageMapByIdRequest> req = client->createGetPackageMapByIdRequest();
        req->rpc().setConnectTimeOutMs(HTTP_CLIENT_DEFAULT_CONNECT_TIMEOUT); //could make configurable, and consider changing read timeout,
                                                                             //but do so across all copy type methods under a stand alone JIRA

        req->setPackageMapId(scopedPMID);
        Owned<IClientGetPackageMapByIdResponse> resp = client->GetPackageMapById(req);
        if (resp->getExceptions().ordinality())
        {
            Owned<IMultiException> mE = makeMultiException("ESP");
            mE->append(const_cast<IMultiException&>(resp->getExceptions()));
            throw mE.getClear();
        }
        init();
        return doCreate(name, resp->getInfo(), updateFlags, filesNotFound, copyonly, stopifcopy);
    }
    bool addPart(const char *partname, const char *xml, unsigned updateFlags, StringArray &filesNotFound, bool copyonly, bool stopifcopy)
    {
        init();

        if (!pmExisting)
            return doCreate(partname, xml, updateFlags, filesNotFound, copyonly, stopifcopy);

        Owned<IPropertyTree> pTree = createPTreeFromXMLString(xml, ipt_ordered);
        createPart(partname, pTree.getClear());

        VStringBuffer xpath("Part[@id='%s']", partname);
        IPropertyTree *existingPart = pmExisting->queryPropTree(xpath);
        if (existingPart && !checkFlag(PKGADD_SEG_REPLACE))
            throw MakeStringException(PKG_NAME_EXISTS, "Package Part %s already exists, remove, or specify 'delete previous'", partname);

        cloneDfsInfo(updateFlags, filesNotFound);

        if (copyonly || (stopifcopy && !publisherWuid.isEmpty()))
        {
            updateDfuPublisherState(false);
            return false;
        }

        if (existingPart)
            pmExisting->removeTree(existingPart);

        pmExisting->addPropTree("Part", pmPart.getClear());
        return true;
    }
    IPropertyTree *ensurePart(const char *partname)
    {
        if (!pmExisting)
            throw MakeStringException(PKG_NAME_EXISTS, "PackageMap %s not found", pmid.str());

        VStringBuffer xpath("Part[@id='%s']", partname);
        IPropertyTree *existingPart = pmExisting->queryPropTree(xpath);
        if (!existingPart)
            throw MakeStringException(PKG_NAME_EXISTS, "PackageMap %s Part %s not found", pmid.str(), partname);
        return existingPart;
    }
    void removePart(const char *partname)
    {
        init();
        pmExisting->removeTree(ensurePart(partname));
    }
    StringBuffer &getPartContent(const char *partname, StringBuffer &content)
    {
        init();
        return toXML(ensurePart(partname), content);
    }
};


void getPackageListInfo(IPropertyTree *mapTree, IEspPackageListMapData *pkgList)
{
    pkgList->setId(mapTree->queryProp("@id"));
    pkgList->setTarget(mapTree->queryProp("@querySet"));

    Owned<IPropertyTreeIterator> iter = mapTree->getElements("Package");
    IArrayOf<IConstPackageListData> results;
    ForEach(*iter)
    {
        IPropertyTree &item = iter->query();

        Owned<IEspPackageListData> res = createPackageListData("", "");
        res->setId(item.queryProp("@id"));
        if (item.hasProp("@queries"))
            res->setQueries(item.queryProp("@queries"));
        results.append(*res.getClear());
    }
    pkgList->setPkgListData(results);
}
void getAllPackageListInfo(IPropertyTree *mapTree, StringBuffer &info)
{
    info.append("<PackageMap id='").append(mapTree->queryProp("@id")).append("'");

    Owned<IPropertyTreeIterator> iter = mapTree->getElements("Package");
    ForEach(*iter)
    {
        IPropertyTree &item = iter->query();
        info.append("<Package id='").append(item.queryProp("@id")).append("'");
        if (item.hasProp("@queries"))
            info.append(" queries='").append(item.queryProp("@queries")).append("'");
        info.append("></Package>");
    }
    info.append("</PackageMap>");
}

void listPkgInfo(double version, const char *target, const char *process, const IPropertyTree* packageMaps, IPropertyTree* pkgSetRegistry, IArrayOf<IConstPackageListMapData>* results)
{
    StringBuffer xpath("PackageMap");
    if (target && *target)
        xpath.appendf("[@querySet='%s']", target);
    Owned<IPropertyTreeIterator> iter = pkgSetRegistry->getElements(xpath.str());
    ForEach(*iter)
    {
        IPropertyTree &item = iter->query();
        const char *id = item.queryProp("@id");
        if (!id || !*id)
            continue;

        StringBuffer xpath;
        xpath.append("PackageMap[@id='").append(id).append("']");
        IPropertyTree *mapTree = packageMaps->queryPropTree(xpath);
        if (!mapTree)
            continue;

        Owned<IEspPackageListMapData> res = createPackageListMapData("", "");
        res->setActive(item.getPropBool("@active"));
        if (process && *process && (version >= 1.01))
            res->setProcess(process);
        getPackageListInfo(mapTree, res);
        res->setTarget(item.queryProp("@querySet"));
        results->append(*res.getClear());
    }
}

void listPkgInfo(double version, const char *target, const char *process, const IPropertyTree* packageMaps, IArrayOf<IConstPackageListMapData>* results)
{
    Owned<IPropertyTree> pkgSetRegistry = getPkgSetRegistry((process && *process) ? process : "*", true);
    if (pkgSetRegistry) //will be NULL if no package map
    {
        listPkgInfo(version, target, process, packageMaps, pkgSetRegistry, results);
    }
}

void getPkgInfo(const IPropertyTree *packageMaps, const char *target, const char *process, StringBuffer &info)
{
    Owned<IPropertyTree> tree = createPTree("PackageMaps");
    Owned<IPropertyTree> pkgSetRegistry = getPkgSetRegistry(process, true);
    if (!pkgSetRegistry)
    {
        toXML(tree, info);
        return;
    }
    StringBuffer xpath("PackageMap[@active='1']");
    if (target && *target)
        xpath.appendf("[@querySet='%s']", target);
    Owned<IPropertyTreeIterator> iter = pkgSetRegistry->getElements(xpath.str());
    ForEach(*iter)
    {
        IPropertyTree &item = iter->query();
        const char *id = item.queryProp("@id");
        if (id)
        {
            StringBuffer xpath;
            xpath.append("PackageMap[@id='").append(id).append("']");
            IPropertyTree *mapTree = packageMaps->queryPropTree(xpath);
            if (mapTree)
                mergePTree(tree, mapTree);
        }
    }

    toXML(tree, info);
}

bool deletePkgInfo(const char *name, const char *target, const char *process, bool globalScope)
{
    Owned<IRemoteConnection> pkgSetsConn = querySDS().connect("/PackageSets/", myProcessSession(), RTM_LOCK_WRITE, SDS_LOCK_TIMEOUT);
    if (!pkgSetsConn)
        throw MakeStringException(PKG_NONE_DEFINED, "No package sets defined");

    IPropertyTree* packageSets = pkgSetsConn->queryRoot();

    StringBuffer pkgSetId;
    buildPkgSetId(pkgSetId, process);
    VStringBuffer pkgSet_xpath("PackageSet[@id='%s']", pkgSetId.str());
    IPropertyTree *pkgSetRegistry = packageSets->queryPropTree(pkgSet_xpath.str());
    if (!pkgSetRegistry)
        throw MakeStringException(PKG_TARGET_NOT_DEFINED, "No package sets defined for %s", process);

    StringBuffer lcTarget(target);
    target = lcTarget.toLowerCase().str();

    StringBuffer lcName(name);
    name = lcName.toLowerCase().str();

    Owned<IPropertyTree> mapEntry;
    StringBuffer xpath;
    if (!globalScope)
    {
        xpath.appendf("PackageMap[@id='%s::%s'][@querySet='%s']", target, name, target);
        mapEntry.setown(pkgSetRegistry->getPropTree(xpath.str()));
    }
    if (!mapEntry)
    {
        xpath.clear().appendf("PackageMap[@id='%s'][@querySet='%s']", name, target);
        mapEntry.setown(pkgSetRegistry->getPropTree(xpath.str()));
        if (!mapEntry)
            throw MakeStringException(PKG_DELETE_NOT_FOUND, "Unable to delete %s - information not found", lcName.str());
    }
    StringAttr pmid(mapEntry->queryProp("@id"));
    pkgSetRegistry->removeTree(mapEntry);

    xpath.clear().appendf("PackageSet/PackageMap[@id='%s']", pmid.get());
    if (!packageSets->hasProp(xpath))
    {
        Owned<IRemoteConnection> pkgMapsConn = querySDS().connect("/PackageMaps/", myProcessSession(), RTM_LOCK_WRITE, SDS_LOCK_TIMEOUT);
        if (!pkgMapsConn)
            throw MakeStringException(PKG_DALI_LOOKUP_ERROR, "Unable to retrieve PackageMaps information from dali [/PackageMaps]");
        IPropertyTree *pkgMaps = pkgMapsConn->queryRoot();
        if (!pkgMaps)
            throw MakeStringException(PKG_DALI_LOOKUP_ERROR, "Unable to retrieve PackageMaps information from dali [/PackageMaps]");
        IPropertyTree *mapTree = pkgMaps->queryPropTree(xpath.clear().appendf("PackageMap[@id='%s']", pmid.get()).str());
        if (mapTree)
            pkgMaps->removeTree(mapTree);
    }
    return true;
}

void activatePackageMapInfo(const char *target, const char *name, const char *process, bool globalScope, bool activate)
{
    if (!target || !*target)
        throw MakeStringExceptionDirect(PKG_TARGET_NOT_DEFINED, "No target defined");

    if (!name || !*name)
        throw MakeStringExceptionDirect(PKG_MISSING_PARAM, "No pmid specified");

    Owned<IRemoteConnection> globalLock = querySDS().connect("PackageSets", myProcessSession(), RTM_LOCK_WRITE|RTM_CREATE_QUERY, SDS_LOCK_TIMEOUT);
    if (!globalLock)
        throw MakeStringException(PKG_DALI_LOOKUP_ERROR, "Unable to retrieve PackageSets information from dali /PackageSets");

    StringBuffer lcTarget(target);
    target = lcTarget.toLowerCase().str();

    StringBuffer lcName(name);
    name = lcName.toLowerCase().str();

    IPropertyTree *root = globalLock->queryRoot();
    if (!root)
        throw MakeStringException(PKG_ACTIVATE_NOT_FOUND, "Unable to retrieve PackageSet information");

    StringBuffer pkgSetId;
    buildPkgSetId(pkgSetId, process);
    VStringBuffer xpath("PackageSet[@id='%s']", pkgSetId.str());
    IPropertyTree *pkgSetTree = root->queryPropTree(xpath);
    if (pkgSetTree)
    {
        IPropertyTree *mapTree = NULL;
        if (!globalScope)
        {
            xpath.clear().appendf("PackageMap[@querySet='%s'][@id='%s::%s']", target, target, name);
            mapTree = pkgSetTree->queryPropTree(xpath);
        }
        if (!mapTree)
        {
            xpath.clear().appendf("PackageMap[@querySet='%s'][@id='%s']", target, name);
            mapTree = pkgSetTree->queryPropTree(xpath);
        }
        if (!mapTree)
            throw MakeStringException(PKG_ACTIVATE_NOT_FOUND, "PackageMap %s not found on target %s", name, target);
        makePackageActive(pkgSetTree, mapTree, target, activate);
    }
}

void PackageMapAndSet::load(const char* path, IPropertyTree* t)
{
    Owned<IRemoteConnection> globalLock = querySDS().connect(path, myProcessSession(), RTM_LOCK_READ, SDS_LOCK_TIMEOUT);
    if (!globalLock)
        throw MakeStringException(PKG_DALI_LOOKUP_ERROR, "Unable to retrieve %s information from dali /%s", path, path);

    t->removeProp(path);

    IPropertyTree *root = globalLock->queryRoot();
    if (root)
        t->addPropTree(path, createPTreeFromIPT(root));
}

void PackageMapAndSet::load(unsigned flags)
{
    Owned<IPropertyTree> t = createPTreeFromIPT(tree);
    if (flags & PMAS_RELOAD_PACKAGE_SET)
        load("PackageSets", t);
    if (flags & PMAS_RELOAD_PACKAGE_MAP)
        load("PackageMaps", t);
    tree.setown(t.getClear());
}

bool CWsPackageProcessEx::readPackageMapString(const char *packageMapString, StringBuffer &target, StringBuffer &process, StringBuffer &packageMap)
{
    if (!packageMapString || !*packageMapString)
        return false;

    StringArray plist;
    plist.appendListUniq(packageMapString, ",");
    if (plist.length() < 3)
        return false;

    target.set(plist.item(0));
    process.set(plist.item(1));
    packageMap.set(plist.item(2));
    if (!target.length() || !packageMap.length())
        return false;
    return true;
}

void CWsPackageProcessEx::getPkgInfoById(const char *target, const char *packageMapId, IPropertyTree* tree)
{
    if (!packageMapId || !*packageMapId)
        return;

    StringBuffer scopedPMID;
    if (target && *target)
        packageMapId = scopedPMID.append(target).append("::").append(packageMapId).str();

    Owned<IPropertyTree> packageMaps = packageMapAndSet.ensurePackageMaps();
    if (!packageMaps)
        throw MakeStringException(PKG_DALI_LOOKUP_ERROR, "Unable to retrieve information about package maps from dali server");

    StringBuffer lcPMID(packageMapId);
    packageMapId = lcPMID.toLowerCase().str();

    StringBuffer xpath;
    xpath.append("PackageMap[@id='").append(packageMapId).append("']");
    IPropertyTree *mapTree = packageMaps->queryPropTree(xpath);
    if (mapTree)
        mergePTree(tree, mapTree);
}

void CWsPackageProcessEx::getPkgInfoById(const char *packageMapId, IPropertyTree* tree)
{
    getPkgInfoById(nullptr, packageMapId, tree);
}

template<class TRequest>
static void setDfuOptions(PackageMapUpdater &updater, unsigned &updateFlags, TRequest &req)
{
    if (req.getDfuCopyFiles())
        updateFlags |= DFU_UPDATEF_COPY;
    if (req.getDfuOverwrite())
        updateFlags |= DFU_UPDATEF_OVERWRITE;
    updater.dfuQueue.set(req.getDfuQueue());
    updater.dfuWait = req.getDfuWait();
    updater.publisherWuid = req.getDfuPublisherWuid();
    updater.keyCompression.set(req.getKeyCompression());
}

bool CWsPackageProcessEx::onAddPackage(IEspContext &context, IEspAddPackageRequest &req, IEspAddPackageResponse &resp)
{
    PackageMapUpdater updater;
    updater.setFlag(PKGADD_MAP_CREATE);
    updater.setFlag(PKGADD_MAP_ACTIVATE, req.getActivate());
    updater.setFlag(PKGADD_MAP_REPLACE, req.getOverWrite());
    updater.setFlag(PKGADD_ALLOW_FOREIGN, req.getAllowForeignFiles());
    updater.setFlag(PKGADD_PRELOAD_ALL, req.getPreloadAllPackages());

    updater.setPMID(req.getTarget(), req.getPackageMap(), req.getGlobalScope());
    updater.setProcess(req.getProcess());
    updater.setUser(context.queryUserId(), context.queryPassword(), nullptr);

    unsigned updateFlags = 0;
    const char *remoteStr = req.getRemoteStorage();
    if (!isEmptyString(remoteStr))
        updateFlags = DFU_UPDATEF_REMOTESTORAGE;
    else
        remoteStr = req.getDaliIp();
    updater.setDerivedDfsLocation(remoteStr, req.getSourceProcess());

    if (req.getOverWrite())
        updateFlags |= (DALI_UPDATEF_PACKAGEMAP | DALI_UPDATEF_REPLACE_FILE | DALI_UPDATEF_CLONE_FROM | DALI_UPDATEF_SUPERFILES);
    if (req.getReplacePackageMap())
        updateFlags |= DALI_UPDATEF_PACKAGEMAP;
    if (req.getUpdateCloneFrom())
        updateFlags |= DALI_UPDATEF_CLONE_FROM;
    if (req.getUpdateSuperFiles())
        updateFlags |= DALI_UPDATEF_SUPERFILES;
    if (req.getAppendCluster())
        updateFlags |= DALI_UPDATEF_APPEND_CLUSTER;

    setDfuOptions(updater, updateFlags, req);

    StringArray filesNotFound;
    if (updater.create(req.getPackageMap(), req.getInfo(), updateFlags, filesNotFound, req.getOnlyCopyFiles(), req.getStopIfFilesCopied()))
    {
        resp.updateStatus().setCode(0);
        resp.updateStatus().setDescription(StringBuffer("Successfully loaded ").append(req.getPackageMap()));
    }
    resp.setFilesNotFound(filesNotFound);
    resp.setDfuPublisherWuid(updater.publisherWuid);
    resp.setDfuPublisherState(updater.publisherState);

    return true;
}

#define PACKAGEMAP_PATH_SEP_CHAR '/'

bool nextPmPathNode(const char *&path, StringBuffer &node)
{
    if (*path==PACKAGEMAP_PATH_SEP_CHAR)
        path++;
    while (*path && *path!=PACKAGEMAP_PATH_SEP_CHAR)
        node.append(*path++);
    return (*path && *++path);
}

bool splitPMPath(const char *path, StringBuffer &netAddress, StringBuffer &target, StringBuffer *pmid)
{
    if (!path || !*path)
        return false;
    if (*path==PACKAGEMAP_PATH_SEP_CHAR && path[1]==PACKAGEMAP_PATH_SEP_CHAR)
    {
        path+=2;
        if (!nextPmPathNode(path, netAddress))
            return false;
    }
    if (!nextPmPathNode(path, target))
        return (pmid==NULL);
    if (!pmid)
        return false;
    if (nextPmPathNode(path, *pmid))
        return false; //query path too deep
    return true;
}


bool CWsPackageProcessEx::onCopyPackageMap(IEspContext &context, IEspCopyPackageMapRequest &req, IEspCopyPackageMapResponse &resp)
{
    PackageMapUpdater updater;
    updater.setFlag(PKGADD_MAP_CREATE);
    updater.setFlag(PKGADD_MAP_ACTIVATE, req.getActivate());
    updater.setFlag(PKGADD_MAP_REPLACE, req.getReplacePackageMap());
    updater.setFlag(PKGADD_PRELOAD_ALL, req.getPreloadAllPackages());
    updater.setFlag(PKGADD_ALLOW_FOREIGN, true);

    updater.setProcess(req.getProcess());
    updater.setUser(context.queryUserId(), context.queryPassword(), &context);

    unsigned updateFlags = 0;
    const char *remoteStr = req.getRemoteStorage();
    if (!isEmptyString(remoteStr))
        updateFlags = DFU_UPDATEF_REMOTESTORAGE;
    else
        remoteStr = req.getDaliIp();
    updater.setDerivedDfsLocation(remoteStr, req.getSourceProcess());

    if (req.getReplacePackageMap())
        updateFlags |= DALI_UPDATEF_PACKAGEMAP;
    if (req.getUpdateCloneFrom())
        updateFlags |= DALI_UPDATEF_CLONE_FROM;
    if (req.getUpdateSuperFiles())
        updateFlags |= DALI_UPDATEF_SUPERFILES;
    if (req.getAppendCluster())
        updateFlags |= DALI_UPDATEF_APPEND_CLUSTER;

    setDfuOptions(updater, updateFlags, req);

    StringBuffer srcAddress, srcTarget, srcPMID;
    if (!splitPMPath(req.getSourcePath(), srcAddress, srcTarget, &srcPMID))
        throw MakeStringException(ECLWATCH_INVALID_INPUT, "Invalid source PackageMap path");

    const char *requestedPMID = req.getPMID();
    if (requestedPMID && *requestedPMID)
        updater.setPMID(req.getTarget(), requestedPMID, false);
    else
        updater.setPMID(req.getTarget(), srcPMID, false);

    bool loaded = false;
    StringArray filesNotFound;
    if (srcAddress && *srcAddress)
        loaded = updater.copy(srcAddress, srcTarget, srcPMID, updateFlags, filesNotFound, req.getOnlyCopyFiles(), req.getStopIfFilesCopied());
    else
    {
        Owned<IPropertyTree> tree = createPTree("PackageMaps");
        getPkgInfoById(srcTarget, srcPMID, tree);
        if (!tree->hasChildren())
            throw MakeStringException(ECLWATCH_INVALID_INPUT, "Source PackageMap not found");
        loaded = updater.copy(tree, srcPMID, updateFlags, filesNotFound, req.getOnlyCopyFiles(), req.getStopIfFilesCopied());
    }
    resp.setFilesNotFound(filesNotFound);
    resp.setDfuPublisherWuid(updater.publisherWuid);
    resp.setDfuPublisherState(updater.publisherState);
    if (loaded)
    {
        resp.updateStatus().setCode(0);
        resp.updateStatus().setDescription(StringBuffer("Successfully loaded ").append(srcPMID.str()));
    }
    return true;
}

void CWsPackageProcessEx::deletePackage(const char *packageMap, const char *target, const char *process, bool globalScope, StringBuffer &returnMsg, int &returnCode)
{
    bool ret = deletePkgInfo(packageMap, target, process, globalScope);
    (ret) ? returnMsg.append("Successfully ") : returnMsg.append("Unsuccessfully ");
    returnMsg.append("deleted ").append(packageMap).append(" from ").append(target).append(";");
    if (!ret)
        returnCode = -1;
    return;
}

bool CWsPackageProcessEx::onDeletePackage(IEspContext &context, IEspDeletePackageRequest &req, IEspDeletePackageResponse &resp)
{
    int returnCode = 0;
    StringBuffer returnMsg;
    IArrayOf<IConstPackageMapEntry>& packageMaps = req.getPackageMaps();
    ForEachItemIn(p, packageMaps)
    {
        IConstPackageMapEntry& item=packageMaps.item(p);
        if (!item.getId() || !*item.getId())
        {
            returnMsg.appendf("PackageMap[%d]: Package map Id not specified; ", p);
            continue;
        }
        if (!item.getTarget() || !*item.getTarget())
        {
            returnMsg.appendf("PackageMap[%d]: Target not specified;", p);
            continue;
        }

        StringBuffer target, processName, packageMap;
        packageMap.set(item.getId());
        target.set(item.getTarget());
        if (!item.getProcess() || !*item.getProcess())
            processName.set("*");
        else
            processName.set(item.getProcess());

        deletePackage(packageMap.str(), target.str(), processName.str(), req.getGlobalScope(), returnMsg, returnCode);
    }

    if (!packageMaps.length())
    {
        StringAttr pkgMap(req.getPackageMap());
        StringAttr processName(req.getProcess());
        if (!processName.length())
            processName.set("*");
        deletePackage(pkgMap.get(), req.getTarget(), processName.get(), req.getGlobalScope(), returnMsg, returnCode);
    }

    resp.updateStatus().setDescription(returnMsg.str());
    resp.updateStatus().setCode(returnCode);
    return true;
}

bool CWsPackageProcessEx::onActivatePackage(IEspContext &context, IEspActivatePackageRequest &req, IEspActivatePackageResponse &resp)
{
    resp.updateStatus().setCode(0);
    activatePackageMapInfo(req.getTarget(), req.getPackageMap(), req.getProcess(), req.getGlobalScope(), true);
    return true;
}

bool CWsPackageProcessEx::onDeActivatePackage(IEspContext &context, IEspDeActivatePackageRequest &req, IEspDeActivatePackageResponse &resp)
{
    resp.updateStatus().setCode(0);
    activatePackageMapInfo(req.getTarget(), req.getPackageMap(), req.getProcess(), req.getGlobalScope(), false);
    return true;
}

bool CWsPackageProcessEx::onListPackage(IEspContext &context, IEspListPackageRequest &req, IEspListPackageResponse &resp)
{
    Owned<IPropertyTree> packageMaps = packageMapAndSet.ensurePackageMaps();
    if (!packageMaps)
        throw MakeStringException(PKG_DALI_LOOKUP_ERROR, "Unable to retrieve information about package maps from dali server");

    resp.updateStatus().setCode(0);
    IArrayOf<IConstPackageListMapData> results;
    StringAttr process(req.getProcess());
    listPkgInfo(context.getClientVersion(), req.getTarget(), process.length() ? process.get() : "*", packageMaps, &results);
    resp.setPkgListMapData(results);
    return true;
}

bool CWsPackageProcessEx::onListPackages(IEspContext &context, IEspListPackagesRequest &req, IEspListPackagesResponse &resp)
{
    Owned<IPropertyTree> packageMaps = packageMapAndSet.ensurePackageMaps();
    if (!packageMaps)
        throw MakeStringException(PKG_DALI_LOOKUP_ERROR, "Unable to retrieve information about package maps from dali server");

    double version = context.getClientVersion();
    const char* targetReq = req.getTarget();
    const char* processReq = req.getProcess();
    const char* processFilterReq = req.getProcessFilter();
    IArrayOf<IConstPackageListMapData> results;
    if ((!processReq || !*processReq) && (processFilterReq && *processFilterReq))
        listPkgInfo(version, targetReq, processFilterReq, packageMaps, &results);
    else
    {
        Owned<IPropertyTree> pkgSetRegistryRoot = packageMapAndSet.ensurePackageSets();
        if (!pkgSetRegistryRoot)
            throw MakeStringException(PKG_DALI_LOOKUP_ERROR, "Unable to retrieve information about package sets from dali server");
        Owned<IPropertyTreeIterator> iter = pkgSetRegistryRoot->getElements("PackageSet");
        ForEach(*iter)
        {
            try
            {
                Owned<IPropertyTree> pkgSetRegistry= &iter->get();
                StringBuffer process;
                pkgSetRegistry->getProp("@process", process);
                if (!process.isEmpty() && (isEmptyString(processReq) || streq(process.str(), "*") || WildMatch(process.str(), processReq, true)))
                    listPkgInfo(version, targetReq, process.str(), packageMaps, pkgSetRegistry, &results);
            }
            catch(IException* e)
            {
                int err = e->errorCode();
                //Dali throws an exception if packagemap is not available for a process.
                if (err == PKG_DALI_LOOKUP_ERROR)
                    e->Release();
                else
                    throw e;
            }
        }
        if ((version >=1.01) && processReq && *processReq)
        {//Show warning if multiple packages are active for the same target.
            ForEachItemIn(i, results)
            {
                IEspPackageListMapData& r1 = (IEspPackageListMapData&) results.item(i);
                if (!r1.getActive())
                    continue;
                const char* target1 = r1.getTarget();
                for (unsigned ii = i+1; ii<results.length(); ++ii)
                {
                    IEspPackageListMapData& r2 = (IEspPackageListMapData&) results.item(ii);
                    if (!r2.getActive())
                        continue;
                    if (!streq(target1, r2.getTarget()))
                        continue;
                    StringBuffer warning;
                    warning.appendf("Error: package %s is also active.", r1.getId());
                    r2.setDescription(warning.str());
                }
            }
        }
    }
    resp.setPackageMapList(results);
    resp.updateStatus().setCode(0);
    return true;
}

bool CWsPackageProcessEx::onGetPackage(IEspContext &context, IEspGetPackageRequest &req, IEspGetPackageResponse &resp)
{
    Owned<IPropertyTree> packageMaps = packageMapAndSet.ensurePackageMaps();
    if (!packageMaps)
        throw MakeStringException(PKG_DALI_LOOKUP_ERROR, "Unable to retrieve information about package maps from dali server");

    resp.updateStatus().setCode(0);
    StringAttr process(req.getProcess());
    StringBuffer info;
    getPkgInfo(packageMaps, req.getTarget(), process.length() ? process.get() : "*", info);
    resp.setInfo(info);
    return true;
}

bool CWsPackageProcessEx::onGetPackageMapById(IEspContext &context, IEspGetPackageMapByIdRequest &req, IEspGetPackageMapByIdResponse &resp)
{
    try
    {
        const char* pkgMapId = req.getPackageMapId();
        if (!pkgMapId && !*pkgMapId)
            throw MakeStringException(PKG_MISSING_PARAM, "PackageMap Id not specified");

        StringBuffer info;
        Owned<IPropertyTree> tree = createPTree("PackageMaps");
        getPkgInfoById(pkgMapId, tree);
        toXML(tree, info);
        resp.setInfo(info.str());
        resp.updateStatus().setCode(0);
    }
    catch (IException *e)
    {
        StringBuffer retMsg;
        resp.updateStatus().setDescription(e->errorMessage(retMsg).str());
        resp.updateStatus().setCode(-1);
    }

    return true;
}

bool CWsPackageProcessEx::onValidatePackage(IEspContext &context, IEspValidatePackageRequest &req, IEspValidatePackageResponse &resp)
{
    try
    {
        const char *target = req.getTarget();
        if (isEmptyString(target))
            throw MakeStringException(PKG_TARGET_NOT_DEFINED, "Target cluster required");

        Owned<IPropertyTree> packageMapTree;
        const char *pmID = req.getPMID();
        const char *packageMapString = req.getInfo();
        if (!req.getActive() && isEmptyString(pmID))
        {
            if (isEmptyString(packageMapString))
                throw makeStringException(ECLWATCH_INVALID_INPUT, "Please specify PMID or Package Map content");

            packageMapTree.setown(createPTreeFromXMLString(packageMapString));
            if (!packageMapTree)
                throw makeStringException(PKG_LOAD_PACKAGEMAP_FAILED, "Error processing package file content");
            fixPackageMapFileIds(packageMapTree, false);
        }

        StringArray &queriesToIgnore = req.getQueriesToIgnore();
        StringArray &queriesToVerify = req.getQueriesToVerify();
        const char *queryid = req.getQueryIdToVerify();
        if (!isEmptyString(queryid))
            queriesToVerify.appendUniq(queryid);

        double version = context.getClientVersion();
        IArrayOf<IEspValidateResult> results;
        if (!streq(target, "*"))
        {
            Owned<IConstWUClusterInfo> clusterInfo = getWUClusterInfoByName(target);
            if (!clusterInfo)
                throw makeStringException(PKG_TARGET_NOT_DEFINED, "Target cluster not found");
            validatePackage(context, req, packageMapTree, clusterInfo, queriesToVerify, queriesToIgnore,
                (version < 1.04) ? &resp : nullptr, results);
        }
        else
        {
            CConstWUClusterInfoArray clusters;
            getWUClusterInfo(clusters);
            ForEachItemIn(i, clusters)
            {
                IConstWUClusterInfo &cluster = clusters.item(i);
                if (cluster.getPlatform() == RoxieCluster)
                {
                    validatePackage(context, req, packageMapTree, &cluster, queriesToVerify, queriesToIgnore,
                        (version < 1.04) ? &resp : nullptr, results);
                    if (version < 1.04)
                        break;
                }
            }
        }
        if (version >= 1.04)
            resp.setResults(results);
    }
    catch(IException *e)
    {
        FORWARDEXCEPTION(context, e, ECLWATCH_INTERNAL_ERROR);
    }
    return true;
}

void CWsPackageProcessEx::validatePackage(IEspContext &context, IEspValidatePackageRequest &req, IPropertyTree *packageMapTree,
    IConstWUClusterInfo *clusterInfo, StringArray &queriesToVerify, StringArray &queriesToIgnore,
    IEspValidatePackageResponse *resp, IArrayOf<IEspValidateResult>& results)
{
    SCMStringBuffer process;
    clusterInfo->getRoxieProcess(process);
    if (!process.length())
        throw makeStringException(PKG_TARGET_NOT_DEFINED, "Roxie process not found");

    SCMStringBuffer clusterName;
    clusterInfo->getName(clusterName);
    const char *target = clusterName.str();
    const char* pmID = req.getPMID();

    Owned<IPropertyTree> mapTree;
    if (req.getActive()) //validate active map
    {
        mapTree.setown(resolveActivePackageMap(process.str(), target, true));
        if (!mapTree)
            throw makeStringException(PKG_PACKAGEMAP_NOT_FOUND, "Active package map not found");
    }
    else if (!isEmptyString(pmID))
    {
        mapTree.setown(getPackageMapById(req.getGlobalScope() ? nullptr : target, pmID, true));
        if (!mapTree)
            throw makeStringExceptionV(PKG_PACKAGEMAP_NOT_FOUND, "Package map %s not found", pmID);
    }
    else if (packageMapTree)
    {
        mapTree.setown(LINK(packageMapTree));
    }

    StringArray notInDFS;
    if (req.getCheckDFS())
    {
        Owned<IReferencedFileList> pmfiles = createReferencedFileList(context.queryUserId(), context.queryPassword(), true, false);
        pmfiles->addFilesFromPackageMap(mapTree);
        StringArray locations;
        locations.append(process.str());
        pmfiles->resolveFiles(locations, nullptr, nullptr, nullptr, true, false, false, false, false);
        Owned<IReferencedFileIterator> files = pmfiles->getFiles();
        ForEach(*files)
        {
            IReferencedFile &file = files->query();
            if (file.getFlags() & RefFileNotFound)
                notInDFS.append(file.getLogicalName());
        }
    }

    const char *id = mapTree->queryProp("@id");
    Owned<IHpccPackageMap> map = createPackageMapFromPtree(mapTree, target, id);
    if (!map)
        throw makeStringExceptionV(PKG_LOAD_PACKAGEMAP_FAILED, "Error loading package map %s", id);

    StringArray warnings, errors, unmatchedQueries, unusedPackages, unmatchedFiles;
    map->validate(queriesToVerify, queriesToIgnore, warnings, errors, unmatchedQueries, unusedPackages, unmatchedFiles, req.getIgnoreOptionalFiles());

    if (resp)
    {
        resp->setPMID(map->queryPackageId());
        if (!req.getIgnoreWarnings())
            resp->setWarnings(warnings);
        resp->setErrors(errors);
        resp->updateQueries().setUnmatched(unmatchedQueries);
        resp->updatePackages().setUnmatched(unusedPackages);
        resp->updateFiles().setUnmatched(unmatchedFiles);
        resp->updateStatus().setCode(0);
        if (notInDFS.length())
            resp->updateFiles().setNotInDFS(notInDFS);
        return;
    }

    Owned<IEspValidateResult> result = createValidateResult();
    result->setTarget(target);
    result->setPMID(map->queryPackageId());
    if (!req.getIgnoreWarnings())
        result->setWarnings(warnings);
    result->setErrors(errors);
    result->updateQueries().setUnmatched(unmatchedQueries);
    result->updatePackages().setUnmatched(unusedPackages);
    result->updateFiles().setUnmatched(unmatchedFiles);
    if (notInDFS.length())
        result->updateFiles().setNotInDFS(notInDFS);
    results.append(*result.getClear());
}

bool CWsPackageProcessEx::onGetPackageMapSelectOptions(IEspContext &context, IEspGetPackageMapSelectOptionsRequest &req, IEspGetPackageMapSelectOptionsResponse &resp)
{
    try
    {
        bool includeTargets = req.getIncludeTargets();
        bool includeProcesses = req.getIncludeProcesses();
        if (includeTargets || includeProcesses)
        {
            IArrayOf<IConstTargetData> targets;
            CConstWUClusterInfoArray clusters;
            getWUClusterInfo(clusters);
            ForEachItemIn(c, clusters)
            {
                IConstWUClusterInfo &cluster = clusters.item(c);
                if ((cluster.getPlatform() == RoxieCluster) && cluster.canPublishQueries())
                {
                    SCMStringBuffer str;
                    Owned<IEspTargetData> target = createTargetData();
                    target->setName(cluster.getName(str).str());
                    target->setType(ROXIECLUSTER);
                    if (includeProcesses)
                    {
                        SCMStringBuffer process;
                        cluster.getRoxieProcess(process);
                        if (process.length())
                        {
                            StringArray processes;
                            processes.append(process.str());
                            target->setProcesses(processes);
                        }
                    }
                    targets.append(*target.getClear());
                }
            }
            resp.setTargets(targets);
        }
        if (req.getIncludeProcessFilters())
        {
            StringArray processFilters;
            processFilters.append("*");
            Owned<IPropertyTree> pkgSets = packageMapAndSet.ensurePackageSets();
            if (pkgSets)
            {
                Owned<IPropertyTreeIterator> iter = pkgSets->getElements("PackageSet");
                ForEach(*iter)
                {
                    StringBuffer process;
                    iter->query().getProp("@process", process);
                    if (process.length() && !processFilters.contains(process.str()))
                        processFilters.append(process.str());
                }
            }
            resp.setProcessFilters(processFilters);
        }
        resp.updateStatus().setCode(0);
    }
    catch (IException *e)
    {
        StringBuffer retMsg;
        resp.updateStatus().setDescription(e->errorMessage(retMsg).str());
        resp.updateStatus().setCode(-1);
    }

    return true;
}

bool CWsPackageProcessEx::onGetQueryFileMapping(IEspContext &context, IEspGetQueryFileMappingRequest &req, IEspGetQueryFileMappingResponse &resp)
{
    const char *queryname = req.getQueryName();
    if (!queryname || !*queryname)
        throw MakeStringException(PKG_INVALID_QUERY_NAME, "Query name required");
    const char *target = req.getTarget();
    if (!target || !*target)
        throw MakeStringException(PKG_TARGET_NOT_DEFINED, "Target cluster required");

    Owned<IConstWUClusterInfo> clusterInfo = getWUClusterInfoByName(target);
    if (!clusterInfo)
        throw MakeStringException(PKG_TARGET_NOT_DEFINED, "Unable to find target cluster");
    if (clusterInfo->getPlatform()!=RoxieCluster)
        throw MakeStringException(PKG_INVALID_CLUSTER_TYPE, "Roxie target required");

    Owned<IHpccPackageSet> set;
    Owned<IHpccPackageMap> ownedmap;
    const IHpccPackageMap *map = NULL;

    const char *pmid = req.getPMID();
    if (pmid && *pmid)
    {
        Owned<IPropertyTree> pm = getPackageMapById(req.getGlobalScope() ? NULL : target, pmid, true);
        ownedmap.setown(createPackageMapFromPtree(pm, target, pmid));
        if (!ownedmap)
            throw MakeStringException(PKG_LOAD_PACKAGEMAP_FAILED, "Error loading package map %s", req.getPMID());
        map = ownedmap;
    }
    else
    {
        SCMStringBuffer process;
        clusterInfo->getRoxieProcess(process);
        set.setown(createPackageSet(process.str()));
        if (!set)
            throw MakeStringException(PKG_CREATE_PACKAGESET_FAILED, "Unable to create PackageSet");
        map = set->queryActiveMap(target);
        if (!map)
            throw MakeStringException(PKG_PACKAGEMAP_NOT_FOUND, "Active package map not found");
    }
    Owned<IPropertyTree> fileInfo = createPTree();
    map->gatherFileMappingForQuery(queryname, fileInfo);

    StringArray unmappedFiles;
    Owned<IPropertyTreeIterator> it = fileInfo->getElements("File");
    ForEach(*it)
        unmappedFiles.append(it->query().queryProp(NULL));
    resp.setUnmappedFiles(unmappedFiles);

    IArrayOf<IEspSuperFile> superArray;
    it.setown(fileInfo->getElements("SuperFile"));
    ForEach(*it)
    {
        IPropertyTree &superTree = it->query();
        Owned<IEspSuperFile> superItem = createSuperFile();
        superItem->setName(superTree.queryProp("@name"));
        StringArray subArray;
        Owned<IPropertyTreeIterator> subfiles = superTree.getElements("SubFile");
        ForEach(*subfiles)
            subArray.append(subfiles->query().queryProp(NULL));
        superItem->setSubFiles(subArray);
        superArray.append(*superItem.getClear());
    }

    resp.setSuperFiles(superArray);
    return true;
}

bool CWsPackageProcessEx::onAddPartToPackageMap(IEspContext &context, IEspAddPartToPackageMapRequest &req, IEspAddPartToPackageMapResponse &resp)
{
    PackageMapUpdater updater;
    updater.setFlag(PKGADD_SEG_ADD);
    updater.setFlag(PKGADD_SEG_REPLACE, req.getDeletePrevious());
    updater.setFlag(PKGADD_ALLOW_FOREIGN, req.getAllowForeignFiles());
    updater.setFlag(PKGADD_PRELOAD_ALL, req.getPreloadAllPackages());

    updater.setPMID(req.getTarget(), req.getPackageMap(), req.getGlobalScope());
    updater.setProcess(req.getProcess());
    updater.setUser(context.queryUserId(), context.queryPassword(), nullptr);

    unsigned updateFlags = 0;
    const char *remoteStr = req.getRemoteStorage();
    if (!isEmptyString(remoteStr))
        updateFlags = DFU_UPDATEF_REMOTESTORAGE;
    else
        remoteStr = req.getDaliIp();
    updater.setDerivedDfsLocation(remoteStr, req.getSourceProcess());


    if (req.getDeletePrevious())
        updateFlags |= DALI_UPDATEF_PACKAGEMAP;
    if (req.getUpdateCloneFrom())
        updateFlags |= DALI_UPDATEF_CLONE_FROM;
    if (req.getUpdateSuperFiles())
        updateFlags |= DALI_UPDATEF_SUPERFILES;
    if (req.getAppendCluster())
        updateFlags |= DALI_UPDATEF_APPEND_CLUSTER;

    setDfuOptions(updater, updateFlags, req);

    StringArray filesNotFound;
    if (updater.addPart(req.getPartName(), req.getContent(), updateFlags, filesNotFound, req.getOnlyCopyFiles(), req.getStopIfFilesCopied()))
    {
        resp.updateStatus().setCode(0);
        resp.updateStatus().setDescription(VStringBuffer("Successfully loaded Part %s to PackageMap %s", req.getPartName(), updater.pmid.str()));
    }
    resp.setFilesNotFound(filesNotFound);
    resp.setDfuPublisherWuid(updater.publisherWuid);
    resp.setDfuPublisherState(updater.publisherState);
    return true;
}

bool CWsPackageProcessEx::onGetPartFromPackageMap(IEspContext &context, IEspGetPartFromPackageMapRequest &req, IEspGetPartFromPackageMapResponse &resp)
{
    PackageMapUpdater updater;
    updater.setPMID(req.getTarget(), req.getPackageMap(), req.getGlobalScope());

    StringBuffer content;
    resp.setContent(updater.getPartContent(req.getPartName(), content));
    return true;
}

bool CWsPackageProcessEx::onRemovePartFromPackageMap(IEspContext &context, IEspRemovePartFromPackageMapRequest &req, IEspRemovePartFromPackageMapResponse &resp)
{
    PackageMapUpdater updater;
    updater.setPMID(req.getTarget(), req.getPackageMap(), req.getGlobalScope());
    updater.removePart(req.getPartName());

    resp.updateStatus().setCode(0);
    resp.updateStatus().setDescription(VStringBuffer("Successfully removed Part %s from PackageMap %s", req.getPartName(), updater.pmid.str()));
    return true;
}

int CWsPackageProcessSoapBindingEx::onFinishUpload(IEspContext &ctx, CHttpRequest* request, CHttpResponse* response,
    const char *service, const char *method, StringArray& fileNames, StringArray& files, IMultiException *meIn)
{
    if (meIn && (meIn->ordinality() > 0))
    {
        StringBuffer msg;
        IWARNLOG("Exception(s) in EspHttpBinding::onFinishUpload - %s", meIn->errorMessage(msg).append('\n').str());
        if ((ctx.getResponseFormat() == ESPSerializationXML) || (ctx.getResponseFormat() == ESPSerializationJSON))
        {
            response->handleExceptions(NULL, meIn, "FileSpray", "UploadFile", NULL, false);
            return 0;
        }
        else
            return EspHttpBinding::onFinishUpload(ctx, request, response, service, method, fileNames, files, meIn);
    }

    StringBuffer respStr;
    Owned<IEspWsPackageProcess> iserv = (IEspWsPackageProcess*)getService();
    if(iserv == NULL)
    {
        IWARNLOG("Exception(s) in %s::%s - Service not available", service, method);
	    respStr.append("{\"Code\":-1,\"Exception\":\"Service not available\"}");
    }
    else
    {
        checkRequest(ctx);
        Owned<CAddPackageRequest> esp_request = new CAddPackageRequest(&ctx, "WsPackageProcess", request->queryParameters(), request->queryAttachments());
        Owned<CAddPackageResponse> esp_response = new CAddPackageResponse("WsPackageProcess");
        StringBuffer source;
        source.setf("WsPackageProcess::%s()", method);
        Owned<IMultiException> me = MakeMultiException(source.str());
        try
        {
            if (!files.length())
                throw MakeStringExceptionDirect(PKG_INFO_NOT_DEFINED, "Package content not found");

            esp_request->setInfo(files.item(0));
            iserv->onAddPackage(ctx, *esp_request.get(), *esp_response.get());
        }
        catch (IMultiException* mex)
        {
	        me->append(*mex);
	        mex->Release();
        }
        catch (IException* e)
        {
	        me->append(*e);
        }
        catch (...)
        {
	        me->append(*MakeStringExceptionDirect(-1, "Unknown Exception"));
        }

        if (!me->ordinality())
        {
            respStr.append("{\"Code\":0,\"Description\":\"Package Map added\"}");
        }
        else
        {
            StringBuffer msg;
            IWARNLOG("Exception(s) in %s::%s - %s", service, method, me->errorMessage(msg).str());
            respStr.appendf("{\"Code\":-1,\"Exception\":\"%s\"}", msg.str());
        }
    }

    response->setContent(respStr.str());
    response->setContentType(HTTP_TYPE_JSON);
    response->send();
    return 0;
}
