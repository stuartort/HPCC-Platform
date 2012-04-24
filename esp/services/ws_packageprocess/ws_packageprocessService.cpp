/*##############################################################################
Copyright (C) 2011 HPCC Systems.
############################################################################## */

#pragma warning (disable : 4786)

#include "ws_packageprocessService.hpp"
#include "daclient.hpp"
#include "dalienv.hpp"
#include "dadfs.hpp"
#include "dfuutil.hpp"
#include "ws_fs.hpp"
#include "ws_workunits.hpp"

#define SDS_LOCK_TIMEOUT (5*60*1000) // 5mins, 30s a bit short

void CWsPackageProcessEx::init(IPropertyTree *cfg, const char *process, const char *service)
{
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

IPropertyTree *getPkgSetRegistry(const char *setName, bool readonly)
{
    Owned<IRemoteConnection> globalLock = querySDS().connect("/PackageSets/", myProcessSession(), RTM_LOCK_WRITE|RTM_CREATE_QUERY, SDS_LOCK_TIMEOUT);

    //Only lock the branch for the target we're interested in.
    StringBuffer xpath;
    xpath.append("/PackageSets/PackageSet[@id=\"").append(setName).append("\"]");
    Owned<IRemoteConnection> conn = querySDS().connect(xpath.str(), myProcessSession(), readonly ? RTM_LOCK_READ : RTM_LOCK_WRITE, SDS_LOCK_TIMEOUT);
    if (!conn)
    {
        if (readonly)
            return NULL;
        Owned<IPropertyTree> querySet = createPTree();
        querySet->setProp("@id", setName);
        globalLock->queryRoot()->addPropTree("PackageSet", querySet.getClear());
        globalLock->commit();

        conn.setown(querySDS().connect(xpath.str(), myProcessSession(), RTM_LOCK_WRITE, SDS_LOCK_TIMEOUT));
        if (!conn)
            throwUnexpected();
    }

    return conn->getRoot();
}

IPropertyTree *getQuerySetRegistry(const char *setName, bool readonly)
{
    Owned<IRemoteConnection> globalLock = querySDS().connect("/QuerySets/", myProcessSession(), RTM_LOCK_WRITE|RTM_CREATE_QUERY, SDS_LOCK_TIMEOUT);

    //Only lock the branch for the target we're interested in.
    StringBuffer xpath;
    xpath.append("/QuerySets/QuerySet[@id=\"").append(setName).append("\"]");
    Owned<IRemoteConnection> conn = querySDS().connect(xpath.str(), myProcessSession(), readonly ? RTM_LOCK_READ : RTM_LOCK_WRITE, SDS_LOCK_TIMEOUT);
    if (!conn)
    {
        if (readonly)
            return NULL;
        Owned<IPropertyTree> querySet = createPTree();
        querySet->setProp("@id", setName);
        globalLock->queryRoot()->addPropTree("QuerySet", querySet.getClear());
        globalLock->commit();

        conn.setown(querySDS().connect(xpath.str(), myProcessSession(), RTM_LOCK_WRITE, SDS_LOCK_TIMEOUT));
        if (!conn)
            throwUnexpected();
    }

    return conn->getRoot();
}

////////////////////////////////////////////////////////////////////////////////////////
const unsigned roxieQueryRoxieTimeOut = 60000;

#define SDS_LOCK_TIMEOUT (5*60*1000) // 5mins, 30s a bit short

bool isRoxieProcess(const char *process)
{
    if (!process)
        return false;
    Owned<IRemoteConnection> conn = querySDS().connect("Environment", myProcessSession(), RTM_LOCK_READ, SDS_LOCK_TIMEOUT);
    if (!conn)
        return false;
    VStringBuffer xpath("Software/RoxieCluster[@name=\"%s\"]", process);
    return conn->queryRoot()->hasProp(xpath.str());
}

bool isFileKnownOnCluster(const char *logicalname, const char *lookupDaliIp, const char *process, IUserDescriptor* userdesc)
{
    Owned<IDistributedFile> dst = queryDistributedFileDirectory().lookup(logicalname, userdesc, true);
    if (dst)
    {
        if (dst->findCluster(process) != NotFound)
            return true; // file already known for this cluster
    }
    return false;
}

bool addFileInfoToDali(const char *logicalname, const char *lookupDaliIp, const char *process, bool overwrite, IUserDescriptor* userdesc, StringBuffer &host, short port, StringBuffer &msg)
{
    bool retval = true;
    try
    {
        if (!overwrite)
        {
            if (isFileKnownOnCluster(logicalname, lookupDaliIp, process, userdesc))
                return true;
        }

        StringBuffer user;
        userdesc->getUserName(user);

        StringBuffer password;
        userdesc->getPassword(password);

        Owned<IClientFileSpray> fs;
        fs.setown(createFileSprayClient());
        fs->setUsernameToken(user.str(), password.str(), NULL);

        VStringBuffer url("http://%s:%d/FileSpray", host.str(), port);
        fs->addServiceUrl(url.str());

        bool isRoxie = isRoxieProcess(process);

        Owned<IClientCopy> req = fs->createCopyRequest();
        req->setSourceLogicalName(logicalname);
        req->setDestLogicalName(logicalname);
        req->setDestGroup(process);
        req->setSuperCopy(false);
        if (isRoxie)
            req->setDestGroupRoxie("Yes");

        req->setSourceDali(lookupDaliIp);

        req->setSrcusername(user);
        req->setSrcpassword(password);
        req->setOverwrite(overwrite);

        Owned<IClientCopyResponse> resp = fs->Copy(req);
    }
    catch(IException *e)
    {
        e->errorMessage(msg);
        DBGLOG("ERROR = %s", msg.str());
        e->Release();  // report the error later if needed
        retval = false;
    }
    catch(...)
    {
        retval = false;
    }

    return retval;
}
//////////////////////////////////////////////////////////

void addPackageMapInfo(IPropertyTree *pkgSetRegistry, const char *setName, const char *packageSetName, IPropertyTree *packageInfo, bool active, bool overWrite)
{
    Owned<IRemoteConnection> globalLock = querySDS().connect("/PackageMaps/", myProcessSession(), RTM_LOCK_WRITE|RTM_CREATE_QUERY, SDS_LOCK_TIMEOUT);

    StringBuffer lcName(packageSetName);
    lcName.toLowerCase();
    StringBuffer xpath;
    xpath.append("PackageMap[@id='").append(lcName).append("']");

    IPropertyTree *pkgRegTree = pkgSetRegistry->queryPropTree(xpath.str());

    IPropertyTree *root = globalLock->queryRoot();
    IPropertyTree *mapTree = root->queryPropTree(xpath);

    if (!overWrite && (pkgRegTree || mapTree))
    {
        throw MakeStringException(0, "Package name %s already exists, either delete it or specify overwrite", lcName.str());
    }

    if (mapTree)
        root->removeTree(mapTree);

    if (pkgRegTree)
        pkgSetRegistry->removeTree(pkgRegTree);


    mapTree = root->addPropTree("PackageMap", createPTree());
    mapTree->addProp("@id", packageSetName);

    IPropertyTree *baseInfo = createPTree();
    Owned<IPropertyTreeIterator> iter = packageInfo->getElements("Package");
    ForEach(*iter)
    {
        IPropertyTree &item = iter->query();
        Owned<IPropertyTreeIterator> super_iter = item.getElements("SuperFile");
        if (super_iter->first())
        {
            ForEach(*super_iter)
            {
                IPropertyTree &supertree = super_iter->query();
                StringAttr id(supertree.queryProp("@id"));
                if (id.length() && id[0] == '~')
                    supertree.setProp("@id", id+1);

                Owned<IPropertyTreeIterator> sub_iter = supertree.getElements("SubFile");
                ForEach(*sub_iter)
                {
                    IPropertyTree &subtree = sub_iter->query();
                    StringAttr subid = subtree.queryProp("@value");
                    if (subid.length())
                    {
                        if (subid[0] == '~')
                            subtree.setProp("@value", subid+1);
                    }
                }
                mapTree->addPropTree("Package", LINK(&item));
            }
        }
        else
        {
            baseInfo->addPropTree("Package", LINK(&item));
        }
    }

    mergePTree(mapTree, baseInfo);
    globalLock->commit();

    IPropertyTree *pkgSetTree = pkgSetRegistry->addPropTree("PackageMap", createPTree("PackageMap"));
    pkgSetTree->setProp("@id", lcName);
    pkgSetTree->setProp("@querySet", setName);
    pkgSetTree->setPropBool("@active", active);
}

void copyPackageSubFiles(IPropertyTree *packageInfo, const char *process, const char *defaultLookupDaliIp, bool overwrite, IUserDescriptor* userdesc, StringBuffer &host, short port)
{
    Owned<IPropertyTreeIterator> iter = packageInfo->getElements("Package");
    ForEach(*iter)
    {
        IPropertyTree &item = iter->query();
        StringBuffer lookupDaliIp;
        lookupDaliIp.append(item.queryProp("@daliip"));
        if (lookupDaliIp.length() == 0)
            lookupDaliIp.append(defaultLookupDaliIp);
        if (lookupDaliIp.length() == 0)
        {
            StringAttr superfile(item.queryProp("@id"));
            DBGLOG("Could not lookup SubFiles in package %s because no remote dali ip was specified", superfile.get());
            return;
        }
        Owned<IPropertyTreeIterator> super_iter = item.getElements("SuperFile");
        ForEach(*super_iter)
        {
            IPropertyTree &supertree = super_iter->query();
            Owned<IPropertyTreeIterator> sub_iter = supertree.getElements("SubFile");
            ForEach(*sub_iter)
            {
                IPropertyTree &subtree = sub_iter->query();
                StringAttr subid = subtree.queryProp("@value");
                if (subid.length())
                {
                    StringBuffer msg;
                    addFileInfoToDali(subid.get(), lookupDaliIp, process, overwrite, userdesc, host, port, msg);
                }
            }
        }
    }
}


void validateDataPackageInfo(IPropertyTree *control, IPropertyTree *dataPackages, StringAttrMapping &packageList, StringBuffer &reply)
{
	bool displayAllInfo = control->getPropBool("@displayAllInfo", false);

	Owned<IPropertyTreeIterator> packages = control->getElements("Package");

	ForEach (*packages)  // check each package 'id' for uniqueness
	{
		IPropertyTree &pkg = packages->query();
		if (pkg.hasProp("SuperFile"))   // only care about data packages - SuperFile contents can be empty
		{
			StringBuffer pkgname(pkg.queryProp("@id"));
			if (packageList.find(pkgname) == 0)
			{
				packageList.setValue(pkgname, pkgname);
				dataPackages->addPropTree(pkgname, LINK(&pkg));
				StringAttrMapping fileList(false);

				// need to know if any SubFile exists for each SuperFile
				Owned<IPropertyTreeIterator> super_items = pkg.getElements("SuperFile");
				ForEach(*super_items)
				{
					Owned<IPropertyTreeIterator> items = super_items->query().getElements("SubFile");

					bool foundSubFile = false;
					ForEach (*items)
					{
						foundSubFile = true;
						StringBuffer name(items->query().queryProp("@value"));
						if (fileList.find(name) == 0)
						{
							fileList.setValue(name, name);
							// need to lookup file in dali
							//bool exists = farmerManager->isFileInfoLoaded(name);
							bool exists = true;
							if (!exists)
							{
								StringBuffer err;
								err.appendf("ERROR: Missing File %s in package %s", name.str(), pkgname.str());

								reply.appendf("<Error id='%s' value='MissingFile'/>\n", name.str());
								reply.appendf("<Exception><Source>PackageValidation</Source><Message>%s</Message></Exception>", err.str());

								DBGLOG("did NOT find %s", name.str());
							}
							else if (displayAllInfo)  // file exists and we want to know it...
								DBGLOG("found %s", name.str());
						}
						else
						{
							StringBuffer err;
							err.appendf("ERROR: Duplicate File %s in package %s", name.str(), pkgname.str());
							reply.appendf("<Exception><Source>PackageValidation</Source><Message>%s</Message></Exception>", err.str());
							DBGLOG("file %s not unique in package %s", name.str(), pkgname.str());
						}
					}

					if (!foundSubFile)
					{
						StringBuffer name(super_items->query().queryProp("@id"));
						StringBuffer err;
						err.appendf("WARNING: SuperFile %s has no SubFiles defined", name.str());
						reply.appendf("<Exception><Source>PackageValidation</Source><Message>%s</Message></Exception>", err.str());

						DBGLOG("%s", err.str());
					}

				}
			}
			else
			{
				StringBuffer err;
				err.appendf("Duplicate PackageFile %s", pkgname.str());

				reply.appendf("<Error id='%s' value='Duplicate PackageFile '/>", pkgname.str());
				reply.appendf("<Exception><Source>PackageValidation</Source><Message>%s</Message></Exception>", err.str());

				DBGLOG("package name %s is NOT unique", pkgname.str());
			}
		}
		else if (pkg.hasProp("Environment"))
		{
			StringBuffer pkgname(pkg.queryProp("@id"));
			bool hasBaseId = (pkg.hasProp("Base"));
			if ( (packageList.find(pkgname) == 0) || (hasBaseId))
			{
				if (!hasBaseId)
					packageList.setValue(pkgname, pkgname);

				// package defining Superfiles - check...
				// unique subfile names within a package
				// make sure that roxie knows about the subfile name
				Owned<IPropertyTreeIterator> items = pkg.getElements("Environment");

				dataPackages->addPropTree(pkgname, LINK(&pkg));
				StringAttrMapping fileList(false);

				ForEach (*items)
				{
					StringBuffer name(items->query().queryProp("@id"));
					StringBuffer val(items->query().queryProp("@val"));
					if (fileList.find(name) == 0)
					{
						fileList.setValue(name, name);
						if (val.length() == 0)
						{
							StringBuffer err;
							err.appendf("WARNING: Environment variable id = %s has no value specified", name.str());
							reply.appendf("<Exception><Source>PackageValidation</Source><Message>%s</Message></Exception>", err.str());
							DBGLOG(err.str());
						}
					}
					else
					{
						StringBuffer err;
						err.appendf("ERROR: Duplicate environment variable %s in package %s", name.str(), pkgname.str());
						reply.appendf("<Exception><Source>PackageValidation</Source><Message>%s</Message></Exception>", err.str());

						DBGLOG("file %s not unique in package %s", name.str(), pkgname.str());
					}
				}
			}
			else
			{
				StringBuffer err;
				err.appendf("Duplicate PackageFile %s", pkgname.str());

				reply.appendf("<Error id='%s' value='Duplicate PackageFile '/>\n", pkgname.str());
				reply.appendf("<Exception><Source>PackageValidation</Source><Message>%s</Message></Exception>", err.str());
				//reply.appendf("<Error id='%s' value='Duplicate PackageFile %s'/>\n", pkgname.str(), pkgname.str());
				DBGLOG("package name %s is NOT unique", pkgname.str());
			}
		}
	}
}

void validateQueryPackageInfo(IPropertyTree *control, IPropertyTree *dataPackages, StringAttrMapping &packageList, StringAttr &querySet, StringBuffer &reply)
{
	bool displayAllInfo = control->getPropBool("@displayAllInfo", false);

	Owned<IPropertyTreeIterator> packages = control->getElements("Package");
	Owned<IPropertyTree> querySetRegistry = getQuerySetRegistry(querySet, false);

	ForEach (*packages)  // check each package 'id' for uniqueness
	{
		IPropertyTree &pkg = packages->query();

		if (pkg.hasProp("Base"))  // only care about query packages
		{
			StringBuffer pkgname(pkg.queryProp("@id"));
			if (packageList.find(pkgname) == 0)
			{
				packageList.setValue(pkgname, pkgname);

				StringAttrMapping queryFileNames(false);

				bool compulsory = false;
				Owned<IAttributeIterator> attrs = pkg.getAttributes();
				for(attrs->first(); attrs->isValid(); attrs->next())
				{
					const char *name = attrs->queryName();
					if (stricmp(name, "@compulsory") == 0)
					{
						const char *value = attrs->queryValue();
						if (value && *value)
							compulsory = strToBool(value);
					}
				}

				bool found = false;
				if (querySetRegistry)
				{
					VStringBuffer xpath("Query[@id='%s']", pkgname.str());
					if (querySetRegistry->hasProp(xpath.str()))
						found = true;
				}
				if (!found)
				{
					StringBuffer err;
					err.appendf("Query : %s not found in roxie's list of queries", pkgname.str());
					reply.appendf("<Exception><Source>PackageValidation</Source><Message>%s</Message></Exception>", err.str());

					DBGLOG("%s", err.str());
					continue;
				}

				if (compulsory)
				{
#ifdef NOTNOW
						IPropertyTree *fileTree = factory->queryFileTree();
						if (fileTree) // should always exist - be just being careful
						{
							Owned<IPropertyTreeIterator> superkeys = fileTree->getElements("SuperKey");
							ForEach (*superkeys)
							{
								IPropertyTree &superkey = superkeys->query();
								StringBuffer superName = superkey.queryProp("@id");
	//							superName.toLowerCase();
								queryFileNames.setValue(superName.str(), superName.str());
							}

							Owned<IPropertyTreeIterator> superfiles = fileTree->getElements("SuperFile");
							ForEach (*superfiles)
							{
								IPropertyTree &superfile = superfiles->query();
								StringBuffer superName = superfile.queryProp("@id");
	//							superName.toLowerCase();
								queryFileNames.setValue(superName.str(), superName.str());
							}
						}
						else
						{
							DBGLOG("no file info found for %s", pkgname.str());
						}
#endif
				}

				// walk the base ids, see if it exists as a package name in the information passed in
				// and also check for duplicate entries
				Owned<IPropertyTreeIterator> items = pkg.getElements("Base");
				StringAttrMapping fileList(false);
				ForEach (*items)
				{
					StringBuffer name(items->query().queryProp("@id"));
					if (fileList.find(name) == 0)
					{
						fileList.setValue(name, name);

						IPropertyTree *dataPackage = dataPackages->queryPropTree(name.str());
						if (!dataPackage)
						{
							StringBuffer err;
							err.appendf("WARNING: Package %s refers to undefined package %s", pkgname.str(), name.str());

							reply.appendf("<Exception><Source>PackageValidation</Source><Message>%s</Message></Exception>", err.str());
							DBGLOG("did NOT find %s", name.str());
						}
						else
						{
							if (displayAllInfo)  // file exists and we want to know it...
								DBGLOG("found %s", name.str());

							if (compulsory)
							{
								// walk the contents of data package and look remove name from queryFileName list
								Owned<IPropertyTreeIterator> pkgfiles = dataPackage->getElements("SuperFile");
								ForEach(*pkgfiles)
								{
									StringBuffer pkgfile(pkgfiles->query().queryProp("@id"));
									//pkgfile.toLowerCase();
									queryFileNames.remove(pkgfile.str());  // don't care if it doesn't find it
								}
							}
						}
					}
					else
					{
						StringBuffer err;
						err.appendf("ERROR: Duplicate Base Id %s in package %s", name.str(), pkgname.str());

						reply.appendf("<Exception><Source>PackageValidation</Source><Message>%s</Message></Exception>", err.str());
						DBGLOG("file %s not unique in package %s", name.str(), pkgname.str());
					}
				}

				HashIterator queryFileNames_iter(queryFileNames);
				StringBuffer err;
				for (queryFileNames_iter.first(); queryFileNames_iter.isValid(); queryFileNames_iter.next())
				{
					if (err.length() == 0)
						err.appendf("Error QUERY : %s  could not find compulsory DATASET(S) :", pkgname.str());
					else
						err.append(",");

					err.appendf(" %s", (const char *)queryFileNames_iter.query().getKey());
				}
				if (err.length())
				{
					reply.appendf("<Error id='%s' value='Compulsory files not found'/>\n", pkgname.str());
					reply.appendf("<Exception><Source>PackageValidation</Source><Message>%s</Message></Exception>", err.str());
					DBGLOG("%s", err.str());
				}
			}
			else
			{
				StringBuffer err;
				err.appendf("Duplicate PackageFile %s", pkgname.str());

				reply.appendf("<Error id='%s' value='Duplicate PackageFile '/>\n", pkgname.str());
				reply.appendf("<Exception><Source>PackageValidation</Source><Message>%s</Message></Exception>", err.str());
				DBGLOG("package name %s is NOT unique", pkgname.str());
			}
		}
	}
}


void validatePackageInfo(IPropertyTree *packageInfo, StringAttr &querySet, StringBuffer &reply)
{

	StringAttrMapping packageList(false);
	Owned <IPropertyTree> dataPackages = createPTree("Data", false);
	validateDataPackageInfo(packageInfo, dataPackages, packageList, reply);
	validateQueryPackageInfo(packageInfo, dataPackages, packageList, querySet, reply);
}

void getPackageListInfo(IPropertyTree *mapTree, IEspPackageListMapData *pkgList)
{
    pkgList->setId(mapTree->queryProp("@id"));

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
void listPkgInfo(const char *cluster, IArrayOf<IConstPackageListMapData>* results)
{
    StringBuffer info;
    Owned<IRemoteConnection> globalLock = querySDS().connect("/PackageMaps/", myProcessSession(), RTM_LOCK_WRITE|RTM_CREATE_QUERY, SDS_LOCK_TIMEOUT);
    if (!globalLock)
        return;
    IPropertyTree *root = globalLock->queryRoot();
    if (!cluster || !*cluster)
    {
        info.append("<PackageMaps>");
        Owned<IPropertyTreeIterator> iter = root->getElements("PackageMap");
        ForEach(*iter)
        {
            Owned<IEspPackageListMapData> res = createPackageListMapData("", "");
            IPropertyTree &item = iter->query();
            getPackageListInfo(&item, res);
            results->append(*res.getClear());
        }
        info.append("</PackageMaps>");
    }
    else
    {
        Owned<IPropertyTree> pkgSetRegistry = getPkgSetRegistry(cluster, true);
        Owned<IPropertyTreeIterator> iter = pkgSetRegistry->getElements("PackageMap");
        info.append("<PackageMaps>");
        ForEach(*iter)
        {
            IPropertyTree &item = iter->query();
            const char *id = item.queryProp("@id");
            if (id)
            {
                StringBuffer xpath;
                xpath.append("PackageMap[@id='").append(id).append("']");
                IPropertyTree *mapTree = root->queryPropTree(xpath);
                Owned<IEspPackageListMapData> res = createPackageListMapData("", "");
                getPackageListInfo(mapTree, res);
                results->append(*res.getClear());
            }
        }
        info.append("</PackageMaps>");
    }
}
void getPkgInfo(const char *cluster, const char *package, StringBuffer &info)
{
    Owned<IRemoteConnection> globalLock = querySDS().connect("/PackageMaps/", myProcessSession(), RTM_LOCK_WRITE|RTM_CREATE_QUERY, SDS_LOCK_TIMEOUT);
    if (!globalLock)
        return;
    IPropertyTree *root = globalLock->queryRoot();
    Owned<IPropertyTree> tree = createPTree("PackageMaps");
    if (cluster)
    {
        Owned<IPropertyTree> pkgSetRegistry = getPkgSetRegistry(cluster, true);
        Owned<IPropertyTreeIterator> iter = pkgSetRegistry->getElements("PackageMap[@active='1']");
        ForEach(*iter)
        {
            IPropertyTree &item = iter->query();
            const char *id = item.queryProp("@id");
            if (id)
            {
                StringBuffer xpath;
                xpath.append("PackageMap[@id='").append(id).append("']");
                IPropertyTree *mapTree = root->queryPropTree(xpath);
                if (mapTree)
                    mergePTree(tree, mapTree);
            }
        }
    }
    else
    {
        StringBuffer xpath;
        xpath.append("PackageMap[@id='").append(package).append("']");
        Owned<IPropertyTreeIterator> iter = root->getElements(xpath.str());
        ForEach(*iter)
        {
            IPropertyTree &item = iter->query();
            mergePTree(tree, &item);
        }
    }
    toXML(tree, info);
}

bool deletePkgInfo(const char *packageSetName, const char *queryset)
{
    Owned<IPropertyTree> pkgSetRegistry = getPkgSetRegistry(queryset, false);
    Owned<IRemoteConnection> globalLock = querySDS().connect("/PackageMaps/", myProcessSession(), RTM_LOCK_WRITE|RTM_CREATE_QUERY, SDS_LOCK_TIMEOUT);

    StringBuffer lcName(packageSetName);
    lcName.toLowerCase();
    StringBuffer xpath;
    xpath.append("PackageMap[@id='").append(lcName).append("']");

    bool ret = true;
    IPropertyTree *root = globalLock->queryRoot();
    IPropertyTree *mapTree = root->queryPropTree(xpath);
    if (mapTree)
        ret = root->removeTree(mapTree);

    if (ret)
    {
        IPropertyTree *pkgTree = pkgSetRegistry->queryPropTree(xpath.str());
        if (pkgTree)
            ret = pkgSetRegistry->removeTree(pkgTree);
    }
    return ret;
}

void activatePackageMapInfo(const char *packageSetName, const char *packageMap, bool activate)
{
    if (!packageSetName || !*packageSetName)
        return;

    Owned<IRemoteConnection> globalLock = querySDS().connect("PackageSets", myProcessSession(), RTM_LOCK_WRITE|RTM_CREATE_QUERY, SDS_LOCK_TIMEOUT);
    if (!globalLock)
        return;

    StringBuffer lcName(packageSetName);
    lcName.toLowerCase();
    VStringBuffer xpath("PackageSet[@id=\"%s\"]", lcName.str());

    IPropertyTree *root = globalLock->queryRoot();
    if (!root)
        return;

    IPropertyTree *pkgSetTree = root->queryPropTree(xpath);
    if (pkgSetTree)
    {
        if (packageMap && *packageMap)
        {
            StringBuffer lcMapName(packageMap);
            lcMapName.toLowerCase();
            VStringBuffer xpath_map("PackageMap[@id=\"%s\"]", lcMapName.str());
            IPropertyTree *mapTree = pkgSetTree->queryPropTree(xpath_map);
            mapTree->setPropBool("@active", activate);
        }
        else
        {
            Owned<IPropertyTreeIterator> iter = pkgSetTree->getElements("PackageMap");
            ForEach(*iter)
            {
                IPropertyTree &item = iter->query();
                item.setPropBool("@active", activate);
            }
        }
    }
}

bool CWsPackageProcessEx::onAddPackage(IEspContext &context, IEspAddPackageRequest &req, IEspAddPackageResponse &resp)
{
    resp.updateStatus().setCode(0);
    StringBuffer info(req.getInfo());
    bool activate = req.getActivate();
    bool overWrite = req.getOverWrite();
    StringAttr querySet(req.getQuerySet());
    StringAttr pkgName(req.getPackageName());

    Owned<IPropertyTree> packageTree = createPTreeFromXMLString(info.str());
    Owned<IPropertyTree> pkgSetRegistry = getPkgSetRegistry(querySet.get(), false);
    addPackageMapInfo(pkgSetRegistry, querySet.get(), pkgName.get(), LINK(packageTree), activate, overWrite);

    StringBuffer msg;
    msg.append("Successfully loaded ").append(pkgName.get());
    resp.updateStatus().setDescription(msg.str());
    return true;
}

bool CWsPackageProcessEx::onDeletePackage(IEspContext &context, IEspDeletePackageRequest &req, IEspDeletePackageResponse &resp)
{
    resp.updateStatus().setCode(0);
    StringAttr pkgName(req.getPackageName());
    bool ret = deletePkgInfo(pkgName.get(), req.getQuerySet());
    StringBuffer msg;
    (ret) ? msg.append("Successfully ") : msg.append("Unsuccessfully ");
    msg.append("deleted").append(pkgName.get());

    resp.updateStatus().setDescription(msg.str());
    return true;
}

bool CWsPackageProcessEx::onActivatePackage(IEspContext &context, IEspActivatePackageRequest &req, IEspActivatePackageResponse &resp)
{
    resp.updateStatus().setCode(0);
    StringBuffer pkgName(req.getPackageName());
    StringBuffer pkgMapName(req.getPackageMapName());

    activatePackageMapInfo(pkgName.str(), pkgMapName.str(), true);
    return true;
}

bool CWsPackageProcessEx::onDeActivatePackage(IEspContext &context, IEspDeActivatePackageRequest &req, IEspDeActivatePackageResponse &resp)
{
    resp.updateStatus().setCode(0);
    StringBuffer pkgName(req.getPackageName());
    StringBuffer pkgMapName(req.getPackageMapName());

    activatePackageMapInfo(pkgName.str(), pkgMapName.str(), false);
    return true;
}

bool CWsPackageProcessEx::onListPackage(IEspContext &context, IEspListPackageRequest &req, IEspListPackageResponse &resp)
{
    resp.updateStatus().setCode(0);
    IArrayOf<IConstPackageListMapData> results;
    listPkgInfo(req.getCluster(), &results);
    resp.setPkgListMapData(results);
    return true;
}

bool CWsPackageProcessEx::onGetPackage(IEspContext &context, IEspGetPackageRequest &req, IEspGetPackageResponse &resp)
{
    resp.updateStatus().setCode(0);
    StringAttr cluster(req.getCluster());
    StringAttr pkgName(req.getPackageName());
    StringBuffer info;
    getPkgInfo(cluster.length() ? cluster.get() : NULL, pkgName.length() ? pkgName.get() : NULL, info);
    resp.setInfo(info);
    return true;
}

bool CWsPackageProcessEx::onCopyFiles(IEspContext &context, IEspCopyFilesRequest &req, IEspCopyFilesResponse &resp)
{
    resp.updateStatus().setCode(0);
    StringBuffer info(req.getInfo());
    StringAttr process(req.getProcess());
    StringAttr pkgName(req.getPackageName());
    StringAttr lookupDaliIp(req.getDaliIp());

    if (process.length() == 0)
        throw MakeStringException(0, "CWsPackageProcessEx::onCopyFiles process parameter not set.");

    Owned<IUserDescriptor> userdesc;
    const char *user = context.queryUserId();
    const char *password = context.queryPassword();
    if (user && *user && *password && *password)
    {
        userdesc.setown(createUserDescriptor());
        userdesc->set(user, password);
    }

    StringBuffer host;
    short port;
    context.getServAddress(host, port);

    Owned<IPropertyTree> packageTree = createPTreeFromXMLString(info.str());
    copyPackageSubFiles(LINK(packageTree), process, lookupDaliIp, req.getOverWrite(), userdesc, host, port);

    StringBuffer msg;
    msg.append("Successfully loaded ").append(pkgName.get());
    resp.updateStatus().setDescription(msg.str());
    return true;
}

bool CWsPackageProcessEx::onValidatePackage(IEspContext &context, IEspValidatePackageRequest &req, IEspValidatePackageResponse &resp)
{
    resp.updateStatus().setCode(0);
    StringBuffer info(req.getInfo());
    StringAttr pkgName(req.getPackageName());

    StringAttr querySet(req.getQuerySet());
    Owned<IPropertyTree> packageTree = createPTreeFromXMLString(info.str());
    StringBuffer reply;
    validatePackageInfo(LINK(packageTree), querySet, reply);

    VStringBuffer msg("Validation of package %s complete", pkgName.get());
    if (reply.length())
    {
    	msg.appendf(" %s", reply.str());
    }
    resp.updateStatus().setDescription(msg.str());
    return true;
}
