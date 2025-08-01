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
#include <stdio.h>
#include "jcomp.hpp"
#include "jfile.hpp"
#include "jlzw.hpp"
#include "jqueue.tpp"
#include "jargv.hpp"
#include "junicode.hpp"

#include "workunit.hpp"
#include "thorplugin.hpp"
#ifndef _WIN32
#include <pwd.h>
#endif

#include "portlist.h"
#include "dadfs.hpp"
#include "dasess.hpp"
#include "daclient.hpp"
#include "mpcomm.hpp"
#include "hqlecl.hpp"
#include "hqlir.hpp"
#include "hqlerrors.hpp"
#include "hqlwuerr.hpp"
#include "hqlfold.hpp"
#include "hqlplugins.hpp"
#include "hqlmanifest.hpp"
#include "hqlcollect.hpp"
#include "hqlrepository.hpp"
#include "hqlerror.hpp"
#include "hqlcerrors.hpp"

#include "hqlgram.hpp"
#include "hqltrans.ipp"
#include "hqlutil.hpp"
#include "hqlstmt.hpp"
#include "hqlcache.hpp"

#include "rmtfile.hpp"
#include "deffield.hpp"

#include "reservedwords.hpp"
#include "eclcc.hpp"
#include "codesigner.hpp"

#ifndef _CONTAINERIZED
#include "environment.hpp"
#endif

#ifdef _USE_CPPUNIT
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#endif

#ifdef _USE_ZLIB
#include "zcrypt.hpp"
#endif

#include "ws_dfsclient.hpp"

//#define TEST_LEGACY_DEPENDENCY_CODE

#define INIFILE "eclcc.ini"
#define DEFAULTINIFILE "eclcc.ini"
#define DEFAULT_OUTPUTNAME  "a.out"

//=========================================================================================

//The following flag is used to speed up closedown by not freeing items
static bool optReleaseAllMemory = false;
static Owned<IPropertyTree> configuration;

#include <signal.h>

#if defined(_WIN32)

#if defined(_DEBUG)
static HANDLE leakHandle;
static void appendLeaks(size32_t len, const void * data)
{
    SetFilePointer(leakHandle, 0, 0, FILE_END);
    DWORD written;
    WriteFile(leakHandle, data, len, &written, 0);
}

void initLeakCheck(const char * title)
{
    StringBuffer leakFilename("eclccleaks.log");
    leakHandle = CreateFile(leakFilename.str(), GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, 0);
    if (title)
        appendLeaks(strlen(title), title);

    _CrtSetReportMode( _CRT_WARN, _CRTDBG_MODE_FILE|_CRTDBG_MODE_DEBUG );
    _CrtSetReportFile( _CRT_WARN, leakHandle );
    _CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_FILE|_CRTDBG_MODE_DEBUG );
    _CrtSetReportFile( _CRT_ERROR, leakHandle );
    _CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_FILE|_CRTDBG_MODE_DEBUG );
    _CrtSetReportFile( _CRT_ASSERT, leakHandle );

//
//  set the states we want to monitor
//
    int LeakTmpFlag = _CrtSetDbgFlag( _CRTDBG_REPORT_FLAG );
    LeakTmpFlag    &= ~_CRTDBG_CHECK_CRT_DF;
    LeakTmpFlag    |= _CRTDBG_LEAK_CHECK_DF;
    _CrtSetDbgFlag(LeakTmpFlag);
}

/**
 * Error handler for ctrl-break:  Don't care about memory leaks.
 */
void __cdecl IntHandler(int)
{
    enableMemLeakChecking(false);
    exit(2);
}

static void installSignalHandlers()
{
    signal(SIGINT, IntHandler);
}

#else

void initLeakCheck(const char *)
{
}

static void installSignalHandlers()
{
}

#endif

static void restoreSignalHandlers()
{
}

#else

//If eclcc is terminated while a git fetch operation is in process then there are situations where orphaned
//lock files are left in the directory.  To avoid this, prevent termination until the git fetch is complete.
static std::atomic<unsigned> terminateRequests = 0;
static void sighandler(int signum, siginfo_t *info, void *extra)
{
    if (!checkAbortGitFetch() && (++terminateRequests < 2))
    {
        //Delaying termination while fetching from git.  Terminate 2 times (or use kill -9) to force closure.
        //Cannot output any logging here because that is not a safe function to call from an interupt handler
    }
    else
    {
        enableMemLeakChecking(false);
        _exit(2);
    }
}

static void installSignalHandlers()
{
    struct sigaction act;
    act.sa_sigaction = &sighandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO; // set so sa_sigaction field is used
    sigaction(SIGTERM, &act, nullptr);
    sigaction(SIGINT, &act, nullptr);
}

static void restoreSignalHandlers()
{
    struct sigaction act;
    act.sa_handler = SIG_DFL;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;       // sa_handler field is used
    sigaction(SIGTERM, &act, nullptr);
    sigaction(SIGINT, &act, nullptr);
}

void initLeakCheck(const char *)
{
}

#endif // _WIN32 && _DEBUG

static bool extractOption(StringBuffer & option, IProperties * globals, const char * envName, const char * propertyName, const char * defaultPrefix, const char * defaultSuffix)
{
    if (option.length())        // check if already specified via a command line option
        return true;
    if (globals->getProp(propertyName, option))
        return true;
    const char * env = getenv(envName);
    if (env)
    {
        option.append(env);
        return true;
    }
    option.append(defaultPrefix).append(defaultSuffix);
    return false;
}

#ifndef _CONTAINERIZED
static bool extractOption(StringAttr & option, IProperties * globals, const char * envName, const char * propertyName, const char * defaultPrefix, const char * defaultSuffix)
{
    if (option)
        return true;
    StringBuffer temp;
    bool ret = extractOption(temp, globals, envName, propertyName, defaultPrefix, defaultSuffix);
    option.set(temp.str());
    return ret;
}
#endif

static bool getHomeFolder(StringBuffer & homepath)
{
    if (!getHomeDir(homepath))
        return false;
    addPathSepChar(homepath);
#ifndef WIN32
    homepath.append('.');
#endif
    homepath.append(hpccBuildInfo.dirName);
    return true;
}

class EclCC;
struct EclCompileInstance : public CInterfaceOf<ICodegenContextCallback>
{
public:
    EclCompileInstance(EclCC & _eclcc, IFile * _inputFile, IErrorReceiver & _errorProcessor, FILE * _errout, const char * _outputFilename, bool _legacyImport, bool _legacyWhen, bool _ignoreSignatures, bool _optIgnoreUnknownImport, bool _optXml) :
      eclcc(_eclcc), inputFile(_inputFile), outputFilename(_outputFilename), errout(_errout),
      legacyImport(_legacyImport), legacyWhen(_legacyWhen), ignoreUnknownImport(_optIgnoreUnknownImport), ignoreSignatures(_ignoreSignatures), optXml(_optXml), errorProcessor(&_errorProcessor)
{
        stats.parseTime = 0;
        stats.generateTime = 0;
        stats.xmlSize = 0;
        stats.cppSize = 0;
    }

    void logStats(bool logTimings);
    bool reportErrorSummary();
    inline IErrorReceiver & queryErrorProcessor() { return *errorProcessor; }

// interface ICodegenContextCallback
    virtual void noteCluster(const char *clusterName) override;
    virtual void pushCluster(const char *clusterName) override;
    virtual void popCluster() override;
    virtual bool allowAccess(const char * category, bool isSigned) override;
    virtual IHqlExpression *lookupDFSlayout(const char *filename, IErrorReceiver &errs, const ECLlocation &location, bool isOpt) const override;
    virtual unsigned lookupClusterSize() const override;
    virtual void getTargetPlatform(StringBuffer & result) override;
    virtual IInterface * getGitUpdateLock(const char * key) override;


public:
    EclCC & eclcc;
    Linked<IFile> inputFile;
    Linked<IPropertyTree> archive;
    Linked<IWorkUnit> wu;
    Owned<IEclPackage> dataServer;  // A member which can be cleared after parsing the query
    OwnedHqlExpr query;  // parsed query - cleared when generating to free memory
    StringAttr eclVersion;
    const char * outputFilename;
    FILE * errout;
    Owned<IPropertyTree> srcArchive;
    Owned<IPropertyTree> generatedMeta;
    Owned<IPropertyTree> globalDependTree;
    StringAttr metaOutputFilename;
    bool legacyImport;
    bool legacyWhen;
    bool fromArchive = false;
    bool ignoreUnknownImport = false;
    bool ignoreSignatures = false;
    bool optXml = false;
    struct {
        unsigned parseTime;
        unsigned generateTime;
        offset_t xmlSize;
        offset_t cppSize;
    } stats;

protected:
    Linked<IErrorReceiver> errorProcessor;
};

class EclCC final : implements CUnsharedInterfaceOf<ICodegenContextCallback>
{
public:
    EclCC(int _argc, const char **_argv)
        : repositoryManager(this), programName(_argv[0])
    {
        argc = _argc;
        argv = _argv;
        cclogFilename.append("cc.").append((unsigned)GetCurrentProcessId()).append(".log");
        defaultAllowed[false] = true;  // May want to change that?
        defaultAllowed[true] = true;
#ifdef _CONTAINERIZED
        setSecurityOptions();
#endif
        const char * defaultGitPrefix = getenv("ECLCC_DEFAULT_GITPREFIX");
        if (isEmptyString(defaultGitPrefix))
            defaultGitPrefix = "https://github.com/";
        optDefaultGitPrefix.set(defaultGitPrefix);
        const char * gitUser = getenv("HPCC_GIT_USERNAME");
        if (!isEmptyString(gitUser))
            optGitUser.set(gitUser);
    }
    ~EclCC()
    {
        if (daliConnected)
        {
            try
            {
                ::closedownClientProcess();
            }
            catch (...)
            {
            }
        }
    }
    bool printKeywordsToXml();
    int parseCommandLineOptions(int argc, const char* argv[]);
    void setSecurityOptions();
    void loadOptions();
    void loadManifestOptions();
    bool processFiles();
    void processBatchedFile(IFile & file, bool multiThreaded);

    // interface ICodegenContextCallback

    virtual void noteCluster(const char *clusterName) override;
    virtual void pushCluster(const char *clusterName) override;
    virtual void popCluster() override;
    virtual bool allowAccess(const char * category, bool isSigned) override;
    virtual IHqlExpression *lookupDFSlayout(const char *filename, IErrorReceiver &errs, const ECLlocation &location, bool isOpt) const override;
    virtual unsigned lookupClusterSize() const override;
    virtual void getTargetPlatform(StringBuffer & result) override;
    virtual IInterface * getGitUpdateLock(const char * key) override;

protected:
    void appendNeverSimplifyList(const char *attribsList);
    bool checkDaliConnected() const;
    void addFilenameDependency(StringBuffer & target, EclCompileInstance & instance, const char * filename);
    void applyApplicationOptions(IWorkUnit * wu);
    void applyDebugOptions(IWorkUnit * wu);
    bool checkWithinRepository(StringBuffer & attributePath, const char * sourcePathname);
    IFileIO * createArchiveOutputFile(EclCompileInstance & instance);
    ICppCompiler *createCompiler(const char * coreName, const char * sourceDir, const char * targetDir, CompilerType targetCompiler, const char *compileBatchOut);
    void evaluateResult(EclCompileInstance & instance);
    bool generatePrecompiledHeader();
    void generateOutput(EclCompileInstance & instance);
    void instantECL(EclCompileInstance & instance, IWorkUnit *wu, const char * queryFullName, IErrorReceiver & errorProcessor, const char * outputFile);
    bool isWithinPath(const char * sourcePathname, const char * searchPath);
    void getComplexity(IWorkUnit *wu, IHqlExpression * query, IErrorReceiver & errorProcessor);
    void outputXmlToOutputFile(EclCompileInstance & instance, IPropertyTree * xml);
    void processSingleQuery(const EclRepositoryManager & localRepositoryManager,
                            EclCompileInstance & instance,
                            IFileContents * queryContents,
                            const char * queryAttributePath);
    void processXmlFile(EclCompileInstance & instance, const char *archiveXML);
    void processFile(EclCompileInstance & info);
    void processReference(EclCompileInstance & instance, const char * queryAttributePath, const char * queryAttributePackage);
    void processBatchFiles();
    void processDefinitions(EclRepositoryManager & target);
    void recordPackagesUsed(IWorkUnit * wu, const EclRepositoryManager & manager);
    void reportCompileErrors(IErrorReceiver & errorProcessor, const char * processName);
    void setDebugOption(const char * name, bool value);
    void traceError(char const * format, ...) __attribute__((format(printf, 2, 3)));
    void usage();

protected:
    EclRepositoryManager repositoryManager;
    mutable CriticalSection dfsCrit;
    mutable MapStringToMyClass<IHqlExpression> fileCache;
    mutable MapStringTo<int> fileMissCache;  // values are the error code
    mutable Owned<IUserDescriptor> udesc;    // For file lookups
    const char * programName;

    StringBuffer cppIncludePath;
    StringBuffer pluginsPath;
    StringBuffer hooksPath;
    StringBuffer eclLibraryPath;
    StringBuffer eclBundlePath;
    StringBuffer eclRepoPath;
    StringBuffer stdIncludeLibraryPath;
    StringBuffer includeLibraryPath;
    StringBuffer compilerPath;
    StringBuffer libraryPath;
    StringBuffer querySearchPath;

    StringBuffer cclogFilename;
    StringAttr optLogfile;
    StringAttr optIniFilename;
    StringAttr optOutputDirectory;
    StringAttr optOutputFilename;
    StringAttr optQueryMainAttribute;
    StringAttr optDefaultRepo;
    StringAttr optDefaultRepoVersion;
    bool optExplicitMainPackage = false;
    StringBuffer optQueryMainPackage;
    StringAttr optQueryMainPackageVersion;
    StringAttr optComponentName;
    StringAttr optDFS;
    StringAttr optCluster;
    StringAttr optConfig;
    StringAttr optScope;
    StringAttr optUser;
    StringAttr optPassword;
    StringAttr optWUID;
    StringAttr optCompileBatchOut;
    StringArray clusters;
    mutable int prevClusterSize = -1;  // i.e. not cached
    StringAttr optExpandPath;
    FILE * batchLog = nullptr;

    StringAttr optManifestFilename;
    StringArray resourceManifestFiles;

    IFileArray inputFiles;
    StringArray inputFileNames;
    StringArray applicationOptions;
    StringArray debugOptions;
    StringArray repoMappings;
    StringArray definitions;
    StringArray warningMappings;
    StringArray compileOptions;
    StringArray linkOptions;
    StringArray libraryPaths;

    StringArray allowedPermissions;
    StringArray allowSignedPermissions;
    StringArray deniedPermissions;
    StringAttr optMetaLocation;
    StringBuffer neverSimplifyRegEx;
    StringAttr optDefaultGitPrefix;
    StringAttr optGitLock; // A key used to lock access to git updates
    StringAttr optGitUser;
    StringAttr optGitPasswordPath;

    bool defaultAllowed[2];

    ClusterType optTargetClusterType = RoxieCluster;
    CompilerType optTargetCompiler = DEFAULT_COMPILER;
    unsigned optThreads = 0;
    unsigned batchPart = 0;
    unsigned batchSplit = 1;
    unsigned optMonitorInterval = 60;
    unsigned optMaxErrors = 0;
    unsigned optDaliTimeout = 30000;
    bool optUnsuppressImmediateSyntaxErrors = false;
    bool logVerbose = false;
    bool logTimings = false;
    bool optArchive = false;
    bool optCheckEclVersion = true;
    bool optCheckDirty = false;
    bool optDebugMemLeak = false;
    bool optEvaluateResult = false;
    bool optGenerateMeta = false;
    bool optGenerateDepend = false;
    bool optIncludeMeta = false;
    bool optKeywords = false;
    bool optLeakCheck = false;
    bool optWorkUnit = false;
    bool optNoCompile = false;
    bool optNoLogFile = false;
    bool optLogToStdOut = false;
    bool optNoStdInc = false;
    bool optNoBundles = false;
    bool optBatchMode = false;
    bool optShared = false;
    bool optOnlyCompile = false;
    bool optSaveQueryText = false;
    bool optSaveQueryArchive = false;
    bool optSyntax = false;
    bool optLegacyImport = false;
    bool optLegacyWhen = false;
    bool optIgnoreSignatures = false;
    bool optGenerateHeader = false;
    bool optShowPaths = false;
    bool optNoSourcePath = false;
    bool optFastSyntax = false;
    bool optCheckIncludePaths = true;
    bool optXml = false;
    bool optTraceCache = false;
    bool optVerifySimplified = false;
    bool optRegenerateCache = false;
    bool optIgnoreUnknownImport = false;
    bool optIgnoreCache = false;
    bool optIgnoreSimplified = false;
    bool optExtraStats = false;
    bool optPruneArchive = true;
    bool optFetchRepos = true;
    bool optUpdateRepos = true;
    bool optCleanInvalidRepos = true;
    bool optCleanRepos = false;

    mutable bool daliConnected = false;
    mutable bool disconnectReported = false;
    int argc;
    const char **argv;
};


//=========================================================================================

static int doSelfTest(int argc, const char *argv[])
{
#ifdef _USE_CPPUNIT
    queryStderrLogMsgHandler()->setMessageFields(MSGFIELD_time | MSGFIELD_prefix);
    CppUnit::TextUi::TestRunner runner;
    if (argc==2)
    {
        CppUnit::TestFactoryRegistry &registry = CppUnit::TestFactoryRegistry::getRegistry();
        runner.addTest( registry.makeTest() );
    }
    else
    {
        // MORE - maybe add a 'list' function here?
        for (int name = 2; name < argc; name++)
        {
            if (stricmp(argv[name], "-q")==0)
            {
                removeLog();
            }
            else
            {
                CppUnit::TestFactoryRegistry &registry = CppUnit::TestFactoryRegistry::getRegistry(argv[name]);
                runner.addTest( registry.makeTest() );
            }
        }
    }
    bool wasSucessful = runner.run( "", false );
    releaseAtoms();
    return wasSucessful;
#else
    return true;
#endif
}

static int doMain(int argc, const char *argv[])
{
    if (argc>=2 && stricmp(argv[1], "-selftest")==0)
        return doSelfTest(argc, argv);

    EclCC processor(argc, argv);
    try
    {
        int ret = processor.parseCommandLineOptions(argc, argv);
        if (ret != 0)
            return ret;

        if (processor.printKeywordsToXml())
            return 0;
        if (!processor.processFiles())
            return 2;
    }
    catch (IException *E)
    {
        StringBuffer m("Error: ");
        E->errorMessage(m);
        fputs(m.newline().str(), stderr);
        E->Release();
        return 2;
    }
#ifndef _DEBUG
    catch (...)
    {
        IERRLOG("Unexpected exception\n");
        return 4;
    }
#endif
    return 0;
}


static constexpr const char * defaultYaml = R"!!(
version: "1.0"
eclccserver:
    name: eclccserver
    logging:
      audiences: "USR+ADT"
      classes: "ERR"
)!!";


int main(int argc, const char *argv[])
{
    EnableSEHtoExceptionMapping();
    setTerminateOnSEH(true);
    InitModuleObjects();
    queryStderrLogMsgHandler()->setMessageFields(0);

    unsigned exitCode = 0;
    try
    {
        configuration.setown(loadConfiguration(defaultYaml, argv, "eclccserver", "ECLCCSERVER", "eclccserver.xml", nullptr, nullptr, false));

#ifndef _CONTAINERIZED
        // Turn logging down (we turn it back up if -v option seen)
        Owned<ILogMsgFilter> filter = getCategoryLogMsgFilter(MSGAUD_user| MSGAUD_operator, MSGCLS_error);
        queryLogMsgManager()->changeMonitorFilter(queryStderrLogMsgHandler(), filter);
#else
        setupContainerizedLogMsgHandler();
        bool useChildProcesses = configuration->getPropBool("@useChildProcesses", false);
        if (!useChildProcesses)  // If using eclcc in separate container (useChildProcesses==false),
        {                        // it will need to create a directory for gpg and import keys from secrets
            queryCodeSigner().initForContainer();
        }
#endif
        installSignalHandlers();
        exitCode = doMain(argc, argv);
        restoreSignalHandlers();
        stopPerformanceMonitor();
    }
    catch (IException *E)
    {
        StringBuffer m("Error: ");
        E->errorMessage(m);
        fputs(m.newline().str(), stderr);
        E->Release();
        exitCode = 2;
    }

    if (!optReleaseAllMemory)
    {
        //In release mode exit without calling all the clean up code.
        //It is faster, and it helps avoid potential crashes if there are active objects which depend on objects in file hook dlls.
        fflush(NULL);
        _exit(exitCode);
    }

    configuration.clear();
    releaseAtoms();
    ClearTypeCache();   // Clear this cache before the file hooks are unloaded
    removeFileHooks();
    return exitCode;
}

//=========================================================================================
bool setTargetPlatformOption(const char *platform, ClusterType &optTargetClusterType)
{
    if (!platform || !*platform)
        return false;
    ClusterType clusterType = getClusterType(platform);
    if (clusterType == NoCluster)
    {
        UERRLOG("Unknown ecl target platform %s\n", platform);
        return false;
    }
    optTargetClusterType = clusterType;
    return true;
}

void EclCC::loadManifestOptions()
{
    if (!optManifestFilename)
        return;
    resourceManifestFiles.append(optManifestFilename);

    Owned<IPropertyTree> mf = createPTreeFromXMLFile(optManifestFilename);
    IPropertyTree *ecl = mf->queryPropTree("ecl");
    if (ecl)
    {
        if (ecl->hasProp("@filename"))
        {
            StringBuffer dir, abspath;
            splitDirTail(optManifestFilename, dir);
            makeAbsolutePath(ecl->queryProp("@filename"), dir.str(), abspath);
            processArgvFilename(inputFiles, abspath.str());
        }
        if (!optLegacyImport && !optLegacyWhen)
        {
            bool optLegacy = ecl->getPropBool("@legacy");
            optLegacyImport = ecl->getPropBool("@legacyImport", optLegacy);
            optLegacyWhen = ecl->getPropBool("@legacyWhen", optLegacy);
        }

        if (!optQueryMainAttribute && ecl->hasProp("@main"))
        {
            optQueryMainAttribute.set(ecl->queryProp("@main"));
            optQueryMainPackage.set(ecl->queryProp("@package"));
        }

        if (ecl->hasProp("@targetPlatform"))
            setTargetPlatformOption(ecl->queryProp("@targetPlatform"), optTargetClusterType);
        else if (ecl->hasProp("@targetClusterType")) //deprecated name
            setTargetPlatformOption(ecl->queryProp("@targetClusterType"), optTargetClusterType);

        Owned<IPropertyTreeIterator> paths = ecl->getElements("IncludePath");
        ForEach(*paths)
        {
            IPropertyTree &item = paths->query();
            if (item.hasProp("@path"))
                includeLibraryPath.append(ENVSEPCHAR).append(item.queryProp("@path"));
        }
        paths.setown(ecl->getElements("LibraryPath"));
        ForEach(*paths)
        {
            IPropertyTree &item = paths->query();
            if (item.hasProp("@path"))
                libraryPaths.append(item.queryProp("@path"));
        }
    }
}

void EclCC::loadOptions()
{
    Owned<IProperties> globals;
    if (!optIniFilename)
    {
        if (checkFileExists(INIFILE))
            optIniFilename.set(INIFILE);
        else
        {
            StringBuffer fn(hpccBuildInfo.configDir);
            fn.append(PATHSEPSTR).append(DEFAULTINIFILE);
            if (checkFileExists(fn))
                optIniFilename.set(fn);
        }
    }
    if (logVerbose && optIniFilename.length())
        fprintf(stdout, "Found ini file '%s'\n", optIniFilename.get());

    globals.setown(createProperties(optIniFilename, true));

    if (globals->hasProp("targetGcc"))
        optTargetCompiler = globals->getPropBool("targetGcc") ? GccCppCompiler : Vs6CppCompiler;

    StringBuffer syspath, homepath;
    if (getPackageFolder(syspath) && getHomeFolder(homepath))
    {
#if _WIN32
        extractOption(compilerPath, globals, "CL_PATH", "compilerPath", syspath, "componentfiles\\cl");
#else
        extractOption(compilerPath, globals, "CL_PATH", "compilerPath", "/usr", NULL);
#endif
        extractOption(cppIncludePath, globals, "ECLCC_INCLUDE_PATH", "includePath", syspath, "componentfiles" PATHSEPSTR "cl" PATHSEPSTR "include");
        extractOption(pluginsPath, globals, "ECLCC_PLUGIN_PATH", "plugins", syspath, "plugins");
        getAdditionalPluginsPath(pluginsPath, syspath);
        if (!extractOption(libraryPath, globals, "ECLCC_LIBRARY_PATH", "libraryPath", syspath, "lib"))
        {
            libraryPath.append(ENVSEPCHAR).append(syspath).append("plugins");
            getAdditionalPluginsPath(libraryPath, syspath);
        }
        extractOption(hooksPath, globals, "HPCC_FILEHOOKS_PATH", "filehooks", syspath, "filehooks");
        extractOption(eclLibraryPath, globals, "ECLCC_ECLLIBRARY_PATH", "eclLibrariesPath", syspath, "share" PATHSEPSTR "ecllibrary" PATHSEPSTR);
        extractOption(eclBundlePath, globals, "ECLCC_ECLBUNDLE_PATH", "eclBundlesPath", homepath, PATHSEPSTR "bundles" PATHSEPSTR);
        extractOption(eclRepoPath, globals, "ECLCC_ECLREPO_PATH", "eclRepoPath", homepath, PATHSEPSTR "repos" PATHSEPSTR);
    }
    extractOption(stdIncludeLibraryPath, globals, "ECLCC_ECLINCLUDE_PATH", "eclIncludePath", ".", NULL);

    if (optLogToStdOut)
    {
        Owned<ILogMsgHandler> handler = getHandleLogMsgHandler(stdout);
        handler->setMessageFields(MSGFIELD_STANDARD);
        Owned<ILogMsgFilter> filter = getCategoryLogMsgFilter(MSGAUD_all, MSGCLS_all, DefaultDetail, true);
        queryLogMsgManager()->addMonitor(handler, filter);
    }
#ifndef _CONTAINERIZED
    else
    {
        if (!optLogfile.length() && !optBatchMode && !optNoLogFile)
            extractOption(optLogfile, globals, "ECLCC_LOGFILE", "logfile", "eclcc.log", NULL);

        if ((logVerbose || optLogfile) && !optNoLogFile)
        {
            if (optLogfile.length())
            {
                StringBuffer lf;
                openLogFile(lf, optLogfile, 0, false);
                if (logVerbose)
                    fprintf(stdout, "Logging to '%s'\n",lf.str());
            }
            if (optMonitorInterval)
                startPerformanceMonitor(optMonitorInterval*1000, PerfMonStandard, nullptr);
        }
    }
#endif

    if (hooksPath.length())
        installFileHooks(hooksPath.str());

    if (!optNoCompile)
        setCompilerPath(compilerPath.str(), cppIncludePath.str(), libraryPath.str(), NULL, optTargetCompiler, logVerbose);
}

//=========================================================================================

void EclCC::applyDebugOptions(IWorkUnit * wu)
{
    ForEachItemIn(i, debugOptions)
    {
        const char * option = debugOptions.item(i);
        const char * eq = strchr(option, '=');
        if (eq)
        {
            StringAttr name;
            name.set(option, eq-option);
            wu->setDebugValue(name, eq+1, true);
        }
        else
        {
            size_t len = strlen(option);
            if (len)
            {
                char last = option[len-1];
                if (last == '-' || last == '+')
                {
                    StringAttr name;
                    name.set(option, len-1);
                    wu->setDebugValueInt(name, last == '+' ? 1 : 0, true);
                }
                else
                    wu->setDebugValue(option, "1", true);
            }
        }
    }
}

void EclCC::applyApplicationOptions(IWorkUnit * wu)
{
    ForEachItemIn(i, applicationOptions)
    {
        const char * option = applicationOptions.item(i);
        const char * eq = strchr(option, '=');
        if (eq)
        {
            StringAttr name;
            name.set(option, eq-option);
            wu->setApplicationValue("eclcc", name, eq+1, true);
        }
        else
        {
            wu->setApplicationValueInt("eclcc", option, 1, true);
        }
    }
}

//=========================================================================================

ICppCompiler * EclCC::createCompiler(const char * coreName, const char * sourceDir, const char * targetDir, CompilerType targetCompiler, const char *compileBatchOut)
{
    Owned<ICppCompiler> compiler = ::createCompiler(coreName, sourceDir, targetDir, targetCompiler, logVerbose, compileBatchOut);
    compiler->setOnlyCompile(optOnlyCompile);
    compiler->setCCLogPath(cclogFilename);

    ForEachItemIn(iComp, compileOptions)
        compiler->addCompileOption(compileOptions.item(iComp));

    ForEachItemIn(iLink, linkOptions)
        compiler->addLinkOption(linkOptions.item(iLink));

    ForEachItemIn(iLib, libraryPaths)
        compiler->addLibraryPath(libraryPaths.item(iLib));

    return compiler.getClear();
}

void EclCC::reportCompileErrors(IErrorReceiver & errorProcessor, const char * processName)
{
    StringBuffer failText;
    StringBuffer absCCLogName;
#ifndef _CONTAINERIZED
    if (optLogfile.get())
        createUNCFilename(optLogfile.get(), absCCLogName, false);
    else
#endif
        absCCLogName = "log file";

    failText.appendf("Compile/Link failed for %s (see %s for details)",processName,absCCLogName.str());
    errorProcessor.reportError(ERR_INTERNALEXCEPTION, failText.str(), processName, 0, 0, 0);
    try
    {
        StringBuffer s;
        Owned<IFile> log = createIFile(cclogFilename);
        Owned<IFileIO> io = log->open(IFOread);
        if (io)
        {
            offset_t len = io->size();
            if (len)
            {
                io->read(0, (size32_t)len, s.reserve((size32_t)len));
#ifdef _WIN32
                const char * noCompiler = "is not recognized as an internal";
#else
                const char * noCompiler = "could not locate compiler";
#endif
                if (strstr(s.str(), noCompiler))
                {
                    OERRLOG("Fatal Error: Unable to locate C++ compiler/linker");
                }
                UERRLOG("\n---------- compiler output --------------\n%s\n--------- end compiler output -----------", s.str());
            }
        }
    }
    catch (IException * e)
    {
        e->Release();
    }
}

//=========================================================================================

static void gatherResourceManifestFilenames(IPropertyTree * tree, const char * tag, StringArray &filenames)
{
    Owned<IPropertyTreeIterator> iter = tree->getElements(tag);
    ForEach(*iter)
    {
        StringBuffer filename(iter->query().queryProp("@sourcePath"));
        if (filename.length())
        {
            getFullFileName(filename, true).append(".manifest");
            if (filenames.contains(filename))
                continue;
            Owned<IFile> manifest = createIFile(filename);
            if (manifest->exists())
                filenames.append(filename);
        }
    }

}

void gatherResourceManifestFilenames(EclCompileInstance & instance, StringArray &filenames)
{
    if (instance.archive)
    {
        gatherResourceManifestFilenames(instance.archive, "Module/Attribute", filenames);

        //Gather resources from dependent packages
        Owned<IPropertyTreeIterator> packageIter = instance.archive->getElements("Archive");
        ForEach(*packageIter)
            gatherResourceManifestFilenames(&packageIter->query(), "Module/Attribute", filenames);
    }
    else if (instance.globalDependTree)
    {
        gatherResourceManifestFilenames(instance.globalDependTree, "Attribute", filenames);
    }
}

void EclCC::instantECL(EclCompileInstance & instance, IWorkUnit *wu, const char * queryFullName, IErrorReceiver & errorProcessor, const char * outputFile)
{
    StringBuffer processName(outputFile);
    if (instance.query && containsAnyActions(instance.query))
    {
        try
        {
            bool optSaveTemps = wu->getDebugValueBool("saveEclTempFiles", false);
            bool optPublishCpp = optSaveTemps || optNoCompile || wu->getDebugValueBool("saveCppTempFiles", false) || wu->getDebugValueBool("saveCpp", false);
            bool optSaveCpp = optPublishCpp || !optCompileBatchOut.isEmpty();
            //New scope - testing things are linked correctly
            {
                Owned<IHqlExprDllGenerator> generator = createDllGenerator(&errorProcessor, processName.str(), NULL, wu, optTargetClusterType, &instance, false, false, optTargetCompiler);

                setWorkunitHash(wu, instance.query);
                if (!optShared)
                    wu->setDebugValueInt("standAloneExe", 1, true);
                EclGenerateTarget target = optWorkUnit ? EclGenerateNone : (optNoCompile ? EclGenerateCpp : optShared ? EclGenerateDll : EclGenerateExe);
                if (instance.srcArchive)
                {
                    generator->addManifestsFromArchive(instance.srcArchive);
                    instance.srcArchive.clear();
                }
                else
                {
                    gatherResourceManifestFilenames(instance, resourceManifestFiles);
                    ForEachItemIn(i, resourceManifestFiles)
                        generator->addManifest(resourceManifestFiles.item(i));
                }
                generator->setSaveGeneratedFiles(optSaveCpp, optPublishCpp);

                if (optSaveQueryArchive && instance.wu && instance.archive)
                {
                    StringBuffer buf;
                    toXML(instance.archive, buf);
                    if (optWorkUnit)
                    {
                        Owned<IWUQuery> q = instance.wu->updateQuery();
                        q->setQueryText(buf);
                    }
                    else
                    {
                        if (!instance.wu->getDebugValueBool("obfuscateOutput", false))
                            generator->addArchiveAsResource(buf);
                    }
                }
                bool generateOk = generator->processQuery(instance.query, target);  // NB: May clear instance.query
                instance.stats.cppSize = generator->getGeneratedSize();
                if (generateOk && !optNoCompile)
                {
                    CompilerType targetCompiler = queryCompilerType(instance.wu, optTargetCompiler);
                    Owned<ICppCompiler> compiler = createCompiler(processName.str(), nullptr, nullptr, targetCompiler, optCompileBatchOut);
                    compiler->setSaveTemps(optSaveTemps);

                    bool compileOk = true;
                    if (optShared)
                    {
                        compileOk = generator->generateDll(compiler);
                    }
                    else
                    {
                        if (optTargetClusterType==RoxieCluster)
                            generator->addLibrary("ccd");
                        else
                            generator->addLibrary("hthorlib");


                        compileOk = generator->generateExe(compiler);
                    }

                    if (!compileOk)
                        reportCompileErrors(errorProcessor, processName);
                    compiler->finish();
                }
                else
                    wu->setState(generateOk ? WUStateCompleted : WUStateFailed);
            }

            if (logVerbose)
            {
                switch (wu->getState())
                {
                case WUStateCompiled:
                    fprintf(stdout, "Output file '%s' created\n",outputFile);
                    break;
                case WUStateFailed:
                    traceError("Failed to create output file '%s'\n",outputFile);
                    break;
                case WUStateUploadingFiles:
                    fprintf(stdout, "Output file '%s' created, local file upload required\n",outputFile);
                    break;
                case WUStateCompleted:
                    fprintf(stdout, "No DLL/SO required\n");
                    break;
                default:
                    traceError("Unexpected Workunit state %d\n", (int) wu->getState());
                    break;
                }
            }
        }
        catch (IError * _e)
        {
            Owned<IError> e = _e;
            errorProcessor.report(e);
        }
        catch (IException * _e)
        {
            Owned<IException> e = _e;
            unsigned errCode = e->errorCode();
            if (errCode != HQLERR_ErrorAlreadyReported)
            {
                StringBuffer exceptionText;
                e->errorMessage(exceptionText);
                if (errCode == 0)
                    errCode = ERR_INTERNALEXCEPTION;
                errorProcessor.reportError(ERR_INTERNALEXCEPTION, exceptionText.str(), queryFullName, 1, 0, 0);
            }
        }

        try
        {
            Owned<IFile> log = createIFile(cclogFilename);
            log->remove();
        }
        catch (IException * e)
        {
            e->Release();
        }
    }
}

//=========================================================================================

void EclCC::getComplexity(IWorkUnit *wu, IHqlExpression * query, IErrorReceiver & errs)
{
    double complexity = getECLcomplexity(query, &errs, wu, optTargetClusterType);
    LOG(MCoperatorProgress, "Complexity = %g", complexity);
}

//=========================================================================================

static bool convertPathToModule(StringBuffer & out, const char * filename)
{
    StringBuffer temp;
#ifdef _USE_ZLIB
    removeZipExtension(temp, filename);
#else
    temp.append(filename);
#endif

    const char * dot = strrchr(temp.str(), '.');
    if (dot)
    {
        if (!strieq(dot, ".ecl") && !strieq(dot, ".hql") && !strieq(dot, ".eclmod") && !strieq(dot, ".eclattr"))
            return false;
    }
    else
        return false;

    const unsigned copyLen = dot-temp.str();
    if (copyLen == 0)
        return false;

    out.ensureCapacity(copyLen);
    for (unsigned i= 0; i < copyLen; i++)
    {
        char next = filename[i];
        if (isPathSepChar(next))
            next = '.';
        out.append(next);
    }
    return true;
}


static bool findFilenameInSearchPath(StringBuffer & attributePath, const char * searchPath, const char * expandedSourceName)
{
    const char * cur = searchPath;
    unsigned lenSource = strlen(expandedSourceName);
    for (;;)
    {
        const char * sep = strchr(cur, ENVSEPCHAR);
        StringBuffer curExpanded;
        if (!sep)
        {
            if (*cur)
                makeAbsolutePath(cur, curExpanded);
        }
        else if (sep != cur)
        {
            StringAttr temp(cur, sep-cur);
            makeAbsolutePath(temp, curExpanded);
        }

        if (curExpanded.length() && (curExpanded.length() < lenSource))
        {
#ifdef _WIN32
            //windows paths are case insensitive
            bool same = memicmp(curExpanded.str(), expandedSourceName, curExpanded.length()) == 0;
#else
            bool same = memcmp(curExpanded.str(), expandedSourceName, curExpanded.length()) == 0;
#endif
            if (same)
            {
                const char * tail = expandedSourceName+curExpanded.length();
                if (isPathSepChar(*tail))
                    tail++;
                if (convertPathToModule(attributePath, tail))
                    return true;
            }
        }

        if (!sep)
            return false;
        cur = sep+1;
    }
}

bool EclCC::isWithinPath(const char * sourcePathname, const char * searchPath)
{
    if (!sourcePathname)
        return false;

    StringBuffer expandedSourceName;
    makeAbsolutePath(sourcePathname, expandedSourceName);

    StringBuffer attributePath;
    return findFilenameInSearchPath(attributePath, searchPath, expandedSourceName);
}


bool EclCC::checkWithinRepository(StringBuffer & attributePath, const char * sourcePathname)
{
    if (!sourcePathname)
        return false;

    StringBuffer searchPath;
    searchPath.append(eclLibraryPath).append(ENVSEPCHAR);
    if (!optNoBundles)
        searchPath.append(eclBundlePath).append(ENVSEPCHAR);
    if (!optNoStdInc)
        searchPath.append(stdIncludeLibraryPath).append(ENVSEPCHAR);
    searchPath.append(includeLibraryPath);

    StringBuffer expandedSourceName;
    makeAbsolutePath(sourcePathname, expandedSourceName);

    return findFilenameInSearchPath(attributePath, searchPath, expandedSourceName);
}

void EclCC::evaluateResult(EclCompileInstance & instance)
{
    IHqlExpression *query = instance.query;
    if (query->getOperator()==no_output)
        query = query->queryChild(0);
    if (query->getOperator()==no_datasetfromdictionary)
        query = query->queryChild(0);
    if (query->getOperator()==no_selectfields)
        query = query->queryChild(0);
    if (query->getOperator()==no_createdictionary)
        query = query->queryChild(0);
    OwnedHqlExpr folded = foldHqlExpression(instance.queryErrorProcessor(), query, HFOthrowerror|HFOloseannotations|HFOforcefold|HFOfoldfilterproject|HFOconstantdatasets);
    StringBuffer out;
    IValue *result = folded->queryValue();
    if (result)
        result->generateECL(out);
    else if (folded->getOperator()==no_list)
    {
        out.append('[');
        ForEachChild(idx, folded)
        {
            IHqlExpression *child = folded->queryChild(idx);
            if (idx)
                out.append(", ");
            result = child->queryValue();
            if (result)
                result->generateECL(out);
            else
                throw MakeStringException(1, "Expression cannot be evaluated");
        }
        out.append(']');
    }
    else if (folded->getOperator()==no_inlinetable)
    {
        IHqlExpression *transformList = folded->queryChild(0);
        if (transformList && transformList->getOperator()==no_transformlist)
        {
            IHqlExpression *transform = transformList->queryChild(0);
            assertex(transform && transform->getOperator()==no_transform);
            out.append('[');
            ForEachChild(idx, transform)
            {
                IHqlExpression *child = transform->queryChild(idx);
                assertex(child->getOperator()==no_assign);
                if (idx)
                    out.append(", ");
                result = child->queryChild(1)->queryValue();
                if (result)
                    result->generateECL(out);
                else
                    throw MakeStringException(1, "Expression cannot be evaluated");
            }
            out.append(']');
        }
        else
            throw MakeStringException(1, "Expression cannot be evaluated");
    }
    else
    {
#ifdef _DEBUG
        EclIR::dump_ir(folded);
#endif
        throw MakeStringException(1, "Expression cannot be evaluated");
    }
    printf("%s\n", out.str());
}

void EclCC::processSingleQuery(const EclRepositoryManager & localRepositoryManager,
                               EclCompileInstance & instance,
                               IFileContents * queryContents,
                               const char * queryAttributePath)
{
#ifdef TEST_LEGACY_DEPENDENCY_CODE
    setLegacyEclSemantics(instance.legacyImportMode, instance.legacyWhenMode);
    Owned<IPropertyTree> dependencies = gatherAttributeDependencies(instance.dataServer, "");
    if (dependencies)
        saveXML("depends.xml", dependencies);
#endif

    Owned<IErrorReceiver> wuErrs = new WorkUnitErrorReceiver(instance.wu, "eclcc", optBatchMode);
    Owned<IErrorReceiver> compoundErrs = createCompoundErrorReceiver(&instance.queryErrorProcessor(), wuErrs);
    Owned<ErrorSeverityMapper> severityMapper = new ErrorSeverityMapper(*compoundErrs);

    //Apply command line mappings...
    ForEachItemIn(i, warningMappings)
    {
        if (!severityMapper->addCommandLineMapping(warningMappings.item(i)))
            return;

        //Preserve command line mappings in the generated archive
        if (instance.archive)
            instance.archive->addPropTree("OnWarning")->setProp("@value",warningMappings.item(i));
    }

    //Apply preserved onwarning mappings from any source archive
    if (instance.srcArchive)
    {
        Owned<IPropertyTreeIterator> iter = instance.srcArchive->getElements("OnWarning");
        ForEach(*iter)
        {
            const char * name = iter->query().queryProp("@name");
            const char * option = iter->query().queryProp("@value");
            if (name)
            {
                if (!severityMapper->addMapping(name, option))
                    return;
            }
            else
            {
                if (!severityMapper->addCommandLineMapping(option))
                    return;
            }
        }
    }

    Linked<IErrorReceiver> errorProcessor = severityMapper.get();
    if (optCheckEclVersion)
    {
        //Strange function that might modify errorProcessor...
        checkEclVersionCompatible(errorProcessor, instance.eclVersion);
    }

    //Associate the error handler - so that failures to fetch from git can be reported as errors, but also mapped
    //to warnings to ensure that automated tasks do not fail because the could not connect to git.
    localRepositoryManager.setErrorReceiver(errorProcessor);
    //Ensure the error processor is cleared up when we exit this function
    COnScopeExit scoped([&]() { localRepositoryManager.setErrorReceiver(NULL); });

    //All dlls/exes are essentially cloneable because you may be running multiple instances at once
    //The only exception would be a dll created for a one-time query.  (Currently handled by eclserver.)
    instance.wu->setCloneable(true);

    recordQueueFilePrefixes(instance.wu, configuration);
    applyDebugOptions(instance.wu);
    applyApplicationOptions(instance.wu);

    optTargetCompiler = queryCompilerType(instance.wu, optTargetCompiler);
    if (optTargetCompiler != DEFAULT_COMPILER)
        instance.wu->setDebugValue("targetCompiler", compilerTypeText[optTargetCompiler], true);

    bool withinRepository = (queryAttributePath && *queryAttributePath);
    bool syntaxChecking = instance.wu->getDebugValueBool("syntaxCheck", false);
    if (syntaxChecking || instance.archive)
        severityMapper->addMapping("security", "ignore");

    //This option isn't particularly useful, but is here to help test the code to gather disk information
    bool optGatherDiskStats = instance.wu->getDebugValueBool("gatherEclccDiskStats", false);
    size32_t prevErrs = errorProcessor->errCount();
    cycle_t startCycles = get_cycles_now();
    SystemInfo systemStartTime(ReadAllInfo);
    ProcessInfo processStartTime(ReadAllInfo);

    //Avoid creating the OsDiskStats object if not gathering timings to avoid unnecessary initialisation
    OwnedPtr<OsDiskStats> systemIoStartInfo;
    if (optGatherDiskStats)
        systemIoStartInfo.setown(new OsDiskStats(true));

    if (optCompileBatchOut.isEmpty())
        addTimeStamp(instance.wu, SSToperation, ">compile", StWhenStarted);
    const char * sourcePathname = queryContents ? str(queryContents->querySourcePath()) : NULL;
    const char * defaultErrorPathname = sourcePathname ? sourcePathname : queryAttributePath;

    //The following is only here to provide information about the source file being compiled when reporting leaks
    if (instance.inputFile)
        setActiveSource(instance.inputFile->queryFilename());

    Owned<IEclCachedDefinitionCollection> cache;
    hash64_t optionHash = 0;
    if (optMetaLocation)
    {
        //Update the hash to include information about which options affect how symbols are processed.  It should only include options that
        //affect how the code is parsed, not how it is generated.
        //Include path
        optionHash = rtlHash64VStr(eclLibraryPath, optionHash);
        if (!optNoBundles)
            optionHash = rtlHash64VStr(eclBundlePath, optionHash);
        if (!optNoStdInc)
            optionHash = rtlHash64VStr(stdIncludeLibraryPath, optionHash);
        optionHash = rtlHash64VStr(includeLibraryPath, optionHash);

        //Any explicit -D definitions
        ForEachItemIn(i, definitions)
            optionHash = rtlHash64VStr(definitions.item(i), optionHash);

        optionHash = rtlHash64Data(sizeof(optLegacyImport), &optLegacyImport, optionHash);
        optionHash = rtlHash64Data(sizeof(optLegacyWhen), &optLegacyWhen, optionHash);
        //And create a cache instances
        cache.setown(createEclFileCachedDefinitionCollection(instance.dataServer, optMetaLocation));
    }

    if (instance.archive)
    {
        instance.archive->setPropBool("@legacyImport", instance.legacyImport);
        instance.archive->setPropBool("@legacyWhen", instance.legacyWhen);
        if (withinRepository)
        {
            IEclPackage * package = instance.dataServer.get();
            instance.archive->setProp("Query", "");
            instance.archive->setProp("Query/@attributePath", queryAttributePath);
            instance.archive->setProp("Query/@package", package->queryPackageName());
        }
    }

    if (withinRepository && instance.archive && cache)
    {
        Owned<IEclCachedDefinition> main = cache->getDefinition(queryAttributePath);
        if (main->isUpToDate(optionHash))
        {
            if (main->hasKnownDependents())
            {
                DBGLOG("Create archive from cache for %s", queryAttributePath);
                updateArchiveFromCache(instance.archive, cache, queryAttributePath);
                return;
            }
            UWARNLOG("Cannot create archive from cache for %s because it is a macro", queryAttributePath);
        }
        else
            UWARNLOG("Cannot create archive from cache for %s because it is not up to date", queryAttributePath);
    }

    {
        //Minimize the scope of the parse context to reduce lifetime of cached items.
        WuStatisticTarget statsTarget(instance.wu, "eclcc");
        HqlParseContext parseCtx(&instance, instance.archive, statsTarget);
        parseCtx.cache = cache;
        parseCtx.optionHash = optionHash;
        if (optSyntax)
            parseCtx.setSyntaxChecking();
        if (optVerifySimplified)
            parseCtx.setCheckSimpleDef();
        if (optRegenerateCache)
            parseCtx.setRegenerateCache();
        if (optIgnoreCache)
            parseCtx.setIgnoreCache();
        if (optIgnoreSimplified)
            parseCtx.setIgnoreSimplified();
        if (neverSimplifyRegEx)
            parseCtx.setNeverSimplify(neverSimplifyRegEx.str());

        //Allow fastsyntax to be specified in the archive to aid with regression testing
        if (optFastSyntax || (instance.srcArchive && instance.srcArchive->getPropBool("@fastSyntax", false)))
            parseCtx.setFastSyntax();
        parseCtx.timeParser = instance.wu->getDebugValueBool("timeParser", false);

        //Avoid creating location annotations if syntax checking or creating an archive - since they are only really
        //used when transforming the tree and generating code.  Can significantly speed up some queries.
        //Option noteLocations can be used to override the default.
        enableLocationAnnotations(instance.wu->getDebugValueBool("noteLocations", !optSyntax && !optArchive));

        unsigned maxErrorsDebugOption = instance.wu->getDebugValueInt("maxErrors", 0);
        if (maxErrorsDebugOption != 0)
            parseCtx.maxErrors = maxErrorsDebugOption;
        if (optMaxErrors > 0)
            parseCtx.maxErrors = optMaxErrors;
        parseCtx.unsuppressImmediateSyntaxErrors = optUnsuppressImmediateSyntaxErrors;
        parseCtx.checkDirty = optCheckDirty;
        if (!instance.archive)
            parseCtx.globalDependTree.setown(createPTree(ipt_fast)); //to locate associated manifests, keep separate from user specified MetaOptions
        if (optGenerateMeta || optIncludeMeta)
        {
            //Currently the meta information is generated as a side-effect of parsing the attributes, so disable
            //using the simplified expressions if meta information is requested.  HPCC-20716 will improve this.
            parseCtx.setIgnoreCache();

            HqlParseContext::MetaOptions options;
            options.includePublicDefinitions = instance.wu->getDebugValueBool("metaIncludePublic", true);
            options.includePrivateDefinitions = instance.wu->getDebugValueBool("metaIncludePrivate", true);
            options.onlyGatherRoot = instance.wu->getDebugValueBool("metaIncludeMainOnly", false);
            options.includeImports = instance.wu->getDebugValueBool("metaIncludeImports", true);
            options.includeInternalUses = instance.wu->getDebugValueBool("metaIncludeInternalUse", true);
            options.includeExternalUses = instance.wu->getDebugValueBool("metaIncludeExternalUse", true);
            options.includeLocations = instance.wu->getDebugValueBool("metaIncludeLocations", true);
            options.includeJavadoc = instance.wu->getDebugValueBool("metaIncludeJavadoc", true);
            parseCtx.setGatherMeta(options);
        }

        if (optMetaLocation && !instance.fromArchive)
            parseCtx.setCacheLocation(optMetaLocation);

        setLegacyEclSemantics(instance.legacyImport, instance.legacyWhen);

        parseCtx.ignoreUnknownImport = instance.ignoreUnknownImport;
        parseCtx.ignoreSignatures = instance.ignoreSignatures;
        bool exportDependencies = instance.wu->getDebugValueBool("exportDependencies",false);
        if (exportDependencies || optMetaLocation)
            parseCtx.nestedDependTree.setown(createPTree("Dependencies", ipt_fast));

        addTimeStamp(instance.wu, SSToperation, ">compile:>parse", StWhenStarted);
        try
        {
            HqlLookupContext ctx(parseCtx, errorProcessor, instance.dataServer);

            if (withinRepository)
            {
                instance.query.setown(getResolveAttributeFullPath(queryAttributePath, LSFpublic, ctx, instance.dataServer));
                if (!instance.query && !syntaxChecking && (errorProcessor->errCount() == prevErrs))
                {
                    StringBuffer msg;
                    msg.append("Could not resolve attribute ").append(queryAttributePath);
                    errorProcessor->reportError(3, msg.str(), defaultErrorPathname, 0, 0, 0);
                }
            }
            else
            {
                Owned<IHqlScope> scope = createPrivateScope();
                instance.query.setown(parseQuery(scope, queryContents, ctx, NULL, NULL, true, true));

                if (instance.archive)
                {
                    StringBuffer queryText;
                    queryText.append(queryContents->length(), queryContents->getText());
                    const char * p = queryText;
                    if (0 == strncmp(p, (const char *)UTF8_BOM,3))
                        p += 3;
                    instance.archive->setProp("Query", p );
                    instance.archive->setProp("Query/@originalFilename", sourcePathname);

                    const char * defaultPackageName = instance.dataServer->queryPackageName();
                    if (defaultPackageName)
                        instance.archive->setProp("Query/@package", defaultPackageName);
                }
            }

            if (syntaxChecking && instance.query && instance.query->getOperator() == no_forwardscope)
            {
                IHqlScope * scope = instance.query->queryScope();
                //Have the side effect of resolving the symbols and triggering any syntax errors
                IHqlScope * resolved = scope->queryResolvedScope(&ctx);
                if (resolved)
                    instance.query.set(resolved->queryExpression());
            }

            gatherParseWarnings(ctx.errs, instance.query, parseCtx.orphanedWarnings);

            if (instance.query && !optGenerateMeta && !optEvaluateResult)
                instance.query.setown(convertAttributeToQuery(instance.query, ctx, syntaxChecking));

            unsigned __int64 parseTimeNs = cycle_to_nanosec(get_cycles_now() - startCycles);
            instance.stats.parseTime = (unsigned)nanoToMilli(parseTimeNs);

            updateWorkunitStat(instance.wu, SSToperation, ">compile:>parse", StTimeElapsed, NULL, parseTimeNs);
            stat_type sourceDownloadTime = localRepositoryManager.getStatistic(StTimeElapsed);
            stat_type sourceDownloadBlockedTime = localRepositoryManager.getStatistic(StTimeBlocked);
            if (sourceDownloadTime)
                updateWorkunitStat(instance.wu, SSToperation, ">compile:>parse:>download", StTimeElapsed, NULL, sourceDownloadTime);
            if (sourceDownloadBlockedTime)
                updateWorkunitStat(instance.wu, SSToperation, ">compile:>parse:>download", StTimeBlocked, NULL, sourceDownloadBlockedTime);

            if (optExtraStats)
            {
                updateWorkunitStat(instance.wu, SSToperation, ">compile:>parse", StNumAttribsProcessed, NULL, parseCtx.numAttribsProcessed);
            }

            if (exportDependencies)
            {
                StringBuffer dependenciesName;
                if (instance.outputFilename && !streq(instance.outputFilename, "-"))
                    addNonEmptyPathSepChar(dependenciesName.append(optOutputDirectory)).append(instance.outputFilename);
                else
                    dependenciesName.append(DEFAULT_OUTPUTNAME);
                dependenciesName.append(".dependencies.xml");

                Owned<IWUQuery> query = instance.wu->updateQuery();
                associateLocalFile(query, FileTypeXml, dependenciesName, "Dependencies", 0);

                saveXML(dependenciesName.str(), parseCtx.nestedDependTree);
            }

            if (optGenerateMeta)
                instance.generatedMeta.setown(parseCtx.getClearMetaTree());
            else if (optIncludeMeta && instance.metaOutputFilename)
            {
                Owned<IPropertyTree> meta = parseCtx.getClearMetaTree();
                saveXML(instance.metaOutputFilename, meta, 0, XML_Embed|XML_LineBreak);
            }

            if (parseCtx.globalDependTree)
                instance.globalDependTree.set(parseCtx.globalDependTree);

            if (optEvaluateResult && !errorProcessor->errCount() && instance.query)
                evaluateResult(instance);
        }
        catch (IException *e)
        {
            StringBuffer s;
            e->errorMessage(s);
            unsigned errorCode = e->errorCode();
            if ((errorCode < HQL_ERROR_START) || (errorCode > HQL_ERROR_END))
                errorCode = ERR_UNKNOWN_EXCEPTION;
            errorProcessor->reportError(errorCode, s.str(), defaultErrorPathname, 1, 0, 0);
            e->Release();
        }

        recordPackagesUsed(instance.wu, localRepositoryManager);
    }

    //Free up the repository (and any cached expressions) as soon as the expression has been parsed
    instance.dataServer.clear();

    if (!syntaxChecking && (errorProcessor->errCount() == prevErrs) && (!instance.query || !containsAnyActions(instance.query)))
    {
        errorProcessor->reportError(3, "Query is empty", defaultErrorPathname, 1, 0, 0);
        return;
    }

    if (optArchive || optGenerateDepend)
        return;

    if (syntaxChecking || optGenerateMeta || optEvaluateResult)
        return;

    StringBuffer targetFilename;
    const char * outputFilename = instance.outputFilename;
    if (!outputFilename)
    {
        addNonEmptyPathSepChar(targetFilename.append(optOutputDirectory));
        targetFilename.append(DEFAULT_OUTPUTNAME);
    }
    else if (strcmp(outputFilename, "-") == 0)
        targetFilename.append("stdout:");
    else
        addNonEmptyPathSepChar(targetFilename.append(optOutputDirectory)).append(outputFilename);

    //Check if it overlaps with the source file and add .eclout if so
    if (instance.inputFile)
    {
        const char * originalFilename = instance.inputFile->queryFilename();
        if (streq(targetFilename, originalFilename))
            targetFilename.append(".eclout");
    }

    if (errorProcessor->errCount() == prevErrs)
    {
        const char * queryFullName = NULL;
        instantECL(instance, instance.wu, queryFullName, *errorProcessor, targetFilename);
    }
    else
    {
        if (stdIoHandle(targetFilename) == -1)
        {
        // MORE - what about intermediate files?
#ifdef _WIN32
            StringBuffer goer;
            remove(goer.append(targetFilename).append(".exe"));
            remove(goer.clear().append(targetFilename).append(".exe.manifest"));
#else
            remove(targetFilename);
#endif
        }
    }

    unsigned __int64 totalTimeNs = cycle_to_nanosec(get_cycles_now() - startCycles);
    SystemInfo systemFinishTime(ReadAllInfo);
    ProcessInfo processFinishTime(ReadAllInfo);
    OwnedPtr<OsDiskStats> systemIoFinishInfo;
    if (optGatherDiskStats)
        systemIoFinishInfo.setown(new OsDiskStats(true));
    instance.stats.generateTime = (unsigned)nanoToMilli(totalTimeNs) - instance.stats.parseTime;
    const char *scopeName = optCompileBatchOut.isEmpty() ? ">compile" : ">compile:>generate";
    if (optCompileBatchOut.isEmpty())
        updateWorkunitStat(instance.wu, SSToperation, scopeName, StTimeElapsed, NULL, totalTimeNs);

    const cost_type cost = money2cost_type(calcCost(getMachineCostRate(), nanoToMilli(totalTimeNs)));
    if (cost)
        instance.wu->setStatistic(queryStatisticsComponentType(), queryStatisticsComponentName(), SSToperation, scopeName, StCostCompile, NULL, cost, 1, 0, StatsMergeReplace);

    if (systemFinishTime.getTotal())
    {
        SystemProcessInfo systemElapsed = systemFinishTime - systemStartTime;
        SystemProcessInfo processElapsed = processFinishTime - processStartTime;
        updateWorkunitStat(instance.wu, SSToperation, scopeName, StNumSysContextSwitches, NULL, systemElapsed.getNumContextSwitches());
        updateWorkunitStat(instance.wu, SSToperation, scopeName, StTimeOsUser, NULL, systemElapsed.getUserNs());
        updateWorkunitStat(instance.wu, SSToperation, scopeName, StTimeOsSystem, NULL, systemElapsed.getSystemNs());
        updateWorkunitStat(instance.wu, SSToperation, scopeName, StTimeOsTotal, NULL, systemElapsed.getTotalNs());
        updateWorkunitStat(instance.wu, SSToperation, scopeName, StTimeUser, NULL, processElapsed.getUserNs());
        updateWorkunitStat(instance.wu, SSToperation, scopeName, StTimeSystem, NULL, processElapsed.getSystemNs());
        if (processFinishTime.getPeakResidentMemory())
            updateWorkunitStat(instance.wu, SSToperation, scopeName, StSizePeakMemory, NULL, processFinishTime.getPeakResidentMemory());
    }

    if (optGatherDiskStats)
    {
        const BlockIoStats summaryIo = systemIoFinishInfo->querySummaryStats() - systemIoStartInfo->querySummaryStats();
        if (summaryIo.rd_sectors)
            updateWorkunitStat(instance.wu, SSToperation, scopeName, StSizeDiskRead, NULL, summaryIo.rd_sectors * summaryIo.getSectorSize());
        if (summaryIo.wr_sectors)
            updateWorkunitStat(instance.wu, SSToperation, scopeName, StSizeDiskWrite, NULL, summaryIo.wr_sectors * summaryIo.getSectorSize());
    }
}

void EclCC::processDefinitions(EclRepositoryManager & target)
{
    ForEachItemIn(iDef, definitions)
    {
        const char * definition = definitions.item(iDef);
        StringAttr name;
        StringBuffer value;
        const char * eq = strchr(definition, '=');
        if (eq)
        {
            name.set(definition, eq-definition);
            value.append(eq+1);
        }
        else
        {
            name.set(definition);
            value.append("true");
        }
        value.append(";");

        StringAttr module;
        const char * attr;
        const char * dot = strrchr(name, '.');
        if (dot)
        {
            module.set(name, dot-name);
            attr = dot+1;
        }
        else
        {
            module.set("");
            attr = name;
        }

        //Create a repository with just that attribute.
        timestamp_type ts = 1; // Use a non zero timestamp so the value can be cached.  Changes are spotted through the optionHash
        Owned<IFileContents> contents = createFileContentsFromText(value, NULL, false, NULL, ts);
        target.addSingleDefinitionEclRepository(module, attr, contents, true);
    }
}


void EclCC::processXmlFile(EclCompileInstance & instance, const char *archiveXML)
{
    instance.srcArchive.setown(createPTreeFromXMLString(archiveXML, ipt_caseInsensitive));

    if (optExpandPath)
    {
        expandArchive(optExpandPath, instance.srcArchive, true);
        const char * queryText = instance.srcArchive->queryProp("Query");
        if (queryText)
            printf("%s", queryText);
        return;
    }

    IPropertyTree * archiveTree = instance.srcArchive;
    Owned<IPropertyTreeIterator> iter = archiveTree->getElements("Option");
    ForEach(*iter)
    {
        IPropertyTree &item = iter->query();
        instance.wu->setDebugValue(item.queryProp("@name"), item.queryProp("@value"), true);
    }

    //Mainly for testing...
    Owned<IPropertyTreeIterator> iterDef = archiveTree->getElements("Definition");
    ForEach(*iterDef)
    {
        IPropertyTree &item = iterDef->query();
        const char * name = item.queryProp("@name");
        const char * value = item.queryProp("@value");
        StringBuffer definition;
        definition.append(name);
        if (value)
            definition.append('=').append(value);
        definitions.append(definition);
    }

    const char * queryText = archiveTree->queryProp("Query");
    const char * queryAttributePath = archiveTree->queryProp("Query/@attributePath");
    const char * queryAttributePackage = archiveTree->queryProp("Query/@package");

    //Takes precedence over an entry in the archive - so you can submit parts of an archive.
    if (optQueryMainAttribute)
    {
        queryAttributePath = optQueryMainAttribute;
        queryAttributePackage = optQueryMainPackage;
    }

    //The legacy mode (if specified) in the archive takes precedence - it needs to match to compile.
    instance.legacyImport = archiveTree->getPropBool("@legacyMode", instance.legacyImport);
    instance.legacyWhen = archiveTree->getPropBool("@legacyMode", instance.legacyWhen);
    instance.legacyImport = archiveTree->getPropBool("@legacyImport", instance.legacyImport);
    instance.legacyWhen = archiveTree->getPropBool("@legacyWhen", instance.legacyWhen);

    //Some old archives contained imports, but no definitions of the module.  This option is to allow them to compile.
    //It shouldn't be needed for new archives in non-legacy mode. (But neither should it cause any harm.)
    instance.ignoreUnknownImport = archiveTree->getPropBool("@ignoreUnknownImport", true);

    instance.eclVersion.set(archiveTree->queryProp("@eclVersion"));

    EclRepositoryManager localRepositoryManager(&instance);
    processDefinitions(localRepositoryManager);
    localRepositoryManager.inherit(repositoryManager); // Definitions, plugins, std library etc.
    Owned<IFileContents> contents;
    Owned<IEclPackage> mainPackage;
    StringBuffer fullPath; // Here so it doesn't get freed when leaving the else block

    if (queryText || queryAttributePath)
    {
        const char * sourceFilename = archiveTree->queryProp("Query/@originalFilename");
        Owned<ISourcePath> sourcePath = createSourcePath(sourceFilename);
        contents.setown(createFileContentsFromText(queryText, sourcePath, false, NULL, 0));
        if (queryAttributePath && queryText && *queryText)
        {
            Owned<IEclSourceCollection> inputFileCollection = createSingleDefinitionEclCollection(queryAttributePath, contents);
            localRepositoryManager.addRepository(inputFileCollection, nullptr, true);
        }
    }
    else
    {
        //This is really only useful for regression testing
        const char * queryText = archiveTree->queryProp("SyntaxCheck");
        const char * syntaxCheckModule = archiveTree->queryProp("SyntaxCheck/@module");
        const char * syntaxCheckAttribute = archiveTree->queryProp("SyntaxCheck/@attribute");
        if (!queryText || !syntaxCheckModule || !syntaxCheckAttribute)
            throw MakeStringException(1, "No query found in xml");

        instance.wu->setDebugValueInt("syntaxCheck", true, true);
        fullPath.append(syntaxCheckModule).append('.').append(syntaxCheckAttribute);
        queryAttributePath = fullPath.str();

        //Create a repository with just that attribute, and place it before the archive in the resolution order.
        Owned<IFileContents> contents = createFileContentsFromText(queryText, NULL, false, NULL, 0);
        localRepositoryManager.addSingleDefinitionEclRepository(syntaxCheckModule, syntaxCheckAttribute, contents, true);
    }

    localRepositoryManager.processArchive(archiveTree);

    if (queryAttributePackage)
        instance.dataServer.set(localRepositoryManager.queryRepositoryAsRoot(queryAttributePackage, nullptr));
    else
        instance.dataServer.setown(localRepositoryManager.createPackage(nullptr));

    //Ensure classes are not linked by anything else
    localRepositoryManager.kill();  // help ensure non-shared repositories are freed as soon as possible

    processSingleQuery(localRepositoryManager, instance, contents, queryAttributePath);
}


//=========================================================================================

void EclCC::processFile(EclCompileInstance & instance)
{
    clearTransformStats();

    Linked<IFile> inputFile = instance.inputFile;
    const char * curFilename = inputFile->queryFilename();
    assertex(curFilename);
    bool inputFromStdIn = streq(curFilename, "stdin:");

    //Ensure the filename is fully expanded, but do not recreate the IFile if it was already absolute
    StringBuffer expandedSourceName;
    if (!inputFromStdIn && !optNoSourcePath && !isAbsolutePath(curFilename))
    {
        makeAbsolutePath(curFilename, expandedSourceName);
        inputFile.setown(createIFile(expandedSourceName));
    }
    else
        expandedSourceName.append(curFilename);

    Owned<ISourcePath> sourcePath = (optNoSourcePath||inputFromStdIn) ? NULL : createSourcePath(expandedSourceName);
    Owned<IFileContents> queryText = createFileContents(inputFile, sourcePath, false, NULL);

    const char * queryTxt = queryText->getText();
    if (optArchive || optGenerateDepend || optSaveQueryArchive)
        instance.archive.setown(createAttributeArchive());

    instance.wu.setown(createLocalWorkUnit());
    //Record the version of the compiler in the workunit, but not when regression testing (to avoid spurious differences)
    if (!optBatchMode)
        instance.wu->setDebugValue("eclcc_compiler_version", LANGUAGE_VERSION, true);
    if (optSaveQueryText)
    {
        Owned<IWUQuery> q = instance.wu->updateQuery();
        q->setQueryText(queryTxt);
    }

    //On a system with userECL not allowed, all compilations must be from checked-in code that has been
    //deployed to the eclcc machine via other means (typically via a version-control system)
    if (!allowAccess("userECL", false) && (!optQueryMainAttribute || queryText->length()))
    {
        instance.queryErrorProcessor().reportError(HQLERR_UserCodeNotAllowed, HQLERR_UserCodeNotAllowed_Text, NULL, 1, 0, 0);
    }
    else if (isArchiveQuery(queryTxt))
    {
        instance.fromArchive = true;
        processXmlFile(instance, queryTxt);
    }
    else
    {
        StringBuffer attributePath;
        const char * attributePackage = nullptr;
        bool withinRepository = false;

        //Specifying --main indicates that the query text (if present) replaces that definition
        if (optQueryMainAttribute)
        {
            withinRepository = true;
            attributePath.clear().append(optQueryMainAttribute);
            if (!optQueryMainPackage.isEmpty())
                attributePackage = optQueryMainPackage;
        }
        else
        {
            withinRepository = !inputFromStdIn && !optNoSourcePath && checkWithinRepository(attributePath, curFilename);
            if (!optDefaultRepo.isEmpty())
                attributePackage = optDefaultRepo.str();
        }

        EclRepositoryManager localRepositoryManager(&instance);
        processDefinitions(localRepositoryManager);
        localRepositoryManager.inherit(repositoryManager); // don't include -I
        if (!optNoBundles)
            localRepositoryManager.addQuerySourceFileEclRepository(&instance.queryErrorProcessor(), eclBundlePath.str(), ESFoptional|ESFnodependencies, 0);

        //Ensure that this source file is used as the definition (in case there are potential clashes)
        //Note, this will not override standard library files.
        Owned<IEclSourceCollection> inputFileCollection;
        if (withinRepository)
        {
            //-main only overrides the definition if the query is non-empty.  Otherwise use the existing text.
            if (!optQueryMainAttribute || queryText->length())
            {
                inputFileCollection.setown(createSingleDefinitionEclCollection(attributePath, queryText));
                localRepositoryManager.addRepository(inputFileCollection, nullptr, true);
            }
        }
        else
        {
            //Ensure that $ is valid for any file submitted - even if it isn't in the include directories
            //Disable this for the moment when running the regression suite.
            if (!optBatchMode && !withinRepository && !inputFromStdIn && !optNoSourcePath && !optLegacyImport)
            {
                //Associate the contents of the directory with an internal module called _local_directory_
                //(If it was root it might override existing root symbols).  $ is the only public way to get at the symbol
                const char * moduleName = INTERNAL_LOCAL_MODULE_NAME;
                IIdAtom * moduleNameId = createIdAtom(moduleName);

                StringBuffer thisDirectory;
                StringBuffer thisTail;
                splitFilename(expandedSourceName, &thisDirectory, &thisDirectory, &thisTail, NULL);
                attributePath.append(moduleName).append(".").append(thisTail);

                inputFileCollection.setown(createSingleDefinitionEclCollection(attributePath, queryText));
                localRepositoryManager.addRepository(inputFileCollection, nullptr, true);

                Owned<IEclSourceCollection> directory = createFileSystemEclCollection(&instance.queryErrorProcessor(), thisDirectory, ESFnone, 0);
                localRepositoryManager.addNestedRepository(moduleNameId, directory, true);
            }
        }

        if (attributePackage)
        {
            //If attribute package is specified, resolve that package as the source for the query
            instance.dataServer.set(localRepositoryManager.queryRepositoryAsRoot(attributePackage, inputFileCollection));
        }
        else
        {
            localRepositoryManager.addQuerySourceFileEclRepository(&instance.queryErrorProcessor(), querySearchPath.str(), ESFdependencies, 0);

            instance.dataServer.setown(localRepositoryManager.createPackage(nullptr));
        }

        processSingleQuery(localRepositoryManager, instance, queryText, attributePath.str());
    }

    if (!instance.reportErrorSummary() || instance.archive || (optGenerateMeta && instance.generatedMeta))
        generateOutput(instance);

    //Transform stats are gathered in static global variables.  Revisit if the code generator is multi threaded.
    if (instance.wu->getDebugValueBool("timeTransforms", false))
    {
        WuStatisticTarget statsTarget(instance.wu, "eclcc");
        gatherTransformStats(statsTarget);
    }
}


IFileIO * EclCC::createArchiveOutputFile(EclCompileInstance & instance)
{
    StringBuffer archiveName;
    if (instance.outputFilename && !streq(instance.outputFilename, "-"))
        addNonEmptyPathSepChar(archiveName.append(optOutputDirectory)).append(instance.outputFilename);
    else
        archiveName.append("stdout:");

    //Work around windows problem writing 64K to stdout if not redirected/piped
    OwnedIFile ifile = createIFile(archiveName);
    return ifile->open(IFOcreate);
}

void EclCC::outputXmlToOutputFile(EclCompileInstance & instance, IPropertyTree * xml)
{
    OwnedIFileIO ifileio = createArchiveOutputFile(instance);
    if (ifileio)
    {
        //Work around windows problem writing 64K to stdout if not redirected/piped
        Owned<IIOStream> stream = createIOStream(ifileio.get());
        {
            Owned<IIOStream> buffered = createBufferedIOStream(stream,0x8000);
            saveXML(*buffered, xml);
        }
        ifileio->close();
    }
}


void EclCC::addFilenameDependency(StringBuffer & target, EclCompileInstance & instance, const char * filename)
{
    if (!filename)
        return;

    //Ignore plugins and standard library components
    if (isWithinPath(filename, pluginsPath) || isWithinPath(filename, eclLibraryPath))
        return;

    //Don't include the input file in the dependencies.
    if (instance.inputFile)
    {
        const char * sourceFilename = instance.inputFile->queryFilename();
        if (sourceFilename && streq(sourceFilename, filename))
            return;
    }
    target.append(filename).newline();
}


void EclCC::generateOutput(EclCompileInstance & instance)
{
    const char * outputFilename = instance.outputFilename;
    if (instance.archive)
    {
        if (optGenerateDepend)
        {
            //Walk the archive, and output all filenames that aren't
            //a)in a plugin b) in std.lib c) the original source file.
            StringBuffer filenames;
            Owned<IPropertyTreeIterator> modIter = instance.archive->getElements("Module");
            ForEach(*modIter)
            {
                IPropertyTree * module = &modIter->query();
                if (module->hasProp("@plugin"))
                    continue;
                addFilenameDependency(filenames, instance, module->queryProp("@sourcePath"));

                Owned<IPropertyTreeIterator> defIter = module->getElements("Attribute");
                ForEach(*defIter)
                {
                    IPropertyTree * definition = &defIter->query();
                    addFilenameDependency(filenames, instance, definition->queryProp("@sourcePath"));
                }
            }

            OwnedIFileIO ifileio = createArchiveOutputFile(instance);
            if (ifileio)
            {
                ifileio->write(0, filenames.length(), filenames.str());
                ifileio->close();
            }
        }
        else
        {
            // Output option settings
            Owned<IStringIterator> debugValues = &instance.wu->getDebugValues();
            ForEach (*debugValues)
            {
                SCMStringBuffer debugStr, valueStr;
                debugValues->str(debugStr);
                instance.wu->getDebugValue(debugStr.str(), valueStr);
                Owned<IPropertyTree> option = createPTree("Option");
                option->setProp("@name", debugStr.str());
                option->setProp("@value", valueStr.str());
                instance.archive->addPropTree("Option", option.getClear());
            }

            if (optArchive)
            {
                //Only include resources in the archive if a full archive is being created, not if it is being saved in the workunit
                gatherResourceManifestFilenames(instance, resourceManifestFiles);
                ForEachItemIn(i, resourceManifestFiles)
                    addManifestResourcesToArchive(instance.archive, resourceManifestFiles.item(i));

                if (optCheckDirty)
                {
                    Owned<IPipeProcess> pipe = createPipeProcess();
                    if (!pipe->run("git", "git describe --always --tags --dirty --long", ".", false, true, false, 0, false))
                    {
                        UWARNLOG("Failed to run git describe");
                    }
                    else
                    {
                        try
                        {
                            unsigned retcode = pipe->wait();
                            StringBuffer buf;
                            Owned<ISimpleReadStream> pipeReader = pipe->getOutputStream();
                            readSimpleStream(buf, *pipeReader, 128);
                            if (retcode)
                                UWARNLOG("Failed to run git describe: returned %d (%s)", retcode, buf.str());
                            else if (buf.length())
                            {
                                buf.replaceString("\n","");
                                instance.archive->setProp("@git", buf);
                            }
                        }
                        catch (IException *e)
                        {
                            EXCLOG(e, "Exception running git describe");
                            e->Release();
                        }
                    }
                }
                outputXmlToOutputFile(instance, instance.archive);
            }
        }
    }

    if (optGenerateMeta && instance.generatedMeta)
        outputXmlToOutputFile(instance, instance.generatedMeta);

    if (optWorkUnit && instance.wu)
    {
        StringBuffer xmlFilename;
        addNonEmptyPathSepChar(xmlFilename.append(optOutputDirectory));
        if (outputFilename)
            xmlFilename.append(outputFilename);
        else
            xmlFilename.append(DEFAULT_OUTPUTNAME);
        xmlFilename.append(".xml");
        exportWorkUnitToXMLFile(instance.wu, xmlFilename, 0, true, false, false, false);
    }
}


void EclCC::processReference(EclCompileInstance & instance, const char * queryAttributePath, const char * queryAttributePackage)
{
    if (isEmptyString(queryAttributePath))
        throw makeStringException(0, "Blank main attribute supplied - no query to compile");

    instance.wu.setown(createLocalWorkUnit());
    if (optArchive || optGenerateDepend || optSaveQueryArchive)
        instance.archive.setown(createAttributeArchive());

    EclRepositoryManager localRepositoryManager(&instance);
    processDefinitions(localRepositoryManager);
    localRepositoryManager.inherit(repositoryManager);
    if (!optNoBundles)
        localRepositoryManager.addQuerySourceFileEclRepository(&instance.queryErrorProcessor(), eclBundlePath.str(), ESFoptional|ESFnodependencies, 0);

    if (!isEmptyString(queryAttributePackage))
    {
        instance.dataServer.set(localRepositoryManager.queryRepositoryAsRoot(queryAttributePackage, nullptr));
    }
    else
    {
        const char * searchPath = querySearchPath;
        while (*searchPath == ENVSEPCHAR)
            searchPath++;

        if (looksLikeGitPackage(searchPath))
        {
            instance.dataServer.set(localRepositoryManager.queryRepositoryAsRoot(searchPath, nullptr));
        }
        else
        {
            localRepositoryManager.addQuerySourceFileEclRepository(&instance.queryErrorProcessor(), searchPath, ESFdependencies, 0);
            instance.dataServer.setown(localRepositoryManager.createPackage(nullptr));
        }
    }

    processSingleQuery(localRepositoryManager, instance, NULL, queryAttributePath);

    if (instance.reportErrorSummary())
        return;
    generateOutput(instance);
}

void EclCC::recordPackagesUsed(IWorkUnit * wu, const EclRepositoryManager & manager)
{
    StringArray packages;
    manager.gatherPackagesUsed(packages);
    ForEachItemIn(i, packages)
    {
        StringBuffer key;
        key.append("package").append(i+1);
        wu->setApplicationValue("packages", key, packages.item(i), true);
    }
}

bool EclCC::generatePrecompiledHeader()
{
    if (inputFiles.ordinality() != 0)
    {
        traceError("No input files should be specified when generating precompiled header");
        return false;
    }
    StringArray paths;
    paths.appendList(cppIncludePath, ENVSEPSTR);
    const char *foundPath = NULL;
    ForEachItemIn(idx, paths)
    {
        StringBuffer fullpath;
        fullpath.append(paths.item(idx));
        addPathSepChar(fullpath).append("eclinclude4.hpp");
        if (checkFileExists(fullpath))
        {
            foundPath = paths.item(idx);
            break;
        }
    }
    if (!foundPath)
    {
        traceError("Cannot find eclinclude4.hpp");
        return false;
    }
    Owned<ICppCompiler> compiler = createCompiler("precompile", foundPath, nullptr, optTargetCompiler, nullptr);
    compiler->setDebug(true);  // a precompiled header with debug can be used for no-debug, but not vice versa
    compiler->addSourceFile("eclinclude4.hpp", nullptr);
    compiler->setPrecompileHeader(true);
    if (compiler->compile())
    {
        try
        {
            Owned<IFile> log = createIFile(cclogFilename);
            log->remove();
        }
        catch (IException * e)
        {
            e->Release();
        }
        return true;
    }
    else
    {
        traceError("Compilation failed - see %s for details", cclogFilename.str());
        return false;
    }
}

static void checkForOverlappingPaths(const char * path)
{
    StringArray originalPaths;
    originalPaths.appendList(path, ENVSEPSTR);

    StringArray expandedPaths;
    ForEachItemIn(i1, originalPaths)
    {
        const char * cur = originalPaths.item(i1);
        if (*cur)
        {
            StringBuffer expanded;
            makeAbsolutePath(cur, expanded);
            expandedPaths.append(expanded);
        }
    }

    //Sort alphabetically, smallest strings will come first
    expandedPaths.sortAscii(!filenamesAreCaseSensitive);

    //If one string is a subset of another then the shorter will come immediately before at least one that overlaps
    for (unsigned i=1; i < expandedPaths.ordinality(); i++)
    {
        const char * prev = expandedPaths.item(i-1);
        const char * next = expandedPaths.item(i);
        if (hasPrefix(next, prev, filenamesAreCaseSensitive))
        {
            if (!streq(next, prev))
                fprintf(stderr, "Warning: Include paths -I '%s' and '%s' overlap\n", prev, next);
        }
    }
}



bool EclCC::processFiles()
{
    loadOptions();
    ForEachItemIn(idx, inputFileNames)
    {
        processArgvFilename(inputFiles, inputFileNames.item(idx));
    }
    if (optShowPaths)
    {
        printf("CL_PATH=%s\n", compilerPath.str());
        printf("ECLCC_ECLBUNDLE_PATH=%s\n", eclBundlePath.str());
        printf("ECLCC_ECLREPO_PATH=%s\n", eclRepoPath.str());
        printf("ECLCC_ECLINCLUDE_PATH=%s\n", stdIncludeLibraryPath.str());
        printf("ECLCC_ECLLIBRARY_PATH=%s\n", eclLibraryPath.str());
        printf("ECLCC_INCLUDE_PATH=%s\n", cppIncludePath.str());
        printf("ECLCC_LIBRARY_PATH=%s\n", libraryPath.str());
        printf("ECLCC_PLUGIN_PATH=%s\n", pluginsPath.str());
        printf("HPCC_FILEHOOKS_PATH=%s\n", hooksPath.str());
        return true;
    }
    if (optGenerateHeader)
    {
        return generatePrecompiledHeader();
    }
    else if (inputFiles.ordinality() == 0)
    {
        if (optBatchMode || !optQueryMainAttribute)
        {
            UERRLOG("No input files could be opened");
            return false;
        }
    }

    if (!optNoStdInc && stdIncludeLibraryPath.length())
        querySearchPath.append(stdIncludeLibraryPath).append(ENVSEPCHAR);
    querySearchPath.append(includeLibraryPath);
    if (optCheckIncludePaths)
        checkForOverlappingPaths(querySearchPath);

    bool includePluginsInArchive = !optPruneArchive;
    bool includeLibraryInArchive = !optPruneArchive;
    Owned<IErrorReceiver> errs = optXml ? createXmlFileErrorReceiver(stderr) : createFileErrorReceiver(stderr);
    bool ok = true;

    try
    {
        //Set up the default repository information.  This could be simplified to not use a localRepositoryManager later
        //if eclcc did not have a strange mode for running multiple queries as part of the regression suite testing on windows.
        repositoryManager.setOptions(eclRepoPath, optGitUser, optGitPasswordPath, optDefaultGitPrefix, optFetchRepos, optUpdateRepos, optCleanRepos, optCleanInvalidRepos, logVerbose);
        ForEachItemIn(iMapping, repoMappings)
        {
            const char * cur = repoMappings.item(iMapping);
            const char * eq = strchr(cur, '=');
            StringBuffer repo(eq-cur, cur);
            repositoryManager.addMapping(repo, eq+1);
        }

        //Items first in the list have priority -Dxxx=y overrides all
        repositoryManager.addSharedSourceFileEclRepository(errs, pluginsPath.str(), ESFallowplugins|ESFnodependencies, logVerbose ? PLUGIN_DLL_MODULE : 0, includePluginsInArchive);
        repositoryManager.addSharedSourceFileEclRepository(errs, eclLibraryPath.str(), ESFnodependencies, 0, includeLibraryInArchive);
        //Bundles are not included in other repos.  Should eventually be replaced by dependent repos

        //Ensure symbols for plugins are initialised - see comment before CHqlMergedScope...
    //    lookupAllRootDefinitions(pluginsRepository);

        if (optBatchMode)
        {
            processBatchFiles();
        }
        else if (inputFiles.ordinality() == 0)
        {
            EclCompileInstance info(*this, NULL, *errs, stderr, optOutputFilename, optLegacyImport, optLegacyWhen, optIgnoreSignatures, optIgnoreUnknownImport, optXml);
            processReference(info, optQueryMainAttribute, optQueryMainPackage);
            ok = (errs->errCount() == 0);

            info.logStats(logTimings);
        }
        else
        {
            EclCompileInstance info(*this, &inputFiles.item(0), *errs, stderr, optOutputFilename, optLegacyImport, optLegacyWhen, optIgnoreSignatures, optIgnoreUnknownImport, optXml);
            processFile(info);
            ok = (errs->errCount() == 0);

            info.logStats(logTimings);
        }
    }
    catch (IException * e)
    {
        //Ensure any exceptions are reported as xml if that option is selected
        StringBuffer msg;
        errs->reportError(e->errorCode(), e->errorMessage(msg).str(), nullptr, 0, 0, 0);
        e->Release();
        ok = false;
    }

    return ok;
}

void EclCC::setDebugOption(const char * name, bool value)
{
    StringBuffer temp;
    temp.append(name).append("=").append(value ? "1" : "0");
    debugOptions.append(temp);
}


void EclCC::traceError(char const * format, ...)
{
    va_list args;
    va_start(args, format);

    if (optXml)
    {
        StringBuffer msg;
        msg.valist_appendf(format, args);
        StringBuffer encoded;
        encodeXML(msg.str(), encoded);
        UERRLOG("<exception msg='%s'/>", encoded.str());
    }
    else
        VALOG(MCuserError, format, args);

    va_end(args);
}

class StatsLogger : public WuScopeVisitorBase
{
public:
    virtual void noteStatistic(StatisticKind kind, unsigned __int64 value, IConstWUStatistic & cur) override
    {
        const char * scope = cur.queryScope();
        OwnedPTree tree = createPTree("stat", ipt_fast);
        tree->setProp("@kind", queryStatisticName(cur.getKind()));
        tree->setProp("@scope", scope);
        tree->setPropInt("@scopeType", (unsigned)cur.getScopeType());
        tree->setPropInt64("@value", cur.getValue());
        tree->setPropInt64("@max", cur.getMax());
        tree->setPropInt64("@count", cur.getCount());

        StringBuffer msg;
        toXML(tree, msg, 0, XML_Embed);
        fprintf(stderr, "%s\n", msg.str());
    }
};

void EclCompileInstance::logStats(bool logTimings)
{
    if (wu && wu->getDebugValueBool("logCompileStats", false))
    {
        //Following only produces output if the system has been compiled with TRANSFORM_STATS defined
        dbglogTransformStats(true);
    }

    if (logTimings)
    {
        const WuScopeFilter filter("props[stat]");
        StatsLogger logger;
        Owned<IConstWUScopeIterator> scopes = &wu->getScopeIterator(filter);
        ForEach(*scopes)
            scopes->playProperties(logger);
    }
}

bool EclCompileInstance::reportErrorSummary()
{
    if (errorProcessor->errCount() || errorProcessor->warnCount())
    {
        if (optXml)
            fprintf(errout, "<summary errors='%u' warnings='%u'/>\n", errorProcessor->errCount(), errorProcessor->warnCount());
        else
            fprintf(errout, "%d error%s, %d warning%s\n", errorProcessor->errCount(), errorProcessor->errCount()<=1 ? "" : "s",
                    errorProcessor->warnCount(), errorProcessor->warnCount()<=1?"":"s");
    }
    return errorProcessor->errCount() != 0;
}

void EclCompileInstance::noteCluster(const char *clusterName)
{
    eclcc.noteCluster(clusterName);
}

void EclCompileInstance::pushCluster(const char *clusterName)
{
    eclcc.pushCluster(clusterName);
}

void EclCompileInstance::popCluster()
{
    eclcc.popCluster();
}

unsigned EclCompileInstance::lookupClusterSize() const
{
    return eclcc.lookupClusterSize();
}

IInterface * EclCompileInstance::getGitUpdateLock(const char * key)
{
    return eclcc.getGitUpdateLock(key);
}


bool EclCompileInstance::allowAccess(const char * category, bool isSigned)
{
    return eclcc.allowAccess(category, isSigned);
}

IHqlExpression * EclCompileInstance::lookupDFSlayout(const char *filename, IErrorReceiver &errs, const ECLlocation &location, bool isOpt) const
{
    return eclcc.lookupDFSlayout(filename, errs, location, isOpt);
}

void EclCompileInstance::getTargetPlatform(StringBuffer & result)
{
    SCMStringBuffer targetText;
    wu->getDebugValue("targetClusterType", targetText);
    ClusterType clusterType = getClusterType(targetText.s.str());
    if (clusterType != NoCluster)
        result.append(clusterTypeString(clusterType, true));
    else
        return eclcc.getTargetPlatform(result);
}

void EclCC::appendNeverSimplifyList(const char *attribsList)
{
    const char * p = attribsList;
    while (*p)
    {
        StringBuffer attribRegex;
        if (*p == ',') p++;
        for (; *p && *p != ','; p++)
        {
            if (*p=='/' || *p=='.' || *p=='\\')
                attribRegex.append("\\.");
            else
                attribRegex.append(*p);
        }
        if (attribRegex.length() > 0)
        {
            if (neverSimplifyRegEx.length() > 0)
                neverSimplifyRegEx.append("|");
            // Match attribute and all child scopes
            neverSimplifyRegEx.append(attribRegex.str()).append("(\\..+)?");
        }
    }
}

void EclCC::noteCluster(const char *clusterName)
{
}

void EclCC::pushCluster(const char *clusterName)
{
    clusters.append(clusterName);
    prevClusterSize = -1;  // i.e. not cached
}

void EclCC::popCluster()
{
    clusters.pop();
    prevClusterSize = -1;  // i.e. not cached
}


bool EclCC::checkDaliConnected() const
{
    if (!daliConnected)
    {
        if (isEmptyString(optDFS) || disconnectReported)
            return false;

        try
        {
            Owned<IGroup> serverGroup = createIGroup(optDFS.str(), DALI_SERVER_PORT);
            if (!initClientProcess(serverGroup, DCR_EclCC, 0, NULL, NULL, optDaliTimeout))
            {
                disconnectReported = true;
                return false;
            }
            if (!optUser.isEmpty())
            {
                udesc.setown(createUserDescriptor());
                udesc->set(optUser, optPassword);
            }
        }
        catch (IException *E)
        {
            E->Release();
            disconnectReported = true;
            return false;
        }
        daliConnected = true;
    }
    return true;
}

unsigned EclCC::lookupClusterSize() const
{
    CriticalBlock b(dfsCrit);  // Overkill at present but maybe one day codegen will start threading? If it does the stack is also iffy!
#ifndef _CONTAINERIZED
    if (!checkDaliConnected())
        return 0;
#endif
    if (prevClusterSize != -1)
        return (unsigned) prevClusterSize;
    const char *cluster = clusters ? clusters.tos() : optCluster.str();
    if (isEmptyString(cluster) || strieq(cluster, "<unknown>"))
        prevClusterSize = 0;
    else
    {
#ifdef _CONTAINERIZED
        VStringBuffer xpath("queues[@name=\"%s\"]", cluster);
        IPropertyTree * queue = configuration->queryPropTree(xpath);
        if (queue)
            prevClusterSize = queue->getPropInt("@width", 1);
        else
            prevClusterSize = 0;
#else
        Owned<IConstWUClusterInfo> clusterInfo = getTargetClusterInfo(cluster);
        prevClusterSize = clusterInfo ? clusterInfo->getSize() : 0;
#endif
    }
    DBGLOG("Cluster %s has size %d", cluster, prevClusterSize);
    return prevClusterSize;
}

IInterface * EclCC::getGitUpdateLock(const char * path)
{
    if (optGitLock.isEmpty())
        return nullptr;

    VStringBuffer lockPath("/GitUpdateLocks/%s/hash%llx", optGitLock.str(), rtlHash64VStr(path, HASH64_INIT));

    CriticalBlock b(dfsCrit);
    if (!checkDaliConnected())
        return nullptr;

    DBGLOG("Get git update lock for '%s':'%s'", optGitLock.str(), path);
    const unsigned lockTimeout = 30 * 60 * 1000; // 30 minutes - fetches from git can take a long time
    const unsigned connectTimeout = 3 * 1000;
    unsigned traceTimeout = connectTimeout * 2;
    CCycleTimer elapsed;
    for (;;)
    {
        try
        {
            unsigned remaining = elapsed.remainingMs(lockTimeout);
            if (remaining == 0)
                break;

            Owned<IInterface> connection = querySDS().connect(lockPath, myProcessSession(), RTM_LOCK_WRITE|RTM_CREATE_QUERY, connectTimeout);
            if (connection)
                return connection.getClear();
        }
        catch (IException * e)
        {
            unsigned errcode = e->errorCode();
            e->Release();
            if (errcode != SDSExcpt_LockTimeout)
                break;
        }
        if (elapsed.elapsedMs() >= traceTimeout)
        {
            DBGLOG("Blocked waiting for a git update lock on '%s' for %u seconds", path, elapsed.elapsedMs() / 1000);
            traceTimeout *= 2;
        }
    }
    DBGLOG("Failed to get git update lock for '%s'", path);
    return nullptr;
}


IHqlExpression *EclCC::lookupDFSlayout(const char *filename, IErrorReceiver &errs, const ECLlocation &location, bool isOpt) const
{
    CriticalBlock b(dfsCrit);  // Overkill at present but maybe one day codegen will start threading?
    if (isEmptyString(optDFS) || disconnectReported)
    {
        // Dali lookup disabled, yet translation requested. Should we report if OPT set?
        if (!(optArchive || optGenerateDepend || optSyntax || optGenerateMeta || optEvaluateResult || disconnectReported))
        {
            VStringBuffer msg("Error looking up file %s in DFS - DFS not configured", filename);
            errs.reportWarning(CategoryDFS, HQLWRN_DFSlookupFailure, msg.str(), str(location.sourcePath), location.lineno, location.column, location.position);
            disconnectReported = true;
        }
        return nullptr;
    }
    if (!checkDaliConnected())
    {
        VStringBuffer msg("Error looking up file %s in DFS - failed to connect to %s", filename, optDFS.str());
        errs.reportError(HQLWRN_DFSlookupFailure, msg.str(), str(location.sourcePath), location.lineno, location.column, location.position);
        return nullptr;
    }
    // Do any scope manipulation
    StringBuffer lookupName;  // do NOT move inside the curly braces below - this needs to stay in scope longer than that
    if (filename[0]=='~')
        filename++;
    else if (!optScope.isEmpty())
    {
         lookupName.appendf("%s::%s", optScope.str(), filename);
         filename = lookupName.str();
    }

    // First lookup the name in our cache...
    Linked<IHqlExpression> ret = fileCache.getValue(filename);
    if (ret)
        return ret.getClear();

    int err = 0;
    OwnedHqlExpr diskRecord;

    // check the nohit cache...
    int *nohit = fileMissCache.getValue(filename);
    if (nohit)
        err = *nohit;
    else
    {
        // Look up the file in Dali
        try
        {
            Owned<IDistributedFile> dfsFile = wsdfs::lookup(filename, udesc, AccessMode::tbdRead, false, false, nullptr, defaultPrivilegedUser, INFINITE);
            if (dfsFile)
            {
                const char *recordECL = dfsFile->queryAttributes().queryProp("ECL");
                if (recordECL)
                {
                    MultiErrorReceiver errs;
                    diskRecord.setown(parseQuery(recordECL, &errs));
                    if (errs.errCount())
                        err = HQLWRN_DFSlookupInvalidRecord;
                    else
                    {
                        diskRecord.set(diskRecord->queryBody());  // Remove location info - it's meaningless
                        if (dfsFile->queryAttributes().hasProp("_record_layout"))
                        {
                            MemoryBuffer mb;
                            dfsFile->queryAttributes().getPropBin("_record_layout", mb);
                            diskRecord.setown(patchEclRecordDefinitionFromRecordLayout(diskRecord, mb));
                        }
                    }
                }
                else
                    err = HQLWRN_DFSlookupNoRecord;
            }
            else
                err = HQLWRN_DFSlookupNoFile;
        }
        catch (IException *E)
        {
            unsigned errCode = E->errorCode();
            if (errCode==DFSERR_LookupAccessDenied)
                err = HQLWRN_DFSdenied;
            else
                throw;  // Anything else is an internal error which will be caught elsewhere
        }
    }
    if (err)
    {
        // Report error, and add it to the nohit cache
        const char *reason = nullptr;
        switch (err)
        {
        case HQLWRN_DFSlookupInvalidRecord:
            reason = "invalid layout information found";
            break;
        case HQLWRN_DFSlookupNoRecord:
            reason = "no layout information found";
            break;
        case HQLWRN_DFSdenied:
            reason = "access denied";
            break;
        case HQLWRN_DFSlookupNoFile:
            if (!isOpt)
                reason = "file not found";
            break;
        }
        if (reason)
        {
            VStringBuffer msg("Error looking up file %s in DFS - %s", filename, reason);
            errs.reportWarning(CategoryDFS, err, msg.str(), str(location.sourcePath), location.lineno, location.column, location.position);
        }
        if (!nohit)
            fileMissCache.setValue(filename, err);
        return nullptr;
    }
    assertex(diskRecord);
    // Add it to the cache
    fileCache.setValue(filename, diskRecord);
    return diskRecord.getClear();
}

bool EclCC::allowAccess(const char * category, bool isSigned)
{
    ForEachItemIn(idx1, deniedPermissions)
    {
        if (stricmp(deniedPermissions.item(idx1), category)==0)
            return false;
    }
    ForEachItemIn(idx2, allowSignedPermissions)
    {
        if (stricmp(allowSignedPermissions.item(idx2), category)==0)
            return isSigned;
    }
    ForEachItemIn(idx3, allowedPermissions)
    {
        if (stricmp(allowedPermissions.item(idx3), category)==0)
            return true;
    }
    return defaultAllowed[isSigned];
}

void EclCC::getTargetPlatform(StringBuffer & result)
{
    result.append(clusterTypeString(optTargetClusterType, true));
}

//=========================================================================================
int EclCC::parseCommandLineOptions(int argc, const char* argv[])
{
    if (argc < 2)
    {
        usage();
        return 1;
    }

    ArgvIterator iter(argc, argv);
    StringAttr tempArg;
    bool tempBool;
    bool showHelp = false;
    unsigned tempUnsigned;
    for (; !iter.done(); iter.next())
    {
        const char * arg = iter.query();
        if (iter.matchFlag(tempArg, "-a"))
        {
            applicationOptions.append(tempArg);
        }
        else if (iter.matchOption(tempArg, "--allow"))
        {
            allowedPermissions.append(tempArg);
        }
        else if (iter.matchOption(tempArg, "--allowsigned"))
        {
            if (stricmp(tempArg, "all")==0)
                defaultAllowed[true] = true;
            else
                allowSignedPermissions.append(tempArg);
        }
        else if (iter.matchFlag(optBatchMode, "-b"))
        {
        }
        else if (iter.matchOption(tempArg, "-brk"))
        {
#if defined(_WIN32) && defined(_DEBUG)
            unsigned id = atoi(tempArg);
            if (id == 0)
                DebugBreak();
            else
                _CrtSetBreakAlloc(id);
#endif
        }
        else if (iter.matchFlag(optOnlyCompile, "-c"))
        {
        }
        else if (iter.matchFlag(optCheckEclVersion, "-checkVersion"))
        {
        }
        else if (iter.matchFlag(optCheckDirty, "-checkDirty"))
        {
        }
        else if (iter.matchFlag(optCleanRepos, "--cleanrepos"))
        {
        }
        else if (iter.matchFlag(optCleanInvalidRepos, "--cleaninvalidrepos"))
        {
        }
        else if (iter.matchOption(optCluster, "-cluster"))
        {
        }
        else if (iter.matchOption(optConfig, "--config"))
        {
        }
        else if (iter.matchOption(tempArg, "--daemon"))
        {
            //Ignore any --daemon option supplied to eclccserver which may be passed onto eclcc
        }
        else if (iter.matchOption(optDefaultGitPrefix, "--defaultgitprefix"))
        {
        }
        else if (iter.matchOption(optDefaultRepo, "--defaultrepo"))
        {
        }
        else if (iter.matchOption(optDefaultRepoVersion, "--defaultrepoversion"))
        {
        }
        else if (iter.matchOption(optDFS, "-dfs") || /*deprecated*/ iter.matchOption(optDFS, "-dali"))
        {
            // Note - we wait until first use before actually connecting to dali
        }
        else if (iter.matchOption(optDaliTimeout, "--dfs-timeout") || /*deprecated*/ iter.matchOption(optDaliTimeout, "--dali-timeout"))
        {
        }
        else if (iter.matchOption(optUser, "-user"))
        {
        }
        else if (iter.matchOption(tempArg, "-password"))
        {
            if (tempArg.isEmpty())
            {
                StringBuffer pw;
                passwordInput("Password: ", pw);
                optPassword.set(pw);
            }
            else
                optPassword.set(tempArg);
        }
        else if (iter.matchOption(tempArg, "-token"))
        {
            // For use by eclccserver - not documented in usage()
            StringBuffer wuid,user;
            extractFromWorkunitDAToken(tempArg, &wuid, &user,nullptr);
            optWUID.set(wuid.str());
            optUser.set(user.str());
        }
        else if (iter.matchOption(optWUID, "-wuid"))
        {
            // For use by eclccserver - not documented in usage()
        }
        else if (iter.matchFlag(optCheckIncludePaths, "--checkIncludePaths"))
        {
            //Only here to provide backward compatibility for the include path checking if it proves to cause issues.
        }
        else if (iter.matchOption(tempArg, "--deny"))
        {
            if (stricmp(tempArg, "all")==0)
            {
                defaultAllowed[false] = false;
                defaultAllowed[true] = false;
            }
            else
                deniedPermissions.append(tempArg);
        }
        else if (iter.matchFlag(tempArg, "-D"))
        {
            definitions.append(tempArg);
        }
        else if (iter.matchFlag(optArchive, "-E"))
        {
        }
        else if (iter.matchOption(optExpandPath, "--expand"))
        {
        }
        else if (iter.matchFlag(tempArg, "-f"))
        {
            debugOptions.append(tempArg);
        }
        else if (iter.matchFlag(optFastSyntax, "--fastsyntax"))
        {
        }
        else if (iter.matchFlag(optFetchRepos, "--fetchrepos"))
        {
        }
        else if (iter.matchFlag(tempBool, "-g") || iter.matchFlag(tempBool, "--debug"))
        {
            if (tempBool)
            {
                debugOptions.append("debugQuery");
                debugOptions.append("saveCppTempFiles");
            }
            else
                debugOptions.append("debugQuery=0");
        }
        else if (strcmp(arg, "-internal")==0)
        {
            outputSizeStmts();
            int error = testHqlInternals() + testReservedWords();  //NOTE: testReservedWords() depends on testHqlInternals() so must be be called after.
            // report test result
            if (error)
            {
                printf("%d error%s found!\n", error, error<=1?"":"s");
                return 300;
            }
            else
                printf("No errors\n");
        }
        else if (iter.matchFlag(optXml, "--xml"))
        {
        }
        else if (iter.matchFlag(tempBool, "-save-cpps"))
        {
            setDebugOption("saveCppTempFiles", tempBool);
        }
        else if (iter.matchFlag(tempBool, "-save-temps"))
        {
            setDebugOption("saveEclTempFiles", tempBool);
        }
        else if (iter.matchOption(tempArg, "-scope"))
        {
            optScope.set(tempArg);
        }
        else if (iter.matchOption(optGitLock, "--gitlock"))
        {
        }
        else if (iter.matchOption(optGitUser, "--gituser"))
        {
        }
        else if (iter.matchOption(optGitPasswordPath, "--gitpasswordpath"))
        {
            //This option is primarily to help debug the git authentication, unlikely to be used by end users.
        }
        else if (iter.matchFlag(showHelp, "-help") || iter.matchFlag(showHelp, "--help"))
        {
        }
        else if (iter.matchPathFlag(includeLibraryPath, "-I"))
        {
        }
        else if (iter.matchFlag(optIgnoreUnknownImport, "--ignoreunknownimport"))
        {
        }
        else if (iter.matchOption(tempArg, "--jobid"))
        {
            setDefaultJobName(tempArg);
        }
        else if (iter.matchFlag(optKeywords, "--keywords"))
        {
        }
        else if (iter.matchFlag(optLeakCheck, "--leakcheck"))
        {
        }
        else if (iter.matchFlag(tempArg, "-L"))
        {
            libraryPaths.append(tempArg);
        }
        else if (iter.matchFlag(tempBool, "-legacy"))
        {
            optLegacyImport = tempBool;
            optLegacyWhen = tempBool;
        }
        else if (iter.matchFlag(optLegacyImport, "-legacyimport"))
        {
        }
        else if (iter.matchFlag(optLegacyWhen, "-legacywhen"))
        {
        }
        else if (iter.matchOption(optLogfile, "--logfile"))
        {
        }
        else if (iter.matchFlag(optNoLogFile, "--nologfile"))
        {
        }
        else if (iter.matchFlag(optLogToStdOut, "--logtostdout"))
        {
        }
        else if (iter.matchFlag(optIgnoreSignatures, "--nogpg"))
        {
        }
        else if (iter.matchFlag(optNoStdInc, "--nostdinc"))
        {
        }
        else if (iter.matchFlag(optNoBundles, "--nobundles"))
        {
        }
        else if (iter.matchOption(tempUnsigned, "--logdetail")) // Now ignored
        {
        }
        else if (iter.matchOption(optMonitorInterval, "--monitorinterval"))
        {
        }
        else if (iter.matchOption(tempArg, "-main") || iter.matchOption(tempArg, "--main"))
        {
            const char * arg = tempArg;
            const char * at = strchr(arg, '@');
            const char * hash = strchr(arg, '#');
            if (at)
            {
                optQueryMainAttribute.set(arg, at - arg);
                optQueryMainPackage.set(at+1);
                optExplicitMainPackage = true;
            }
            else if (hash)
            {
                optQueryMainAttribute.set(arg, hash - arg);
                optQueryMainPackageVersion.set(hash+1);
            }
            else
            {
                optQueryMainAttribute.set(arg);
                optQueryMainPackage.set(nullptr);
            }
        }
        else if (iter.matchOption(tempArg, "--mainrepo"))
        {
            //--mainrepo only provides a default - it does not override an explicit package specified by --main
            //but does override a previous setting of --mainrepo
            if (!optExplicitMainPackage)
                optQueryMainPackage.set(tempArg);
        }
        else if (iter.matchOption(optQueryMainPackageVersion, "--mainrepoversion"))
        {
        }
        else if (iter.matchFlag(optDebugMemLeak, "-m"))
        {
        }
        else if (iter.matchFlag(optIncludeMeta, "-meta") || iter.matchFlag(optIncludeMeta, "--meta"))
        {
        }
        else if (iter.matchOption(tempArg, "--metacache"))
        {
            if (!tempArg.isEmpty())
                optMetaLocation.set(tempArg);
            else
                optMetaLocation.clear();
        }
        else if (iter.matchOption(tempArg, "--neversimplify"))
        {
            appendNeverSimplifyList(tempArg);
        }
        else if (iter.matchFlag(optGenerateMeta, "-M"))
        {
        }
        else if (iter.matchFlag(optGenerateDepend, "-Md"))
        {
        }
        else if (iter.matchFlag(optEvaluateResult, "-Me"))
        {
        }
        else if (iter.matchFlag(optNoSourcePath, "--nosourcepath"))
        {
        }
        else if (iter.matchFlag(optOutputFilename, "-o"))
        {
        }
        else if (iter.matchFlag(optOutputDirectory, "-P"))
        {
        }
        else if (iter.matchFlag(optGenerateHeader, "-pch"))
        {
        }
        else if (iter.matchFlag(optPruneArchive, "--prunearchive"))
        {
        }
        else if (iter.matchOption(optComponentName, "--component"))
        {
        }
        else if (iter.matchFlag(optSaveQueryText, "-q"))
        {
        }
        else if (iter.matchFlag(optSaveQueryArchive, "-qa"))
        {
        }
        else if (iter.matchOption(tempArg, "--repocachepath"))
        {
            eclRepoPath.set(tempArg);
        }
        else if (iter.matchFlag(optNoCompile, "-S"))
        {
        }
        else if (iter.matchOption(optCompileBatchOut, "-Sx"))
        {
        }
        else if (iter.matchFlag(optShared, "-shared"))
        {
        }
        else if (iter.matchFlag(tempBool, "-syntax"))
        {
            optSyntax = tempBool;
            setDebugOption("syntaxCheck", tempBool);
        }
        else if (iter.matchOption(optMaxErrors, "--maxErrors"))
        {
        }
        else if (iter.matchFlag(optUnsuppressImmediateSyntaxErrors, "--unsuppressImmediateSyntaxErrors"))
        {
        }
        else if (iter.matchOption(optIniFilename, "-specs"))
        {
            if (!checkFileExists(optIniFilename))
            {
                traceError("Error: INI file '%s' does not exist",optIniFilename.get());
                return 1;
            }
        }
        else if (iter.matchFlag(optShowPaths, "-showpaths"))
        {
        }
        else if (iter.matchOption(optManifestFilename, "-manifest"))
        {
            if (!isManifestFileValid(optManifestFilename))
                return 1;
        }
        else if (iter.matchOption(tempArg, "-split"))
        {
            batchPart = atoi(tempArg)-1;
            const char * split = strchr(tempArg, ':');
            if (!split)
            {
                UERRLOG("Error: syntax is -split=part:splits\n");
                return 1;
            }
            batchSplit = atoi(split+1);
            if (batchSplit == 0)
                batchSplit = 1;
            if (batchPart >= batchSplit)
                batchPart = 0;
        }
        else if (iter.matchFlag(logTimings, "--timings"))
        {
        }
        else if (iter.matchOption(tempArg, "-platform") || /*deprecated*/ iter.matchOption(tempArg, "-target"))
        {
            if (!setTargetPlatformOption(tempArg.get(), optTargetClusterType))
                return 1;
        }
        else if (iter.matchFlag(optTraceCache, "--tracecache"))
        {
        }
        else if (iter.matchFlag(optVerifySimplified, "--internalverifysimplified"))
        {
        }
        else if (iter.matchFlag(optRegenerateCache, "--regeneratecache"))
        {
        }
        else if (iter.matchFlag(tempArg, "-R"))
        {
            if (!strchr(tempArg, '='))
                throw MakeStringException(99, "'-R%s' should have form -Rrepo[#version]=path", tempArg.str());
            repoMappings.append(tempArg);
        }
        else if (iter.matchFlag(optIgnoreCache, "--internalignorecache"))
        {
        }
        else if (iter.matchFlag(optIgnoreSimplified, "--ignoresimplified"))
        {
        }
        else if (iter.matchFlag(optExtraStats, "--internalextrastats"))
        {
        }
        else if (iter.matchFlag(optUpdateRepos, "--updaterepos"))
        {
        }
        else if (iter.matchFlag(logVerbose, "-v") || iter.matchFlag(logVerbose, "--verbose"))
        {
            Owned<ILogMsgFilter> filter = getDefaultLogMsgFilter();
            queryLogMsgManager()->changeMonitorFilter(queryStderrLogMsgHandler(), filter);
        }
        else if (strcmp(arg, "--version")==0)
        {
            fprintf(stdout,"%s %s\n", LANGUAGE_VERSION, hpccBuildInfo.buildTag);
            return 1;
        }
        else if (startsWith(arg, "-Wc,"))
        {
            expandCommaList(compileOptions, arg+4);
        }
        else if (startsWith(arg, "-Wl,"))
        {
            //Pass these straight through to the linker - with -Wl, prefix removed
            linkOptions.append(arg+4);
        }
        else if (startsWith(arg, "-Wp,") || startsWith(arg, "-Wa,"))
        {
            //Pass these straight through to the gcc compiler
            compileOptions.append(arg);
        }
        else if (iter.matchFlag(optWorkUnit, "-wu"))
        {
        }
        else if (iter.matchFlag(tempArg, "-w"))
        {
            //Any other option beginning -wxxx are treated as warning mappings
            warningMappings.append(tempArg);
        }
        else if (strcmp(arg, "-")==0)
        {
            inputFileNames.append("stdin:");
        }
        else if (iter.matchFlag(tempArg, "--logging.postMortem"))
        {
            // Ignore, but may be present
        }
        else if (arg[0] == '-')
        {
            //If --config has been specified, then ignore any unknown options beginning with -- since they will be added to the globals.
            if ((arg[1] == '-') && optConfig)
                continue;
            traceError("Error: unrecognised option %s",arg);
            usage();
            return 1;
        }
        else
            inputFileNames.append(arg);
    }
    if (showHelp)
    {
        usage();
        return 1;
    }

    if (optComponentName.length())
        setStatisticsComponentName(SCTeclcc, optComponentName, false);
    else
        setStatisticsComponentName(SCTeclcc, "eclcc", false);

    // Option post processing follows:
    if (optArchive || optWorkUnit || optGenerateMeta || optGenerateDepend || optShowPaths)
    {
        optNoCompile = true;
        optIgnoreSignatures = true;
    }

    // If a default version is explicitly given it takes precedence over the version provided in optDefaultRepo
    // ensure optDefaultRepo is fully qualified, and optDefaultRepoVersion is consistent
    if (!optDefaultRepo.isEmpty())
    {
        StringBuffer temp;
        const char * repo = optDefaultRepo.str();
        const char * hash = strchr(repo, '#');
        if (hash)
        {
            if (!optDefaultRepoVersion.isEmpty())
            {
                //Unusual situation: version provided in default and explicitly, but resolve it consistently
                //An explicit --defaultrepoversion takes precedence over any default in the repo stringe
                optDefaultRepo.set(temp.clear().append(hash-repo, repo).append("#").append(optDefaultRepoVersion));
            }
            else
            {
                //Extract the default version from the version provided to --defaultrepo
                optDefaultRepoVersion.set(hash+1);
            }
        }
        else if (!optDefaultRepoVersion.isEmpty())
            optDefaultRepo.set(temp.clear().append(optDefaultRepo).append("#").append(optDefaultRepoVersion));
    }

    // Rules for the repo used if --main has been specified:
    //   If no repo is specified then use the default repoistory and version
    //   If repo is specified with no version then use the default repo
    //   If main repoversion is specified then that takes precedence.
    // Set up optQueryMainPackage. (optQueryMainPackageVersion does not need to be updated.)
    if (optQueryMainPackage.isEmpty())
        optQueryMainPackage.append(optDefaultRepo);

    if (!optQueryMainPackage.isEmpty())
    {
        const char * repo = optQueryMainPackage.str();
        const char * hash = strchr(repo, '#');
        const char * newVersion = nullptr;
        if (hash)
        {
            //only thing that takes precedence is optQueryMainPackageVersion
            if (!optQueryMainPackageVersion.isEmpty())
            {
                optQueryMainPackage.setLength(hash-repo); // Remove the version - ready for replacing below.
                newVersion = optQueryMainPackageVersion;
            }
        }
        else if (!optQueryMainPackageVersion.isEmpty())
            newVersion = optQueryMainPackageVersion.str();
        else if (!optDefaultRepoVersion.isEmpty())
            newVersion = optDefaultRepoVersion.str();

        if (newVersion)
            optQueryMainPackage.append("#").append(newVersion);
    }

    optReleaseAllMemory = optDebugMemLeak || optLeakCheck;
    loadManifestOptions();

    if (optDebugMemLeak)
    {
        StringBuffer title;
        title.append(inputFileNames.item(0)).newline();
        initLeakCheck(title);
    }

    setTraceCache(optTraceCache);

    if (inputFileNames.ordinality() == 0 && !optKeywords)
    {
        if (optGenerateHeader || optShowPaths || (!optBatchMode && optQueryMainAttribute))
            return 0;
        UERRLOG("No input filenames supplied");
        return 1;
    }
    return 0;
}

void EclCC::setSecurityOptions()
{
    Owned<IPropertyTree> eclSecurity = configuration->getPropTree("eclSecurity");
    if (eclSecurity)
    {
        // Name of security option in configuration yaml
        const char * configName[] = {"@embedded", "@pipe", "@extern", "@datafile" };
        // Name of security option used internally
        const char * securityOption[] = {"cpp", "pipe", "extern", "datafile" };
        for (int i=0; i < 4; i++)
        {
            const char * optVal = eclSecurity->queryProp(configName[i]);
            if (optVal)
            {
                if (!strcmp(optVal, "allow"))
                    allowedPermissions.append(securityOption[i]);
                else if (!strcmp(optVal, "deny"))
                    deniedPermissions.append(securityOption[i]);
                else if (!strcmp(optVal, "allowSigned"))
                    allowSignedPermissions.append(securityOption[i]);
            }
        }
    }
}
//=========================================================================================



void EclCC::usage()
{
    for (unsigned line=0; line < _elements_in(helpText); line++)
    {
        const char * text = helpText[line];
        StringBuffer wsPrefix;
        if (*text == '?')  //NOTE: '?' indicates eclcmd usage so don't print.
        {
            text = text+1;
            if (*text == ' ' || ( *text == '!' && text[1] == ' '))
                wsPrefix.append(' ');
        }
        if (*text == '!')
        {
            if (logVerbose)
            {
                text = text+1;
                if (*text == ' ')
                    wsPrefix.append(' ');
                fprintf(stdout, "%s%s\n", wsPrefix.str(), text);
            }
        }
        else
            fprintf(stdout, "%s%s\n", wsPrefix.str(), text);
    }
}

//=========================================================================================

// The following methods are concerned with running eclcc in batch mode (primarily to aid regression testing)
void EclCC::processBatchedFile(IFile & file, bool multiThreaded)
{
    StringBuffer basename, logFilename, xmlFilename, outFilename, metaFilename;

    splitFilename(file.queryFilename(), NULL, NULL, &basename, &basename);
    addNonEmptyPathSepChar(logFilename.append(optOutputDirectory)).append(basename).append(".log");
    addNonEmptyPathSepChar(xmlFilename.append(optOutputDirectory)).append(basename).append(".xml");
    addNonEmptyPathSepChar(metaFilename.append(optOutputDirectory)).append(basename).append(".meta");

    splitFilename(file.queryFilename(), NULL, NULL, &outFilename, &outFilename);

    unsigned startTime = msTick();
    FILE * logFile = fopen(logFilename.str(), "w");
    if (!logFile)
        throw MakeStringException(99, "couldn't create log output %s", logFilename.str());

    Owned<ILogMsgHandler> handler;
    try
    {
        // Print compiler and arguments to help reproduce problems
        for (int i=0; i<argc; i++)
            fprintf(logFile, "%s ", argv[i]);
        fprintf(logFile, "\n");
        fprintf(logFile, "--- %s --- \n", basename.str());
        {
            if (!multiThreaded)
            {
                handler.setown(getHandleLogMsgHandler(logFile, 0, LOGFORMAT_table));
                Owned<ILogMsgFilter> filter = getCategoryLogMsgFilter(MSGAUD_all, MSGCLS_all, DefaultDetail);
                queryLogMsgManager()->addMonitor(handler, filter);

                resetUniqueId();
                resetLexerUniqueNames();
            }

            Owned<IErrorReceiver> localErrs = createFileErrorReceiver(logFile);
            EclCompileInstance info(*this, &file, *localErrs, logFile, outFilename, optLegacyImport, optLegacyWhen, optIgnoreSignatures, optIgnoreUnknownImport, optXml);
            info.metaOutputFilename.set(metaFilename);
            processFile(info);
            if (info.wu &&
                (info.wu->getDebugValueBool("generatePartialOutputOnError", false) || info.queryErrorProcessor().errCount() == 0))
            {
                exportWorkUnitToXMLFile(info.wu, xmlFilename, XML_NoBinaryEncode64, true, false, false, true);
                Owned<IFile> xml = createIFile(xmlFilename);
                info.stats.xmlSize = xml->size();
            }

            info.logStats(logTimings);
        }
    }
    catch (IException * e)
    {
        StringBuffer s;
        e->errorMessage(s);
        e->Release();
        fprintf(logFile, "Unexpected exception: %s", s.str());
    }
    if (handler)
    {
        queryLogMsgManager()->removeMonitor(handler);
        handler.clear();
    }

    fflush(logFile);
    fclose(logFile);

    unsigned nowTime = msTick();
    StringBuffer s;
    s.append(basename).append(":");
    s.padTo(50);
    s.appendf("%8d ms\n", nowTime-startTime);
    fprintf(batchLog, "%s", s.str());
//  fflush(batchLog);
}


typedef SafeQueueOf<IFile, true> RegressQueue;
class BatchThread : public Thread
{
public:
    BatchThread(EclCC & _compiler, RegressQueue & _queue, Semaphore & _fileReady)
        : compiler(_compiler), queue(_queue), fileReady(_fileReady)
    {
    }
    virtual int run()
    {
        for (;;)
        {
            fileReady.wait();
            IFile * next = queue.dequeue();
            if (!next)
                return 0;
            compiler.processBatchedFile(*next, true);
            next->Release();
        }
    }
protected:
    EclCC & compiler;
    RegressQueue & queue;
    Semaphore & fileReady;
};

int compareFilenames(IInterface * const * pleft, IInterface * const * pright)
{
    IFile * left = static_cast<IFile *>(*pleft);
    IFile * right = static_cast<IFile *>(*pright);

    return stricmp(pathTail(left->queryFilename()), pathTail(right->queryFilename()));
}


void EclCC::processBatchFiles()
{
    Thread * * threads = NULL;
    RegressQueue queue;
    Semaphore fileReady;
    unsigned startAllTime = msTick();
    if (optThreads > 0)
    {
        threads = new Thread * [optThreads];
        for (unsigned i = 0; i < optThreads; i++)
        {
            threads[i] = new BatchThread(*this, queue, fileReady);
            threads[i]->start(false);
        }
    }

    StringBuffer batchLogName;
    addNonEmptyPathSepChar(batchLogName.append(optOutputDirectory)).append("_batch_.");
    batchLogName.append(batchPart+1);
    batchLogName.append(".log");

    batchLog = fopen(batchLogName.str(), "w");
    if (!batchLog)
        throw MakeStringException(99, "couldn't create log output %s", batchLogName.str());

    //Divide the files up based on file size, rather than name
    inputFiles.sort(compareFilenames);
    unsigned __int64 totalSize = 0;
    ForEachItemIn(iSize, inputFiles)
    {
        IFile & cur = inputFiles.item(iSize);
        totalSize += cur.size();
    }

    //Sort the filenames so you have a consistent order between windows and linux

    unsigned __int64 averageFileSize = totalSize / inputFiles.ordinality();
    unsigned splitter = 0;
    unsigned __int64 sizeSoFar = 0;
    ForEachItemIn(i, inputFiles)
    {
        IFile &file = inputFiles.item(i);
        if (splitter == batchPart)
        {
            if (optThreads > 0)
            {
                queue.enqueue(LINK(&file));
                fileReady.signal();
            }
            else
                processBatchedFile(file, false);
        }

        unsigned __int64 thisSize = file.size();
        sizeSoFar += thisSize;
        if (sizeSoFar > averageFileSize)
        {
            sizeSoFar = 0;
            splitter++;
        }
        if (splitter == batchSplit)
            splitter = 0;
    }

    if (optThreads > 0)
    {
        for (unsigned i = 0; i < optThreads; i++)
            fileReady.signal();
        for (unsigned j = 0; j < optThreads; j++)
            threads[j]->join();
        for (unsigned i2 = 0; i2 < optThreads; i2++)
            threads[i2]->Release();
        delete [] threads;
    }

    fprintf(batchLog, "@%5ds total time for part %d\n", (msTick()-startAllTime)/1000, batchPart);
    fclose(batchLog);
    batchLog = NULL;
}

bool EclCC::printKeywordsToXml()
{
    if(!optKeywords)
        return false;

    ::printKeywordsToXml();
    return true;
}
