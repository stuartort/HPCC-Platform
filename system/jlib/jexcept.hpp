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



#ifndef __JEXCEPT__
#define __JEXCEPT__

#include <functional>

#include "jiface.hpp"
#include "jlib.hpp"
#include "errno.h"

jlib_decl const char* serializeMessageAudience(MessageAudience ma);
jlib_decl MessageAudience deserializeMessageAudience(const char* text);
jlib_decl void setBacktraceOnAssert(bool value);

//the following interface to be thrown when a user command explicitly calls for a failure

interface jlib_thrown_decl IUserException : public IException
{
};

//the following interface defines a collection of exceptions
//
interface jlib_thrown_decl IMultiException : extends IException
{
   //convenience methods for handling this as an array
   virtual aindex_t ordinality() const          = 0;
   virtual IException& item(aindex_t pos) const = 0;
    virtual const char* source() const              = 0;

   //for complete control...
   virtual IArrayOf<IException>& getArray()= 0;

   //add another exception
   virtual void append(IException& e) = 0;
   virtual void append(IMultiException& e) = 0;

   virtual StringBuffer& serialize(StringBuffer& ret, unsigned indent = 0, bool simplified=false, bool root=true) const = 0;
   virtual StringBuffer& serializeJSON(StringBuffer& ret, unsigned indent = 0, bool simplified=false, bool root=true, bool enclose=false) const = 0;
   virtual void deserialize(const char* xml) = 0; //throws IException on failure!

   //the following methods override those in IIException
   // 
    virtual int errorCode() const = 0;
    virtual StringBuffer&   errorMessage(StringBuffer &msg) const = 0;
    virtual MessageAudience errorAudience() const = 0;
};

IMultiException jlib_decl *makeMultiException(const char* source = NULL);

interface IExceptionHandler
{
   virtual bool fireException(IException *e) = 0;
};

IException jlib_decl *makeStringExceptionV(int code, const char *why, ...) __attribute__((format(printf, 2, 3)));
IException jlib_decl *makeStringExceptionVA(int code, const char *why, va_list args) __attribute__((format(printf, 2, 0)));
IException jlib_decl *makeStringException(int code, const char *why);
IException jlib_decl *makeStringExceptionV(MessageAudience aud, int code, const char *why, ...) __attribute__((format(printf, 3, 4)));
IException jlib_decl *makeStringExceptionVA(MessageAudience aud, int code, const char *why, va_list args) __attribute__((format(printf, 3, 0)));
IException jlib_decl *makeStringException(MessageAudience aud, int code, const char *why);
IException jlib_decl *makePrefixedException(const char * prefix, const IException * e);
__declspec(noreturn) void jlib_decl throwStringExceptionV(int code, const char *format, ...) __attribute__((format(printf, 2, 3), noreturn));
IException jlib_decl *makeWrappedException(IException *e, int code, const char *why);
IException jlib_decl *makeWrappedExceptionVA(IException *e, int code, const char *why, va_list args) __attribute__((format(printf, 3, 0)));
IException jlib_decl *makeWrappedExceptionV(IException *e, int code, const char *why, ...) __attribute__((format(printf, 3, 4)));

// Macros for legacy names of above functions

#define MakeMultiException makeMultiException
#define MakeStringException makeStringExceptionV
#define MakeStringExceptionVA makeStringExceptionVA
#define MakeStringExceptionDirect makeStringException
#define ThrowStringException throwStringExceptionV

interface jlib_thrown_decl IOSException: extends IException{};
IOSException jlib_decl *makeOsException(int code);
IOSException jlib_decl *makeOsException(int code, const char *msg);
IOSException jlib_decl *makeOsExceptionV(int code, const char *msg, ...) __attribute__((format(printf, 2, 3)));

#define DISK_FULL_EXCEPTION_CODE ENOSPC

interface jlib_thrown_decl IErrnoException: extends IException{};
IErrnoException jlib_decl *makeErrnoException(int errn, const char *why);
IErrnoException jlib_decl *makeErrnoException(const char *why);
IErrnoException jlib_decl *makeErrnoExceptionV(int errn, const char *why, ...) __attribute__((format(printf, 2, 3)));
IErrnoException jlib_decl *makeErrnoExceptionV(const char *why, ...) __attribute__((format(printf, 1, 2)));
IErrnoException jlib_decl *makeErrnoException(MessageAudience aud, int errn, const char *why);
IErrnoException jlib_decl *makeErrnoExceptionV(MessageAudience aud, int errn, const char *why, ...) __attribute__((format(printf, 3, 4)));
IErrnoException jlib_decl *makeErrnoExceptionV(MessageAudience aud, const char *why, ...) __attribute__((format(printf, 2, 3)));

void jlib_decl pexception(const char *msg,IException *e); // like perror except for exceptions
jlib_decl StringBuffer & formatSystemError(StringBuffer & out, unsigned errcode);

void userBreakpoint();

interface jlib_thrown_decl ISEH_Exception : extends IException
{
};

interface jlib_thrown_decl IOutOfMemException: extends IException
{
};


void  jlib_decl enableSEHtoExceptionMapping();
void  jlib_decl disableSEHtoExceptionMapping();
// NB only enables for current thread or threads started after call
// requires /EHa option to be set in VC++ options (after /GX)
// Macros for legacy names of above functions
#define EnableSEHtoExceptionMapping enableSEHtoExceptionMapping
#define DisableSEHtoExceptionMapping disableSEHtoExceptionMapping

void jlib_decl *setSEHtoExceptionHandler(IExceptionHandler *handler); // sets handler and return old value

void jlib_decl raiseSignalInFuture(int signo, unsigned timeoutSec);

void jlib_decl setTerminateOnSEHInSystemDLLs(bool set=true);
void jlib_decl setTerminateOnSEH(bool set=true);

void jlib_decl setProcessAborted(bool _abortVal);

__declspec(noreturn) void jlib_decl throwUnexpectedException(const char * function, const char * file, unsigned line) __attribute__((noreturn));
__declspec(noreturn) void jlib_decl throwUnexpectedException(const char * what, const char * function, const char * file, unsigned line) __attribute__((noreturn));

const char jlib_decl *sanitizeSourceFile(const char *file);

#define makeUnexpectedException()  makeStringExceptionV(9999, "Internal Error in %s() at %s(%d)", __func__, sanitizeSourceFile(__FILE__), __LINE__)
#define throwUnexpected()          throwUnexpectedException(__func__, sanitizeSourceFile(__FILE__), __LINE__)
#define throwUnexpectedX(x)        throwUnexpectedException(x, __func__, sanitizeSourceFile(__FILE__), __LINE__)
#define assertThrow(x)             assertex(x)

__declspec(noreturn) void jlib_decl throwUnimplementedException(const char * function, const char * file, unsigned line) __attribute__((noreturn));
__declspec(noreturn) void jlib_decl throwUnimplementedException(const char * what, const char * function, const char * file, unsigned line) __attribute__((noreturn));
__declspec(noreturn) void jlib_decl throwUnimplementedException(const char * what, const char *what2, const char * function, const char * file, unsigned line) __attribute__((noreturn));
#define throwUnimplemented()        throwUnimplementedException(__func__, sanitizeSourceFile(__FILE__), __LINE__)
#define throwUnimplementedX(x)      throwUnimplementedException(x, __func__, sanitizeSourceFile(__FILE__), __LINE__)

#define UNIMPLEMENTED throwUnimplementedException(__func__, sanitizeSourceFile(__FILE__), __LINE__)
#define UNIMPLEMENTED_C throwUnimplementedException("CLASSTYPE:", typeid(*this).name(), __func__, sanitizeSourceFile(__FILE__), __LINE__)
#define UNIMPLEMENTED_X(reason) throwUnimplementedException(reason, __func__, sanitizeSourceFile(__FILE__), __LINE__)
#define UNIMPLEMENTED_XY(a,b) throwUnimplementedException(a, b, __func__, sanitizeSourceFile(__FILE__), __LINE__)

IException jlib_decl * deserializeException(MemoryBuffer & in); 
void jlib_decl serializeException(IException * e, MemoryBuffer & out); 

void  jlib_decl printStackReport(__int64 startIP = 0);
// Macro for legacy name of above function
#define PrintStackReport printStackReport

bool jlib_decl getAllStacks(StringBuffer &output);
unsigned jlib_decl getCommandOutput(StringBuffer &output, const char *cmd, const char *cmdTitle=nullptr, const char *allowedPrograms=nullptr);
bool jlib_decl getDebuggerGetStacksCmd(StringBuffer &output);

#ifdef _DEBUG
#define RELEASE_CATCH_ALL       int*********
#else
#define RELEASE_CATCH_ALL       ...
#endif

//These are used in several places to wrap error reporting, to keep error numbers+text together.  E.g.,
//#define XYZfail 99    #define XXZfail_Text "Failed"     throwError(XYZfail)
#define throwError(x)                           throwStringExceptionV(x, (x ## _Text))
#define throwError1(x,a)                        throwStringExceptionV(x, (x ## _Text), a)
#define throwError2(x,a,b)                      throwStringExceptionV(x, (x ## _Text), a, b)
#define throwError3(x,a,b,c)                    throwStringExceptionV(x, (x ## _Text), a, b, c)
#define throwError4(x,a,b,c,d)                  throwStringExceptionV(x, (x ## _Text), a, b, c, d)

//---------------------------------------------------------------------------------------------------------------------

//These values are persisted - so should not be reordered.
enum ErrorSeverity
{
    SeverityInformation = 0,
    SeverityWarning = 1,
    SeverityError = 2,
    SeverityAlert = 3,
    SeverityIgnore = 4,
    SeverityFatal = 5,      // a fatal error - can't be mapped to anything else
    SeverityUnknown,
    SeverityMax = SeverityUnknown
};

inline bool isError(ErrorSeverity severity) { return severity == SeverityError || severity == SeverityFatal; }
inline bool isFatal(ErrorSeverity severity) { return severity == SeverityFatal; }

//TBD in a separate commit - add support for warnings to be associated with different categories
enum WarnErrorCategory
{
    CategoryInformation,// Some kind of information [default severity information]

    CategoryCast,       // Suspicious casts between types or out of range values
    CategoryConfuse,    // Likely to cause confusion
    CategoryDeprecated, // deprecated features or syntax
    CategoryEfficiency, // Something that is likely to be inefficient
    CategoryFolding,    // Unusual results from constant folding
    CategoryFuture,     // Likely to cause problems in future versions
    CategoryIgnored,    // Something that has no effect, or is ignored
    CategoryIndex,      // Unusual indexing of datasets or strings
    CategoryMistake,    // Almost certainly a mistake
    CategoryLimit,      // An operation that should really have some limits to protect data runaway
    CategorySyntax,     // Invalid syntax which is painless to recover from
    CategoryUnusual,    // Not strictly speaking an error, but highly unusual and likely to be a mistake
    CategoryUnexpected, // Code that could be correct, but has the potential for unexpected behaviour
    CategoryCpp,        // Warning passed through from C++ compiler
    CategorySecurity,   // Security warnings - operations that will be refused at codegen time unless unused.
    CategoryDFS,        // DFS resolution issues - field translation may not have occurred even though requested
    CategoryEmbed,      // Warning passed through from embedded code syntax check

    CategoryError,      // Typically severity fatal
    CategoryAll,
    CategoryUnknown,
    CategoryMax,
};

interface jlib_thrown_decl IError : public IException
{
public:
    virtual const char* getFilename() const = 0;
    virtual WarnErrorCategory getCategory() const = 0;
    virtual int getLine() const = 0;
    virtual int getColumn() const = 0;
    virtual int getPosition() const = 0;
    virtual StringBuffer& toString(StringBuffer&) const = 0;
    virtual ErrorSeverity getSeverity() const = 0;
    virtual IError * cloneSetSeverity(ErrorSeverity _severity) const = 0;
    virtual unsigned getActivity() const = 0;
    virtual const char * queryScope() const = 0;
    virtual IPropertyTree * toTree() const = 0;
};

interface IWorkUnit;
interface jlib_decl IErrorReceiver : public IInterface
{
    virtual void report(IError* error) = 0;
    virtual IError * mapError(IError * error) = 0;
    virtual size32_t errCount() = 0;
    virtual size32_t warnCount() = 0;
    virtual void exportMappings(IWorkUnit * wu) const = 0;
    virtual __declspec(noreturn) void throwStringExceptionV(int code,const char *format, ...) const __attribute__((format(printf, 3, 4), noreturn));            // override the global function to try and add more context information

    //global helper functions
    void reportError(int errNo, const char *msg, const char *filename, int lineno, int column, int pos);
    void reportWarning(WarnErrorCategory category, int warnNo, const char *msg, const char *filename, int lineno, int column, int pos);
};


inline bool isError(IError * error) { return isError(error->getSeverity()); }
inline bool isFatal(IError * error) { return isFatal(error->getSeverity()); }
extern jlib_decl ErrorSeverity queryDefaultSeverity(WarnErrorCategory category);

extern jlib_decl IError *createError(WarnErrorCategory category, ErrorSeverity severity, int errNo, const char *msg, const char *filename, int lineno=0, int column=0, int pos=0, unsigned activity = 0, const char * scope = nullptr);
extern jlib_decl IError *createError(WarnErrorCategory category, ErrorSeverity severity, int errNo, const char *msg, unsigned activity, const char * scope);
extern jlib_decl IError *createError(IPropertyTree * tree);
inline IError * createError(int errNo, const char *msg, const char *filename, int lineno=0, int column=0, int pos=0)
{
    return createError(CategoryError, SeverityFatal, errNo, msg, filename, lineno, column, pos);
}

extern jlib_decl const char * querySeverityString(ErrorSeverity errorSeverity);
class LogMsgCategory;
extern jlib_decl const LogMsgCategory & mapToLogMsgCategory(ErrorSeverity severity, MessageAudience aud);

enum ExceptionInterceptClass
{
    eString = 0x01,
    eErrno  = 0x02,
    eOs     = 0x04,
    eSocket = 0x08
};
typedef std::function<void(IException *e)> InterceptHandler;
interface IExceptionIntercept
{
    virtual void handle(ExceptionInterceptClass eClass, IException *e) const = 0;
    virtual void clear() = 0;
    virtual void setIntercept(ExceptionInterceptClass eClass, int code, InterceptHandler func) = 0;
    virtual void addFromConfig(const IPropertyTree *exceptionHandlerTree) = 0;
};
extern jlib_decl IExceptionIntercept &queryExceptionIntercept();

#endif

