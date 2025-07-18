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

#ifdef _WIN32
#pragma warning(disable:4786)
#endif

#include "platform.h"

#include "hidl_utils.hpp"
#include "hidlcomp.h"
#include "AccessMapGenerator.hpp"

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <algorithm>

//-------------------------------------------------------------------------------------------------------------
inline bool strieq(const char* s,const char* t) { return stricmp(s,t)==0; }

//-------------------------------------------------------------------------------------------------------------
#define HIDL "HIDL"

extern FILE *yyin;
extern int yyparse();

extern HIDLcompiler * hcp;

// --- globals -----

bool isSCM = true;
bool isESP = false;
bool isESPng = false;
char srcFileExt[4];

int gOutfile;

//-------------------------------------------------------------------------------------------------------------
// Utility struct and function

char* getFieldName(const char* name)
{
    char *uname=strdup(name);
    *uname=upperchar(*uname);
    return uname;
}

static const char* getTypeKindName(type_kind kind)
{
    switch (kind)
    {
    case TK_null: return "TK_null";
    case TK_CHAR: return "TK_CHAR";
    case TK_UNSIGNEDCHAR: return "TK_UNSIGNEDCHAR";
    case TK_BYTE: return "TK_BYTE";
    case TK_BOOL: return "TK_BOOL";
    case TK_SHORT: return "TK_SHORT";
    case TK_UNSIGNEDSHORT: return "TK_UNSIGNEDSHORT";
    case TK_INT: return "TK_INT";
    case TK_UNSIGNED: return "TK_UNSIGNED";
    case TK_LONG: return "TK_LONG";
    case TK_UNSIGNEDLONG: return "TK_UNSIGNEDLONG";
    case TK_LONGLONG: return "TK_LONGLONG";
    case TK_UNSIGNEDLONGLONG: return "TK_UNSIGNEDLONGLONG";
    case TK_DOUBLE: return "TK_DOUBLE";
    case TK_FLOAT: return "TK_FLOAT";
    case TK_STRUCT: return "TK_STRUCT";
    case TK_ENUM: return "TK_ENUM";
    case TK_VOID: return "TK_VOID";
    case TK_ESPSTRUCT: return "TK_ESPSTRUCT";
    case TK_ESPENUM: return "TK_ESPENUM";
    default: return "<unknown kind>";
    }
};

const char *type_name[] =
{
    "??",
    "char",
    "unsigned char",
    "byte",
    "bool",
    "short",
    "unsigned short",
    "int",
    "unsigned",
    "long",
    "unsigned long",
    "__int64",
    "unsigned __int64",
    "double",
    "float",
    "",  // STRUCT
    "",  // ENUM
    "void",
    "??", // ESPSTRUCT
    "??" // ESPENUM
};

const int type_size[] =
{
    0,  // tk_null
    1,  // TK_CHAR
    1,  // TK_UCHAR
    1,  // BYTE
    1,  // BOOL
    2,  // SHORT
    2,  // USHORT
    4,  // INT
    4,  // UNSIGNED
    4,  // LONG
    4,  // ULONG
    8,  // LONGLONG
    8,  // ULONGLONG
    8,  // DOUBLE
    4,  // FLOAT
    4,  // STRUCT
    4,  // ENUM
    0,  // void
    1,  // ESP_STRUCT
    1   // ESP_ENUM
};


bool toClaInterface(char * dest, const char * src)
{
    if(*src == 'I' && strlen(src) > 1)
    {
        strcpy(dest, "cpp");
        strcpy(dest + 3, src + 1);
        return true;
    }
    strcpy(dest, src);
    return false;
}

#define ForEachParam(pr,pa,flagsset,flagsclear) for (pa=pr->params;pa;pa=pa->next) \
if (((pa->flags&(flagsset))==(flagsset))&((pa->flags&(flagsclear))==0))

#define INDIRECTSIZE(p) ((p->flags&(PF_PTR|PF_REF))==(PF_PTR|PF_REF))

void indent(int indents)
{
    for (int i=0;i<indents; i++)
        out("\t",1);
}

void out(const char *s,ssize_t l)
{
    ssize_t written = write(gOutfile,s,(unsigned)l);
    if (written < 0)
        throw "Error while writing out";
    if (written != l)
        throw "Truncated write";
}

void outs(const char *s)
{
    out(s,strlen(s));
}

void outs(int indents, const char *s)
{
    indent(indents);
    out(s,strlen(s));
}

static void voutf(const char* fmt,va_list args) __attribute__((format(printf,1,0)));
void voutf(const char* fmt,va_list args)
{
    const int BUF_LEN = 0x4000;
    static char buf[BUF_LEN+1];

    // Better to use StringBuffer.valist_appendf, but unfortunately, project dependencies
    // disallow us to use StringBuffer (defined in jlib).
    if (_vsnprintf(buf, BUF_LEN, fmt, args)<0)
        fprintf(stderr,"Warning: outf() gets too many long buffer (>%d)", BUF_LEN);
    va_end(args);

    outs(buf);
}

void outf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    voutf(fmt,args);
}

void outf(int indents, const char *fmt, ...)
{
    indent(indents);

    va_list args;
    va_start(args, fmt);
    voutf(fmt,args);
}

// ------------------------------------
// "auto" indenting

int gIndent = 0;

void indentReset(int indent=0) { gIndent = indent; }
void indentInc(int inc) {  gIndent += inc; }

void indentOuts(const char* s)
{
    indent(gIndent);
    out(s,strlen(s));
}

void indentOuts(int inc, const char* s)
{
    gIndent += inc;
    indentOuts(s);
}

void indentOuts1(int inc, const char* s)
{
    indent(gIndent+inc);
    out(s,strlen(s));
}

void indentOutf(const char* fmt,...) __attribute__((format(printf,1,2)));
void indentOutf(const char* fmt, ...)
{
    indent(gIndent);

    va_list args;
    va_start(args, fmt);
    voutf(fmt,args);
}

void indentOutf(int inc, const char* fmt,...) __attribute__((format(printf,2,3)));
void indentOutf(int inc, const char* fmt, ...)
{
    gIndent += inc;
    indent(gIndent);

    va_list args;
    va_start(args, fmt);
    voutf(fmt,args);
}

void indentOutf1(int inc, const char* fmt,...) __attribute__((format(printf,2,3)));
void indentOutf1(int inc, const char* fmt, ...)
{
    indent(gIndent+inc);

    va_list args;
    va_start(args, fmt);
    voutf(fmt,args);
}

void validateProfileExecutionOptions(std::string &options)
{
    //
    // Expected format:
    //   options     ::= ("s" | "ms" | "us" | "ns") "," <bucketLimit> ["," <bucketLimit>]*
    //   bucketLimit ::= digit+
    // Note, caller must remove any spaces

    //
    // Split the option string up
    std::vector<std::string> optionValues;
    size_t start;
    size_t end = 0;
    while ((start = options.find_first_not_of(',', end)) != std::string::npos) {
        end = options.find(',', start);
        optionValues.push_back(options.substr(start, end - start));
    }

    //
    // Must be at least 2, units and a bucket
    if (optionValues.size() < 2)
        throw "Execution profiling option must define at least one bucket";

    //
    // First entry is units
    if (optionValues[0] != "s" && optionValues[0] != "ms" && optionValues[0]  != "us" && optionValues[0] != "ns")
        throw "Execution profiling units must be s, ms, us, or ns";

    //
    // Remaining entries must be non-zero numbers increasing in value
    int maxValue = 0;
    for (unsigned i=1; i<optionValues.size(); ++i)
    {
        int value = std::stoi(optionValues[i]);
        if (value <= maxValue )
            throw "Execution profiling bucket limits must be non-zero and greater than the previous";
        maxValue = value;
    }
}

//-------------------------------------------------------------------------------------------------------------
// class LayoutInfo

LayoutInfo::LayoutInfo()
{
    size = 0;
    count = 0;
    next = NULL;
}

LayoutInfo::~LayoutInfo()
{
    delete next;
}

//-------------------------------------------------------------------------------------------------------------
// class ParamInfo

ParamInfo::ParamInfo()
{
    name = NULL;
    templ = NULL;
    typname = NULL;
    size = NULL;
    flags = 0;
    next = NULL;
    kind = TK_null;
    sizebytes = NULL;
    layouts = NULL;
    tags = NULL;
    xsdtype = NULL;
    m_arrayImplType = NULL;
}

ParamInfo::~ParamInfo()
{
    if (name)
        free(name);
    if (typname)
        free(typname);
    if (size)
        free(size);
    if (sizebytes)
        free(sizebytes);
    if (templ)
        free(templ);
    if (xsdtype)
        free(xsdtype);
    if (m_arrayImplType)
        delete m_arrayImplType;

    delete tags;
    delete layouts;
    delete next;
}

char * ParamInfo::bytesize(int deref)
{
    if (!size)
        return NULL;
    if (sizebytes)
        return sizebytes;
    char str[1024];
    if (type_size[kind]==1)
    {
        if (deref)
        {
            strcpy(str,"*");
            strcat(str,size);
            sizebytes = strdup(str);
            return sizebytes;
        }
        else
            return size;
    }

    strcpy(str,"sizeof(");
    if (kind==TK_STRUCT)
        strcat(str,typname);
    else
        strcat(str,type_name[kind]);
    strcat(str,")*(");
    if (deref)
        strcat(str,"*");
    strcat(str,size);
    strcat(str,")");
    sizebytes = strdup(str);
    return sizebytes;
}

bool ParamInfo::simpleneedsswap()
{
    switch(kind) {
    case TK_SHORT:
    case TK_UNSIGNEDSHORT:
    case TK_INT:
    case TK_UNSIGNED:
    case TK_LONG:
    case TK_UNSIGNEDLONG:
    case TK_LONGLONG:
    case TK_UNSIGNEDLONGLONG:
        return true;
    default:
        return false;
    }
}



void ParamInfo::cat_type(char *s,int deref,int var)
{
    if ((flags&PF_CONST)&&!var)
        strcat(s,"const ");
    if (typname)
        strcat(s,typname);
    else {
        if (kind!=TK_null)
            strcat(s,type_name[kind]);
        else
            strcat(s,"string"); // TODO: why this happens?
    }
    if (!deref) {
        if (flags&PF_PTR)
            strcat(s," *");
        if (flags&PF_REF)
            strcat(s," &");
    }
}

void ParamInfo::out_parameter(const char * pfx)
{
    out_type();
    outf(" %s%s",pfx,name);
}

void ParamInfo::out_type(int deref,int var)
{
    char s[256];
    s[0] = 0;
    cat_type(s,deref,var);
    outs(s);
}

void ParamInfo::typesizeacc(char *accstr,size_t &acc)
{
    if ((kind==TK_STRUCT)||(flags&(PF_PTR|PF_REF))) {
        acc = (acc+3)&~3;
        if (*accstr)
            strcat(accstr,"+");
        strcat(accstr,"sizeof(");
        cat_type(accstr);
        strcat(accstr,")");
    }
    else {
        size_t sz=type_size[kind];
        if (sz==2)
            acc = (acc+1)&~1;
        else if (sz>=4)
            acc = (acc+3)&~3;
        acc += type_size[kind];
    }
}

size_t ParamInfo::typesizealign(size_t &ofs)
{
    size_t ret=0;
    if ((kind==TK_STRUCT)||(flags&(PF_PTR|PF_REF))) {
        if (ofs) {
            ret = 4-ofs;
            ofs = 0;
        }
    }
    else {
        size_t sz=type_size[kind];
        if (sz==1) {
            ret = 0;
            ofs = (ofs+1)%4;
        }
        else if (sz==2) {
            ret = (ofs&1);
            ofs = (ofs+ret+2)%4;
        }
        else {
            if (ofs) {
                ret = 4-ofs;
                ofs = 0;
            }
        }
    }
    return ret;
}

void ParamInfo::write_body_struct_elem(int ref)
{
    outs("\t");
    out_type(ref,1);
    if (ref&&(flags&(PF_REF|PF_PTR)))
    {
        outs(" *");
        if ((flags&(PF_REF|PF_PTR))==(PF_REF|PF_PTR))
        {
            outs(" *");
        }
    }
    outf(" %s;\n",name);
}


void ParamInfo::write_param_convert(int deref)
{
    outs("(");
    out_type(1,1);
    if (flags&(PF_REF|PF_PTR)) {
        if (!deref)
            outs(" *");
        if ((flags&(PF_REF|PF_PTR))==(PF_REF|PF_PTR)) {
            outs(" *");
        }
    }
    outs(")");
}


bool ParamInfo::hasMapInfo()
{
    if (hasMetaVerInfo("min_ver") || hasMetaVerInfo("max_ver") || hasMetaVerInfo("depr_ver"))
        return true;

    if (getMetaString("optional", NULL))
        return true;

    return false;
}

static esp_xlate_info esp_xlate_table[]=
{
    //meta type                 xsd type                implementation      array impl      access type             type_kind           flags               method
    //------------------        ---------------         --------------      --------------  --------------          -----------         ------------        ----------

//  {"string",                  "string",               "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"string",                  "string",               "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"StringBuffer",            "string",               "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
//  {"hexBinary",               "base64Binary",         "MemoryBuffer",     "???",          "unsigned char *",      TK_UNSIGNEDCHAR,    (PF_PTR),           EAM_jmbuf},
    {"binary",                  "base64Binary",         "MemoryBuffer",     "???",          "const MemoryBuffer &", TK_STRUCT,          (PF_REF),           EAM_jmbin},
    {"bool",                    "boolean",              "bool",             "BoolArray",    "bool",                 TK_BOOL,            0,                  EAM_basic},
    {"boolean",                 "boolean",              "bool",             "BoolArray",    "bool",                 TK_BOOL,            0,                  EAM_basic},
    {"decimal",                 "decimal",              "float",            "???",          "float",                TK_FLOAT,           0,                  EAM_basic},
    {"float",                   "float",                "float",            "FloatArray",   "float",                TK_FLOAT,           0,                  EAM_basic},
    {"double",                  "double",               "double",           "DoubleArray",  "double",               TK_DOUBLE,          0,                  EAM_basic},
    {"integer",                 "integer",              "int",              "???",          "int",                  TK_INT,             0,                  EAM_basic},
    {"int64",                   "long",                 "__int64",          "Int64Array",   "__int64",              TK_LONGLONG,        0,                  EAM_basic},
    {"long",                    "long",                 "long",             "Int64Array",   "__int64",              TK_LONG,            0,                  EAM_basic},
    {"int",                     "int",                  "int",              "IntArray",     "int",                  TK_INT,             0,                  EAM_basic},
    {"short",                   "short",                "short",            "ShortArray",   "short",                TK_SHORT,           0,                  EAM_basic},
    {"nonPositiveInteger",      "nonPositiveInteger",   "int",              "???",          "int",                  TK_INT,             0,                  EAM_basic},
    {"negativeInteger",         "negativeInteger",      "unsigned int",     "???",          "unsigned int",         TK_UNSIGNED,        0,                  EAM_basic},
    {"nonNegativeInteger",      "nonNegativeInteger",   "unsigned int",     "???",          "unsigned int",         TK_UNSIGNED,        0,                  EAM_basic},
    {"unsignedLong",            "unsignedLong",         "unsigned long",    "???",          "unsigned long",        TK_UNSIGNEDLONG,    0,                  EAM_basic},
    {"unsignedInt",             "unsignedInt",          "unsigned int",     "???",          "unsigned int",         TK_UNSIGNED,        0,                  EAM_basic},
    {"unsigned",                "unsignedInt",          "unsigned int",     "???",          "unsigned int",         TK_UNSIGNED,        0,                  EAM_basic},
    {"unsignedShort",           "unsignedShort",        "unsigned short",   "???",          "unsigned short",       TK_UNSIGNEDSHORT,   0,                  EAM_basic},
    {"unsignedByte",            "unsignedByte",         "unsigned char",    "???",          "unsigned char",        TK_UNSIGNEDCHAR,    0,                  EAM_basic},
    {"positiveInteger",         "positiveInteger",      "unsigned int",     "???",          "unsigned int",         TK_UNSIGNED,        0,                  EAM_basic},
    {"base64Binary",            "base64Binary",         "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"normalizedString",        "normalizedString",     "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdString",               "string",               "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdBinary",               "binary",               "MemoryBuffer",     "???",          "const MemoryBuffer &", TK_STRUCT,          (PF_REF),           EAM_jmbin},
    {"xsdBoolean",              "boolean",              "bool",             "???",          "bool",                 TK_BOOL,            0,                  EAM_basic},
    {"xsdDecimal",              "decimal",              "float",            "???",          "float",                TK_FLOAT,           0,                  EAM_basic},
    {"xsdInteger",              "integer",              "int",              "???",          "int",                  TK_INT,             0,                  EAM_basic},
    {"xsdByte",                 "byte",                 "unsigned char",    "???",          "unsigned char",        TK_UNSIGNEDCHAR,    0,                  EAM_basic},
    {"xsdDuration",             "duration",             "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdDateTime",             "dateTime",             "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdTime",                 "time",                 "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdDate",                 "date",                 "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdYearMonth",            "gYearMonth",           "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdYear",                 "gYear",                "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdMonthDay",             "gMonthDay",            "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdDay",                  "gDay",                 "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdMonth",                "gMonth",               "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdAnyURI",               "anyURI",               "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdQName",                "QName",                "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdNOTATION",             "NOTATION",             "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdToken",                "token",                "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdLanguage",             "language",             "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdNMTOKEN",              "NMTOKEN",              "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdNMTOKENS",             "NMTOKENS",             "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdName",                 "Name",                 "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdNCName",               "NCName",               "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdID",                   "ID",                   "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdIDREF",                "IDREF",                "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdIDREFS",               "IDREFS",               "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdENTITY",               "ENTITY",               "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdENTITIES",             "ENTITIES",             "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdNonPositiveInteger",   "nonPositiveInteger",   "int",              "???",          "int",                  TK_INT,             0,                  EAM_basic},
    {"xsdNegativeInteger",      "negativeInteger",      "unsigned int",     "???",          "unsigned int",         TK_UNSIGNED,        0,                  EAM_basic},
    {"xsdNonNegativeInteger",   "nonNegativeInteger",   "unsigned int",     "???",          "unsigned int",         TK_UNSIGNED,        0,                  EAM_basic},
    {"xsdUnsignedLong",         "unsignedLong",         "unsigned long",    "???",          "unsigned long",        TK_UNSIGNEDLONG,    0,                  EAM_basic},
    {"xsdUnsignedInt",          "unsignedInt",          "unsigned int",     "???",          "unsigned int",         TK_UNSIGNED,        0,                  EAM_basic},
    {"xsdUnsignedShort",        "unsignedShort",        "unsigned short",   "???",          "unsigned short",       TK_UNSIGNEDSHORT,   0,                  EAM_basic},
    {"xsdUnsignedByte",         "unsignedByte",         "unsigned char",    "???",          "unsigned char",        TK_UNSIGNEDCHAR,    0,                  EAM_basic},
    {"xsdPositiveInteger",      "positiveInteger",      "unsigned int",     "???",          "unsigned int",         TK_UNSIGNED,        0,                  EAM_basic},
    {"xsdBase64Binary",         "base64Binary",         "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"xsdNormalizedString",     "normalizedString",     "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"EspTextFile",             "string",               "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"EspResultSet",            "string",               "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {"AdoDataSet",              "tns:AdoDataSet",       "StringBuffer",     "StringArray",  "const char *",         TK_CHAR,            (PF_PTR|PF_CONST),  EAM_jsbuf},
    {NULL,                      NULL,                   NULL,               NULL,           NULL,                   TK_null,            0,                  EAM_basic}
};


esp_xlate_info *esp_xlat(const char *from, bool defaultToString)
{
    if (from)
    {
        for (unsigned i=0; esp_xlate_table[i].meta_type!=NULL; i++)
        {
            if (stricmp(from,esp_xlate_table[i].meta_type)==0)
                return &esp_xlate_table[i];
        }
    }
    return (defaultToString) ? &esp_xlate_table[0] : NULL;
}

static const char *MetaTypeToXsdType(const char *val)
{
    esp_xlate_info *xlation=esp_xlat(val);
    return (xlation) ? xlation->xsd_type : (const char *)"string";
}

// return: true if the ver tag is defined
bool hasMetaVerInfo(MetaTagInfo *list, const char* tag)
{
    double ver = getMetaDouble(list,tag,-1);
    if (ver>0)
        return true;

    const char* vs = getMetaString(list,tag, NULL);
    if (vs!=NULL)
        return true;

    const char* id = getMetaConstId(list,tag,NULL);
    if (id)
        return true;

    return false;
}

bool getMetaVerInfo(MetaTagInfo *list, const char* tag, StrBuffer& s)
{
    double ver = getMetaDouble(list,tag,-1);
    if (ver>0) {
        s.append(ver);
        return true;
    }

    const char* vs = getMetaString(list,tag, NULL);
    if (vs!=NULL) {
        if (*vs=='"' || *vs=='\'')
            vs++;
        double v = atof(vs);
        s.append(v);
        return true;
    }

    const char* id = getMetaConstId(list,tag,NULL);
    if (id) {
        s.append(id);
        return true;
    }

    return false;
}

static esp_xlate_info *esp_xlat(ParamInfo *pi)
{
    char metatype[256];
    *metatype=0;

    pi->cat_type(metatype);

    return esp_xlat(metatype);
}

void ParamInfo::setXsdType(const char *value)
{
    if (xsdtype)
        free(xsdtype);

    const char *newValue=value;
    if (strncmp(value, "xsd", 3)==0)
        newValue=MetaTypeToXsdType(value);

    xsdtype = (newValue!=NULL) ? strdup(newValue) : NULL;
}


const char *ParamInfo::getXsdType()
{
    if (xsdtype==NULL)
    {
        char metatype[256];
        *metatype=0;
        cat_type(metatype);

        setXsdType(MetaTypeToXsdType(metatype));
    }

    return xsdtype;
}

const char* ParamInfo::getArrayImplType()
{
    if (m_arrayImplType)
        return m_arrayImplType->str();

    if (isPrimitiveArray())
    {
        char metatype[256];
        metatype[0] = 0;
        cat_type(metatype);
        esp_xlate_info *xlation=esp_xlat(metatype, false);
        m_arrayImplType = new StrBuffer(xlation->array_type);
    }
    else
    {
        if (kind == TK_ESPENUM)
            m_arrayImplType = new VStrBuffer("%sArray", typname);
        else
            m_arrayImplType = new VStrBuffer("IArrayOf<IConst%s>", typname);
    }

    return m_arrayImplType->str();
}

const char* ParamInfo::getArrayItemXsdType()
{
    switch (kind)
    {
    case TK_CHAR: return "string";
    case TK_UNSIGNEDCHAR: return "string"; //?
    case TK_BYTE: return "byte";
    case TK_BOOL: return "boolean";
    case TK_SHORT: return "short";
    case TK_UNSIGNEDSHORT: return "unsignedShort";
    case TK_INT: return "int";
    case TK_UNSIGNED: return "unsignedInt";
    case TK_LONG: return "long";
    case TK_UNSIGNEDLONG: return "unsignedLong";
    case TK_LONGLONG: return "long";
    case TK_UNSIGNEDLONGLONG: return "unsignedLong";
    case TK_DOUBLE: return "double";
    case TK_FLOAT: return "float";

    case TK_null: return "string";

    case TK_STRUCT:
    case TK_VOID:
    case TK_ESPSTRUCT:
    case TK_ESPENUM:
    default: throw "Unimplemented";
    }
}

const char* ParamInfo::getArrayItemTag()
{
    const char *item_tag = getMetaString("item_tag", NULL);
    if (item_tag)
        return item_tag;
    if (!(flags & PF_TEMPLATE) || !streq(templ, "ESParray"))
        return NULL;
    if (isEspStringArray())
        return "Item";
    return typname;
}

void ParamInfo::write_esp_declaration()
{
    char metatype[256];
    *metatype=0;

    cat_type(metatype);

    esp_xlate_info *xlation=esp_xlat(metatype, false);

    if (hasNameTag())
        outf("\tSoapStringParam m_%s_name;\n", name);

    if (xlation)
    {
        if (xlation->eam_type==EAM_jmbin)
        {
            if (getMetaInt("attach", 0))
                outf("\tSoapAttachBinary m_%s;\n", name);
            else
                outf("\tSoapParamBinary m_%s;\n", name);
        }
        else
        {
            if (getMetaInt("attach", 0))
            {
                if (!stricmp(xlation->store_type, "StringBuffer"))
                    outf("\tSoapAttachString m_%s;\n", name);
                else
                    outf("\tSoapAttachParam<%s> m_%s;\n", xlation->store_type, name);
            }
            else if (flags & PF_TEMPLATE)
            //  outf("\tSoapArrayParam<%s> m_%s;\n", xlation->array_type, name);
                outf("\tSoap%s m_%s;\n", xlation->array_type, name);
            else if (!stricmp(xlation->store_type, "StringBuffer"))
                outf("\tSoapStringParam m_%s;\n", name);
            else
                outf("\tSoapParam<%s> m_%s;\n", xlation->store_type, name);
        }
    }
    else
    {
        if (getMetaInt("attach", 0))
            outf("\tSoapAttachString m_%s;\n", name);
        else if (flags & PF_TEMPLATE && templ && !strcmp(templ, "ESParray"))
        {
            if (isEspStringArray())
                //outf("\tSoapArrayParam<StringArray> m_%s;\n", name);
                outf("\tSoapStringArray m_%s;\n", name);
            else if (kind==TK_ESPENUM)
                outf("\tSoapEnumArrayParam<C%s, CX%s, %sArray> m_%s;\n", typname, typname, typname, name);
            else
                outf("\tSoapStructArrayParam<IConst%s, C%s> m_%s;\n", typname, typname, name);
        }
        else if (kind==TK_ESPSTRUCT)
            outf("\tSoapStruct<C%s, IConst%s> m_%s;\n", typname, typname, name);
        else if (kind==TK_ESPENUM)
            outf("\tCX%s m_%s;\n", typname, name);
        else
            outf("\tSoapStringParam m_%s;\n", name);
    }
}

void ParamInfo::write_esp_init(bool &isFirst, bool msgRemoveNil)
{
    outs(isFirst ? "\n\t: " : ",");

    MetaTagInfo* deftag = findMetaTag(tags, "default");

    bool removeNil = (msgRemoveNil || findMetaTag(tags, "nil_remove")!=NULL);
    const char *nilStr = (removeNil) ? "nilRemove" : "nilIgnore";

    if (kind==TK_ESPSTRUCT)
    {
        outf("m_%s(serviceName, %s)", name, nilStr);
    }
    else if (kind==TK_ESPENUM)
    {
        if (deftag)
        {
            outf("m_%s(", name);
            switch(deftag->mttype_)
            {
            case MetaTagInfo::mt_string: outf("%s",deftag->getString()); break;
            case MetaTagInfo::mt_int:    outf("\"%d\"", deftag->getInt()); break;
            case MetaTagInfo::mt_double: outf("\"%g\"", deftag->getDouble()); break;
            case MetaTagInfo::mt_const_id: outf("\"%s\"", deftag->getName()); break;
            case MetaTagInfo::mt_none: assert(false); break;
            }
            outf(")");
        }
        else
            outf("m_%s(%s)", name, nilStr);
    }
    else if ((flags & PF_TEMPLATE) || kind==TK_STRUCT || getMetaInt("attach", 0))
    {
        outf("m_%s(%s)", name, nilStr);
    }
    else if (deftag)
    {
        if (deftag->mttype_==MetaTagInfo::mt_string)
            outf("m_%s(%s, %s)", name, deftag->getString(), nilStr);
        else if (deftag->mttype_==MetaTagInfo::mt_int)
            outf("m_%s(%d, %s,false)", name, deftag->getInt(), nilStr);
        else if (deftag->mttype_==MetaTagInfo::mt_double)
            outf("m_%s(%g, %s,false)", name, deftag->getDouble(), nilStr);
    }
    else
    {
        if (getMetaInt("http_nillable", 1)!=0)
            outf("m_%s(%s)", name, nilStr);
        else
            outf("m_%s(%s, false)", name, nilStr);
    }

    isFirst=false;
}



void ParamInfo::write_esp_attr_method(const char *msgname, bool isSet, bool parNilRemove, bool isDecl, bool isPure, bool parTrim, const char* xsdType)
{
    char metatype[256];
    *metatype=0;

    cat_type(metatype);

    esp_xlate_info *xlation=esp_xlat(metatype);

    char *methName=strdup(name);
    *methName=upperchar(*methName);

    const char *httpcont = getMetaString("http_content", NULL);

    bool hasNilRemove = (parNilRemove || getMetaInt("nil_remove"));
    bool hasTrim = (parTrim || getMetaInt("trim"));


    if (hasNameTag())
    {
        if (isSet)
        {
            if (isDecl)
                outs("\t");
            if (isDecl && isPure)
                outs("virtual ");
            outs("void ");
            if (!isDecl && msgname)
                outf("C%s::", msgname);
            outf("set%s_name", methName);
            outs("(const char *  val)");

            if (isDecl)
                outs((isPure) ? "=0;\n" : ";\n");
            else
                outf("{ m_%s_name.set(val); }\n", name);

        }
        else
        {
            if (isDecl)
                outs("\t");
            if (isDecl && isPure)
                outs("virtual ");
            outs("const char *");
            if (!isDecl && msgname)
                outf("C%s::", msgname);
            outf("get%s_name()", methName);

            if (isDecl)
                outs((isPure) ? "=0;\n" : ";\n");
            else
                outf("{ return m_%s_name.query(); }\n", name);

            if (isDecl)
                    outs("\t");
            if (isDecl && isPure)
                outs("virtual ");
            outs("const StringBuffer& ");
            if (!isDecl && msgname)
                outf("C%s::", msgname);
            outf("get%s_value()", methName);

            if (isDecl)
                outs((isPure) ? "=0;\n" : ";\n");
            else
                outf("{ return m_%s.getValue(); }\n", name);
        }
    }

    if (httpcont!=NULL)
    {
        if (isSet)
        {
            if (isDecl)
                outs("\t");
            if (isDecl && isPure)
                outs("virtual ");
            outs("void ");
            if (!isDecl && msgname)
                outf("C%s::", msgname);
            outf("set%s_mimetype", methName);
            outs("(const char *  val)");

            if (isDecl)
                outs((isPure) ? "=0;\n" : ";\n");
            else
                outf("{ m_%s_mimetype.set(val); }\n", name);

        }
        else
        {
            if (isDecl)
                outs("\t");
            if (isDecl && isPure)
                outs("virtual ");
            outs("const char *");
            if (!isDecl && msgname)
                outf("C%s::", msgname);
            outf("get%s_mimetype()", methName);

            if (isDecl)
                outs((isPure) ? "=0;\n" : ";\n");
            else
                outf("{ return m_%s_mimetype.str(); }\n", name);
        }
    }


    if (isSet)
    {
        if (hasNilRemove && xlation->eam_type == EAM_basic && (flags & PF_TEMPLATE)==0 )
        {
            if (isDecl)
                outs("\t");
            if (isDecl && isPure)
                outs("virtual ");
            outs("void ");
            if (!isDecl && msgname)
                outf("C%s::", msgname);
            outf("set%s_null()", methName);

            if (isDecl)
                outs((isPure) ? "=0;\n" : ";\n");
            else
                outf("{ m_%s.Nil(); }", name);
        }

        if (isDecl)
            outs("\t");
        if (isDecl && isPure)
            outs("virtual ");

        if (flags & PF_TEMPLATE)
        {
            // setXXX(IArrayOf<IEspXXX>);
            if (templ && !strcmp(templ, "ESParray") && typname && !isEspStringArray() && kind!=TK_ESPENUM)
            {
                outs("void ");
                if (!isDecl && msgname)
                    outf("C%s::", msgname);
                outf("set%s", methName);
                if (kind == TK_ESPENUM)
                    ;// outf("(%sArray &val)", typname);
                else
                    outf("(IArrayOf<IEsp%s> &val)", typname);
                if (isDecl)
                {
                    if (isPure)
                        outs("=0;\n\tvirtual ");
                    else
                        outs(";\n ");
                }
                else
                {
                    outs("\n{\n");

                    if (kind == TK_ESPENUM)
                    {
                        /*
                        outf("\tm_%s->kill();\n", name);
                        outf("\t%sArray &target = m_%s.getValue();\n", typname, name);
                        outs("\tForEachItemIn(idx, val)\n");
                        outs("\t{\n");
                        outf("\t\tC%s &item = (val).item(idx);\n", typname);
                        outs("\t\ttarget.append(item);\n");
                        outs("\t}\n");
                        */
                    }
                    else
                    {
                        outf("\tm_%s->kill();\n", name);
                        outf("\tIArrayOf<IConst%s> &target = m_%s.getValue();\n", typname, name);
                        outs("\tForEachItemIn(idx, val)\n");
                        outs("\t{\n");
                        outf("\t\tIEsp%s &item = (val).item(idx);\n", typname);
                        outs("\t\titem.Link();\n");
                        outs("\t\ttarget.append(item);\n");
                        outs("\t}\n");
                    }

                    outs("}\n");
                }
            }

            outs("void ");
            if (!isDecl && msgname)
                outf("C%s::", msgname);
            outf("set%s", methName);

            if (templ && !strcmp(templ, "ESParray"))
            {
                //if (isEspStringArray())
                //  outf("(%s &val)", "StringArray");
                //else
                //  outf("(IArrayOf<IConst%s> &val)", typname);
                outf("(%s &val)", getArrayImplType());
            }
            else
            {
                switch (xlation->eam_type)
                {
                case EAM_jmbuf:
                    outf("(%s val, unsigned int len)", xlation->access_type);
                    break;
                case EAM_jmbin:
                case EAM_basic:
                case EAM_jsbuf:
                default:
                    outf("(%s val)", xlation->access_type);
                    break;
                }
            }

            if (isDecl)
            {
                if (isPure)
                    outs("=0");
                outs(";\n");
            }
            else
            {
                if (isPrimitiveArray())
                {
                    outf("{ ");
                    if (isEspStringArray())
                        outf("m_%s->kill(); ",name);
                    outf(" CloneArray(m_%s.getValue(), val); }\n", name);
                }
                else if (kind == TK_ESPENUM)
                {
                    outs("\n{\n");
                    outf("\tm_%s->kill();\n", name);
                    outf("\t%sArray &target = m_%s.getValue();\n", typname, name);
                    outs("\tForEachItemIn(idx, val)\n");
                    outs("\t{\n");
                    outf("\t\tC%s item = val.item(idx);\n", typname);
                    outs("\t\ttarget.append(item);\n");
                    outs("\t}\n");
                    outs("}\n");
                }
                else
                {
                    outs("\n{\n");
                    outf("\tm_%s->kill();\n", name);
                    outf("\tIArrayOf<IConst%s> &target = m_%s.getValue();\n", typname, name);
                    outs("\tForEachItemIn(idx, val)\n");
                    outs("\t{\n");
                    outf("\t\tIConst%s &item = val.item(idx);\n", typname);
                    outs("\t\titem.Link();\n");
                    outs("\t\ttarget.append(item);\n");
                    outs("\t}\n");
                    outs("}\n");
                }
            }
        } // flags & PF_TEMPLATE

        else if (kind==TK_ESPSTRUCT)
        {
            outf("IEsp%s & ", typname);
            if (!isDecl && msgname)
                outf("C%s::", msgname);
            outf("update%s()", methName);

            if (isDecl)
            {
                if (isPure)
                    outs("=0;\n");
                else
                    outs(";\n");
            }
            else
            {
                outf("{ return (IEsp%s &) m_%s.getValue(); }\n", typname, name);
            }

            if (isDecl)
                outs("\t");
            if (isDecl && isPure)
                outs("virtual ");
            outs("void ");
            if (!isDecl && msgname)
                outf("C%s::", msgname);
            outf("set%s(IConst%s &ifrom)", methName, typname);
            if (isDecl)
            {
                if (isPure)
                    outs("=0");
                outs(";\n");
            }
            else
            {
                outf("{ m_%s.copy(ifrom); }\n", name);
            }
        }
        else if (kind==TK_ESPENUM)
        {
            outs("void ");
            if (!isDecl && msgname)
                outf("C%s::", msgname);
            outf("set%s(C%s val)",methName, typname);
            if (isDecl)
            {
                if (isPure)
                    outs("=0");
                outs(";\n");
            }
            else
                outf(" { m_%s.setValue(val); }\n", name);

            // as string
            if (isDecl && isPure)
                outs("\tvirtual void ");
            else
                outs("void ");
            if (!isDecl && msgname)
                outf("C%s::",msgname);
            outf("set%s(const char* val)", methName);
            if (isDecl)
            {
                if (isPure)
                    outs("=0");
                outs(";\n");
            }
            else
                outf(" { m_%s.setValue(val); }\n", name);
        }
        else
        {
            //else
            {
                outs("void ");
                if (!isDecl && msgname)
                    outf("C%s::", msgname);
                outf("set%s", methName);
                switch (xlation->eam_type)
                {
                case EAM_jmbuf:
                    outf("(%s val, unsigned int len)", xlation->access_type);
                    break;
                case EAM_jsbuf:
                    //if (xsdType)
                    //  outf("(%s val, IEspContext& ctx)", xlation->access_type);
                    //else
                        outf("(%s val)", xlation->access_type);
                    break;
                case EAM_jmbin:
                case EAM_basic:
                default:
                    outf("(%s val)", xlation->access_type);
                    break;
                }

                if (isDecl)
                {
                    if (isPure)
                        outs("=0");
                    outs(";\n");
                }
                else
                {
                    //outf("{ m_%s", name);
                    switch (xlation->eam_type)
                    {
                    case EAM_jsbuf:
                        // TODO: can not handle ArrayOfXXX yet
                        /**
                        if (xsdType && strncmp(xsdType,"ArrayOf",7)!=0)
                        {
                            //do a deserialization to enforce the versioning
                            outf("\n{\n");
                            outf("\tif (ctx)\n");
                            outf("\t{\n");
                            outf("\t\tXmlPullParser xpp(val,strlen(val));\n");

                            outf("\t\tCRpcMessage msg;\n");
                            outf("\t\tmsg.unmarshall(&xpp);\n");

                            outf("\t\tStringBuffer s;\n");
                            outf("\t\tC%s tmp(\"%s\");\n", xsdType, "XX"); // msgname?: not right

                            outf("\t\ttmp.unserialize(msg,NULL,\"%s\");\n", name);
                            outf("\t\tC%s::serializer(ctx,tmp,s,false);\n",xsdType);

                            outf("\t\tm_%s.set(s.str()%s); \n", name, hasTrim?",true":"");
                            outf("\t}\n");
                            outf("\telse\n");
                            outf("\t\tm_%s.set(val%s);\n",name,hasTrim?",true":"");
                            outf("}\n");
                        }
                        else
                        */
                            outf("{ m_%s.set(val%s); }\n", name, hasTrim?",true":"");
                        break;
                    case EAM_jmbin:
                        outf("{ m_%s->clear().append(val); }\n", name);
                        break;
                    case EAM_jmbuf:
                        outf("{ m_%s->set(len, val); }\n", name);
                        break;
                    case EAM_basic:
                    default:
                        outf("{ m_%s=val; }\n", name);
                        break;
                    }
                }
            }
        }
    }
    else // get function
    {
        if (hasNilRemove && xlation->eam_type == EAM_basic && (flags & PF_TEMPLATE)==0 )
        {
            if (isDecl && isPure)
                outs("\tvirtual ");
            outf("bool ");
            if (!isDecl && msgname)
                outf("C%s::", msgname);
            outf("get%s_isNull()", methName);

            if (isDecl)
                outs((isPure) ? "=0;\n" : ";\n");
            else
                outf("{return m_%s.is_nil();}\n", name);
        }

        if (isDecl)
            outs("\t");
        if (isDecl && isPure)
            outs("virtual ");

        if (flags & PF_TEMPLATE)
        {
            outf("%s & ",getArrayImplType());
            if (!isDecl && msgname)
                outf("C%s::",msgname);
            outf("get%s()", methName);
        }
        else if (kind==TK_ESPSTRUCT)
        {
            outf("IConst%s & ", typname);
            if (!isDecl && msgname)
                outf("C%s::", msgname);
            outf("get%s()", methName);
        }
        else if (kind==TK_ESPENUM)
        {
            outf("C%s ", typname);
            if (!isDecl && msgname)
                outf("C%s::", msgname);
            outf("get%s()", methName);
        }
        else
        {
            switch (xlation->eam_type)
            {
            case EAM_jmbuf:
                outs("void ");
                if (!isDecl && msgname)
                    outf("C%s::", msgname);
                outf("get%s(%s val, unsigned int len)", methName, xlation->access_type);
                break;
            case EAM_jmbin:
            case EAM_basic:
            case EAM_jsbuf:
            default:
                outf("%s ", xlation->access_type);
                if (!isDecl && msgname)
                    outf("C%s::", msgname);
                outf("get%s()", methName);
                break;
            }
        }

        if (isDecl)
        {
            if (isPure)
                outs("=0");
            outs(";\n");
        }
        else
        {
            if (kind==TK_ESPSTRUCT)
            {
                outf(" { return (IConst%s &) m_%s.getValue();}\n", typname, name);
            }
            else if (kind==TK_ESPENUM)
            {
                outf(" { return m_%s.getValue(); }\n", name);
            }
            else if (flags & PF_TEMPLATE)
            {
                outf(" { return (%s &) m_%s; }\n", getArrayImplType(), name);
            }
            else
            {
                switch (xlation->eam_type)
                {
                case EAM_jsbuf:
                    outf(" { return m_%s.query();}\n", name);
                    break;
                case EAM_jmbuf:
                    outf(" { m_%s->read(len, val);}\n", name);
                    break;
                case EAM_jmbin:
                    outf(" { return m_%s.getValue();}\n", name);
                    break;
                case EAM_basic:
                default:
                    outf(" { return m_%s;}\n", name);
                    break;
                }
            }
        }

        // additonal method
        switch(kind)
        {
        case TK_ESPENUM:
            // getXXAsString
            if (!(flags & PF_TEMPLATE))
            {
                if (isDecl)
                    outs("\t");
                if (isDecl && isPure)
                    outs("virtual ");
                outs("const char* ");
                if (!isDecl && msgname)
                    outf("C%s::", msgname);
                outf("get%sAsString()", methName);

                if (isDecl)
                {
                    if (isPure)
                        outs("=0");
                    outs(";\n");
                }
                else
                    outf(" {  return (const char*)m_%s; }\n", name);
            }
            break;

        default:
            // nothing to do
            break;
        }
    }

    free(methName);
}


void ParamInfo::write_esp_client_impl()
{
    char *methName=strdup(name);
    *methName=upperchar(*methName);

    outf("\treq->set%s(%s_);\n", methName, name);
    free(methName);
}


void ParamInfo::write_esp_param()
{
    char metatype[256];
    *metatype=0;

    cat_type(metatype);

    esp_xlate_info *xlation=esp_xlat(metatype);

    if (kind==TK_ESPSTRUCT)
    {
        outf("IConst%s &%s_", typname, name);
    }
    else if (kind==TK_ESPENUM)
    {
        outf("C%s %s_", typname, name);
    }
    else
    {
        if (flags & PF_TEMPLATE)
        {
            if (templ && !strcmp(templ, "ESParray"))
            {
                /*if (isEspStringArray())
                    outf("StringArray &%s_", name);
                else
                    outf("IArrayOf<IConst%s> &%s_", typname, name);
                */
                outf("%s &%s_", getArrayImplType(), name);
            }
            else
            {
                switch (xlation->eam_type)
                {
                case EAM_jmbuf:
                    outf("%s %s_, unsigned int %s_len)", xlation->access_type, name, name);
                    break;
                case EAM_jmbin:
                case EAM_basic:
                case EAM_jsbuf:
                default:
                    outf("%s %s_", xlation->access_type, name);
                    break;
                }
            }

        }
        else
        {
            switch (xlation->eam_type)
            {
                case EAM_jmbuf:
                    outf("%s %s_, unsigned int %s_len", xlation->access_type, name, name);
                    break;
                case EAM_jmbin:
                case EAM_basic:
                case EAM_jsbuf:
                default:
                    outf("%s %s_", xlation->access_type, name);
                break;
            }
        }
    }
}

bool ParamInfo::write_mapinfo_check(int indents, const char* ctxvar)
{
    StrBuffer minVer, maxVer, deprVer;
    bool hasMin = getMetaVerInfo("min_ver", minVer);
    bool hasMax = getMetaVerInfo("max_ver", maxVer);
    bool hasDepr = getMetaVerInfo("depr_ver", deprVer);

    bool hasOutput = false;

    if (hasMin || hasDepr || hasMax)
    {
        hasOutput = true;
        indent(indents);
        outs("if ((clientVer==-1.0");
        if (hasMin)
        {
            if (hasDepr)
                outf(" || (clientVer>=%s && clientVer<%s))", minVer.str(), deprVer.str());
            else if (hasMax)
                outf(" || (clientVer>=%s && clientVer<=%s))", minVer.str(), maxVer.str());
            else
                outf(" || clientVer>=%s)", minVer.str());
        }
        else if (hasDepr)
            outf(" || clientVer<%s)", deprVer.str());
        else // maxVer>0
            outf(" || clientVer<=%s)", maxVer.str());
    }
    if (ctxvar)
    {
        const char* optional = getMetaString("optional",NULL);
        if (optional)
        {
            if (hasOutput)
                outs(" && ");
            else
            {
                indent(indents);
                outs("if (");
                hasOutput = true;
            }
            const char* quote = (*optional == '"') ? "":"\"";
            outf("(!ctx || %s->checkOptional(%s%s%s))", ctxvar, quote,optional,quote);
        }
    }

    if (hasOutput)
        outs(")\n");

    return hasOutput;
}

void ParamInfo::write_esp_marshall(bool isRpc, bool encodeXml, bool checkVer, int indents, bool encodeJson)
{
    const char *soap_path=getMetaString("soap_path", NULL);
    char *path = (soap_path!=NULL) ? strdup(soap_path) : NULL;
    char *tagname = NULL;

    if (path)
    {
        path[strlen(path)-1]=0;
        path++;
        tagname=strrchr(path, '/');
        if (tagname)
        {
            *tagname=0;
            tagname++;
        }
        else
        {
            tagname=path;
            path= (char *) ""; // cast to kill a warning. Could recode to avoid more cleanly but this is obsolete code anyway
        }
    }

    if (checkVer)
    {
        if (write_mapinfo_check(indents,"ctx"))
            indents++;
    }

    if (!isEspArrayOf() && getMetaInt("encode_newlines", -1)!=-1)
    {
        indent(indents);
        outf("m_%s.setEncodeNewlines(true);\n", name);
    }

    indent(indents);
    if (isRpc)
        outf("m_%s.marshall(rpc_resp, ", name);
    else
        outf("m_%s.toStr(ctx, buffer, ", name);

    if (isEspArrayOf())
    {
        if (path)
            outf("\"%s\", \"%s\", \"%s\");\n", tagname, getArrayItemTag(), path);
        else
            outf("\"%s\", \"%s\");\n", getXmlTag(), getArrayItemTag());
    }
    else
    {
        const char *prefix = getMetaString("ns_var", "\"\"");
        const char *encode = encodeXml ? "true" : "false";
        if (path)
        {
            outf("\"%s\", \"%s\"", tagname, path);
            if (isRpc)
                outf(", \"\", %s", prefix);
            else if (kind!=TK_ESPSTRUCT)
                outf(", %s", encode);
            outs(");\n");
        }
        else if (!getMetaInt("attribute"))
        {
            outf("\"%s\", \"\", ", getXmlTag());
            if (isRpc)
                outf("\"\", %s);\n", prefix);
            else if (kind==TK_ESPSTRUCT)
                outf("false, \"\", %s);\n", prefix);
            else
            {
                outf("%s, \"\", %s", encode, prefix);
                if (getMetaInt("json_inline", !encodeJson))
                    outs(", false");
                outs(");\n");
            }
        }
    }
}

const char* ParamInfo::getOptionalParam()
{
    static StrBuffer optGroup;
    StrBuffer optional;

    optGroup.clear();

    if (getMetaStringValue(optional,"optional"))
        optGroup.appendf(", \"%s\"", optional.str());

    return optGroup.str();
}

void ParamInfo::write_esp_unmarshall(const char *rpcvar, bool useBasePath, int indents)
{
    const char *soap_path=getMetaString("soap_path", NULL);
    char *path = (soap_path!=NULL) ? strdup(soap_path) : NULL;

    if (path && *path)
    {
        path[strlen(path)-1]=0;
        path++;
        char *tagname=strrchr((char *)path, '/');
        indent(indents);
        if (tagname)
        {
            *tagname=0;
            tagname++;
            outf("hasValue |= m_%s.unmarshall(%s, \"%s\", \"%s\"%s);\n", name, rpcvar, tagname, path, getOptionalParam());
        }
        else
        {
            outf("hasValue |= m_%s.unmarshall(%s, \"%s\"%s);\n", name, rpcvar, path, getOptionalParam());
        }
    }
    else
    {
        bool isAttr = getMetaInt("attribute")!=0;
        indent(indents);
        outf("hasValue |= m_%s.unmarshall(%s, \"%s%s\"%s%s);\n", name, rpcvar, isAttr ? "@" : "",getXmlTag(), (useBasePath) ? ", basepath" : "", getOptionalParam());
    }

    free(path);
}

void ParamInfo::write_esp_unmarshall_properties(const char *propvar, const char *attachvar, int indents)
{
    indent(indents);
    const char* at = getMetaInt("attribute") ? "@" : "";
    outf("hasValue |= m_%s.unmarshall(ctx, %s, %s, \"%s%s\", basepath%s);\n", name, propvar, attachvar, at, getXmlTag(), getOptionalParam());
}

void ParamInfo::write_esp_unmarshall_attachments(const char *propvar, const char *attachvar, int indents)
{
    indent(indents);
    const char* at = getMetaInt("attribute") ? "@" : "";
    outf("hasValue |= m_%s.unmarshallAttach(ctx, %s, %s, \"%s%s\", basepath%s);\n", name, propvar, attachvar, at, getXmlTag(), getOptionalParam());
}

void ParamInfo::write_esp_unmarshall_soapval(const char *var, int indents)
{
    indent(indents);
    const char* at = getMetaInt("attribute") ? "@" : "";
    outf("hasValue |= m_%s.unmarshall(ctx, %s, \"%s%s\"%s);\n", name, var, at, getXmlTag(), getOptionalParam());
}

//-------------------------------------------------------------------------------------------------------------
// class ProcInfo

ProcInfo::ProcInfo()
{
    name = NULL;
    rettype = NULL;
    params = NULL;
    next = NULL;
    conntimeout = NULL;
    calltimeout = NULL;
    async = 0;
    callback = 0;
    virt = 0;
    constfunc = 0;
}

ProcInfo::~ProcInfo()
{
    if (name)
        free(name);
    if (conntimeout)
        free(conntimeout);
    if (calltimeout)
        free(calltimeout);

    delete rettype;
    delete params;
    delete next;
}


void ProcInfo::out_method(const char *classpfx, int omitvirt)
{
    if (virt&&!omitvirt)
    {
        if (callback)
            outf("HRPCvirtualcallback ");
        else
            outf("virtual ");
    }

    if (rettype==NULL)
        outs("void");
    else
        rettype->out_type();

    if (classpfx)
        outf(" %s::%s",classpfx,name);
    else
        outf(" %s",name);

    out_parameter_list("");

    if (constfunc)
    {
        if (isSCM)
            outf(" const");
        else
            outf(" /* const (omitted by HIDL) */");
    }

    if ((virt==2)&&!omitvirt)
    {
        if (isSCM)
            outf(" = 0");
        else
            outf(" HRPCpure%s", callback ? "callback" : "");
    }
}

void ProcInfo::out_parameter_list(const char *pfx)
{
    outs("(");
    ParamInfo * p = params;
    while (p)
    {
        p->out_parameter(pfx);
        p = p->next;
        if (p)
            outs(", ");
    }
    outs(")");
}

void ProcInfo::write_body_method_structs2(const char * modname)
{
    // buffer structure
    outf("struct HRPC_d_%s__%s\n{\n",modname,name);
    ParamInfo *p;
    lastin=NULL;
    firstin=NULL;
    ForEachParam(this,p,0,0)
        p->flags &= ~PF_SIMPLE;
    size_t align=0;
    int dummy = 0;
    ForEachParam(this,p,PF_IN,PF_OUT|PF_REF|PF_PTR|PF_VARSIZE) {
        p->flags |= PF_SIMPLE;
        lastin = p;
        if (!firstin)
            firstin = p;
        size_t a=p->typesizealign(align);
        if (a>0) {
            dummy++;
            if (a>1)
                outf("\tchar __dummy%d[%u];\n",dummy,(unsigned)a);
            else
                outf("\tchar __dummy%d;\n",dummy);
        }
        p->write_body_struct_elem(0);
    }
    if (align>0) {
        dummy++;
        outf("\tchar _dummy%d[%u];\n",dummy,(unsigned)(4-align));
        align = 0;
    }
    ForEachParam(this,p,PF_IN,PF_OUT|PF_SIMPLE) {
        p->write_body_struct_elem(1);
    }
    ForEachParam(this,p,PF_IN|PF_OUT,PF_SIMPLE) {
        p->write_body_struct_elem(1);
    }
    ForEachParam(this,p,PF_OUT,PF_IN|PF_SIMPLE) {
        p->write_body_struct_elem(1);
    }
    if (rettype) {
        rettype->typesizealign(align);
        rettype->write_body_struct_elem(0);
        if (align>0) {
            dummy++;
            outf("\tchar _dummy%d[%u];\n",dummy,(unsigned)(4-align));
            align = 0;
        }
    }

    int swapp=write_body_swapparam();
    write_body_pushparam(swapp);
    write_body_popparam(swapp);
    if (!async) {
        write_body_pushreturn();
        write_body_popreturn();
    }

    // now constructors
    outf("\tHRPC_d_%s__%s() {}\n",modname,name);

    if (params) {
        outf("\tHRPC_d_%s__%s",modname,name);
        out_parameter_list("_");
        outs(": ");
        ForEachParam(this,p,0,0) {
            outf("%s(",p->name);
            if (p->flags&PF_REF) {
                outs("&");
            }
            else if ((p->flags&(PF_PTR&PF_CONST))==(PF_PTR&PF_CONST)) {
                p->write_param_convert();
            }
            outf("_%s)",p->name);
            if (p->next)
                outs(", ") ;
        }
        outs("\n\t{\n");
        outs("\t};");
    }
    outs("\n};\n");
}

void ProcInfo::write_body_popparam(int swapp)
{
    outs("\tvoid popparams(HRPCbuffer &_b)\n\t{\n");
    if (lastin) {
        outf("\t\t_b.read(&%s,",firstin->name);
        write_head_size();
        outs(");\n");
    }
    int needensure=0;
    ParamInfo *p;
    ForEachParam(this,p,PF_OUT,PF_IN|PF_SIMPLE) {
        if (needensure) {
            outs("\t\t\t+");
        }
        else {
            outs("\t\t_b.ensure(\n");
            outs("\t\t\t");
            needensure = 1;
        }
        if ((p->flags&PF_VARSIZE)&&!(INDIRECTSIZE(p))) {
            outf("(%s)\n",p->bytesize());
        }
        else {
            outf("sizeof(*%s)\n",p->name);
        }
    }
    if (needensure) {
        outs("\t\t);\n");
    }
    ForEachParam(this,p,PF_OUT,PF_IN|PF_SIMPLE|PF_VARSIZE|PF_STRING) {
        outf("\t\t%s = ",p->name);
        p->write_param_convert();
        outf("_b.writeptr(sizeof(*%s));\n",p->name);

    }
    ForEachParam(this,p,PF_OUT|PF_STRING,0) {
        outf("\t\t%s = ",p->name);
        p->write_param_convert();
        outf("_b.writeptr(sizeof(*%s));\n",p->name);
        outf("\t\t*%s = 0;\n",p->name);
    }
    ForEachParam(this,p,PF_IN,PF_SIMPLE|PF_VARSIZE|PF_STRING) {
        outf("\t\t%s = ",p->name);
        p->write_param_convert();
        outf("_b.readptr(sizeof(*%s));\n",p->name);
        outf("\t\t\t//_b.readptrrev(sizeof(*%s));\n",p->name);
    }
    ForEachParam(this,p,PF_IN|PF_STRING,PF_SIMPLE|PF_VARSIZE) {
        outf("\t\t%s = _b.readstrptr();\n",p->name);
    }
    // now dynamic sizes
    ForEachParam(this,p,PF_VARSIZE|PF_IN,0) {
        outf("\t\t%s = ",p->name);
        p->write_param_convert();
        if (INDIRECTSIZE(p)) {
            // should handle size_t* as well as ref
            outs("_b.readptr(sizeof");
            p->write_param_convert();
            outs(")\n");
        }
        else {
            outf("_b.readptr(%s);\n",p->bytesize());
        }
    }
    ForEachParam(this,p,PF_OUT|PF_VARSIZE,PF_IN|PF_SIMPLE) {
        outf("\t\t%s = ",p->name);
        p->write_param_convert();
        outs("_b.writeptr(");
        if ((p->flags&PF_VARSIZE)&&!(INDIRECTSIZE(p))) {
            outf("%s);\n",p->bytesize());
        }
        else {
            outf("sizeof(*%s));\n",p->name);
        }
    }
    if (swapp)
        outs("\t\t//swapparams();\n");
    outs("\t}\n\n");
}

void ProcInfo::write_body_popreturn()
{
    if (!async) {
        outs("\tvoid popreturn(HRPCbuffer &_b)\n\t{\n");
        ParamInfo *p;
        ForEachParam(this,p,PF_OUT,PF_SIMPLE|PF_VARSIZE|PF_RETURN|PF_STRING) {
            outf("\t\t_b.read(%s,sizeof(*%s));\n",p->name,p->name);
        }
        ForEachParam(this,p,PF_OUT|PF_STRING,0) {
            outf("\t\t*%s = _b.readstrdup();\n",p->name);
        }
        // now dynamic sizes
        ForEachParam(this,p,PF_VARSIZE|PF_OUT,0) {
            if (INDIRECTSIZE(p)) {
                outf("\t\t*%s = ",p->name);
                p->write_param_convert(1);
                outf("malloc(%s);\n",p->bytesize(1));
                outf("\t\t_b.read(*%s,%s);\n",p->name,p->bytesize(1));

            }
            else {
                outf("\t\t_b.read(%s,%s);\n",p->name,p->bytesize());
            }
        }
        p = rettype;
        if (p) {
            if ((p->flags&(PF_PTR|PF_STRING))==(PF_PTR|PF_STRING)) {
                outf("\t\t%s = _b.readstrdup();\n",p->name);
            }
            else if (p->flags&PF_PTR) {
                outf("\t\t%s = ",p->name);
                p->write_param_convert();
                outf("malloc(%s);\n",p->bytesize(1));
                outf("\t\t_b.read(%s,%s);\n",p->name,p->bytesize(1));
            }
            else {
                outf("\t\t_b.read(&%s,sizeof(%s));\n",p->name,p->name);
            }
        }
        outs("\t}\n\n");
    }
}

int ProcInfo::write_body_swapparam()
{
    int ret=0;
    ParamInfo *p;
    ForEachParam(this,p,PF_IN|PF_SIMPLE,PF_VARSIZE|PF_STRING) {
        if(p->simpleneedsswap()) {
            if (!ret) {
                outs("\tvoid swapparams()\n\t{\n");
                ret = 1;
            }
            outf("\t\t_WINREV%d(%s);\n",type_size[p->kind],p->name);
        }
    }
    if (ret)
        outs("\t}\n\n");
    return ret;
}


void ProcInfo::write_body_pushparam(int swapp)
{
    outs("\tvoid pushparams(HRPCbuffer &_b)\n\t{\n");
    if (swapp)
        outs("\t\t//swapparams();\n");
    if (lastin) {
        outf("\t\t_b.write(&%s,",firstin->name);
        write_head_size();
        outs(");\n");
    }
    ParamInfo *p;
    ForEachParam(this,p,PF_IN,PF_SIMPLE|PF_VARSIZE|PF_STRING) {
        if (p->simpleneedsswap()) {
            outf("\t\t//_b.writerev(%s,sizeof(*%s));\n",p->name,p->name);
            outf("\t\t_b.write(%s,sizeof(*%s));\n",p->name,p->name);
        }
        else
            outf("\t\t_b.write(%s,sizeof(*%s));\n",p->name,p->name);
    }
    ForEachParam(this,p,PF_IN|PF_STRING,PF_SIMPLE|PF_VARSIZE) {
        outf("\t\t_b.writestr(%s);\n",p->name);
    }
    // now dynamic sizes
    ForEachParam(this,p,PF_VARSIZE|PF_IN,0) {
        if (INDIRECTSIZE(p)) {
            // should handle size_t* as well as ref
            outf("\t\t_b.write(%s,%s);\n",p->name,p->bytesize());
        }
        else {
            outf("\t\t_b.write(%s,%s);\n",p->name,p->bytesize());
        }
    }
    outs("\t}\n\n");
}

void ProcInfo::write_body_pushreturn()
{
    if (!async) {
        outs("\tvoid pushreturn(HRPCbuffer &_b)\n\t{\n");
        ParamInfo *p;
        ForEachParam(this,p,PF_OUT,PF_SIMPLE|PF_VARSIZE|PF_STRING) {
            outf("\t\t_b.write(%s,sizeof(*%s));\n",p->name,p->name);
        }
        ForEachParam(this,p,PF_OUT|PF_STRING,0) {
            outf("\t\t_b.writestr(*%s);\n",p->name);
            outf("\t\tfree(*%s);\n",p->name);
        }
        // now dynamic sizes
        ForEachParam(this,p,PF_VARSIZE|PF_OUT,0) {
            if (INDIRECTSIZE(p)) {
                // should handle size_t* as well as ref
                outf("\t\t_b.write(*%s,%s);\n",p->name,p->bytesize(1));
                outf("\t\tfree(*%s);\n",p->name);

            }
            else {
                outf("\t\t_b.write(%s,%s);\n",p->name,p->bytesize());
            }
        }
        p = rettype;
        if (p) {
            if ((p->flags&(PF_PTR|PF_STRING))==(PF_PTR|PF_STRING)) {
                outf("\t\t_b.writestr(%s);\n",p->name);
                outf("\t\tfree(%s);\n",p->name);
            }
            else if (p->flags&PF_PTR) {
                outf("\t\t_b.write(%s,%s);\n",p->name,p->bytesize(1));
                outf("\t\tfree(%s);\n",p->name);
            }
            else {
                outf("\t\t_b.write(&%s,sizeof(%s));\n",p->name,p->name);
            }
        }
        outs("\t}\n\n");
    }
}

void ProcInfo::write_head_size()
// used for simple types only at the head of the packet
{
    if (lastin) {
        ParamInfo *p=params;
        ParamInfo *lp=NULL;
        while (1) {
            if (p->flags&PF_SIMPLE) {
                lp = p;
            }
            if(p==lastin)
                break;
            p = p->next;
        }
        if (lp==NULL)
            outs("0");
        else if (lp!=firstin)
            outf("sizeof(%s)+(byte *)&%s-(byte *)&%s",lp->name,lp->name,firstin->name);
        else
            outf("sizeof(%s)",firstin->name);
    }
    else
        outs("0");
}


//-------------------------------------------------------------------------------------------------------------
// class ApiInfo

ApiInfo::ApiInfo(const char *n)
{
    name = NULL;
    group = strdup(n);
    proc = NULL;
    next = NULL;
}

ApiInfo::~ApiInfo()
{
    if (name)
        free(name);
    if (proc)
        delete proc;
    if (group)
        free(group);
    delete next;
}


void ApiInfo::write_header_method()
{
    ProcInfo *pi = proc;
    if (!pi->callback)
    {
        outf("extern \"C\" %s_API ", group);
        pi->rettype->out_type();
        outf(" %s", pi->name);
        pi->out_parameter_list("");
        outs(";\n");
    }
}


//-------------------------------------------------------------------------------------------------------------
// class ModuleInfo

ModuleInfo::ModuleInfo(const char *n)
{
    name = strdup(n);
    base = NULL;
    version = 0;
    procs = NULL;
    next = NULL;
    isSCMinterface=false;
}

ModuleInfo::~ModuleInfo()
{
    free(name);
    if (base)
        free(base);

    delete procs;
    delete next;
}

void ModuleInfo::write_body_class()
{
    outf("// class %s \n\n",name);

    outf("static struct HRPCmoduleid _id_%s = { { ",name);
    char *mn = name;
    for (int i=0;i<8;i++)
    {
        if (i)
            outs(", ");
        if (*mn) {
            outf("'%c'",*mn);
            mn++;
        }
        else
            outs("0");
    }
    outf("}, %d };\n\n",version);

    for (ProcInfo *pi=procs; pi; pi=pi->next)
    {
        pi->write_body_method_structs2(name);
    }
    outs("\n");
    outf("%s::%s() { _id = &_id_%s; }\n\n",name,name,name);
    outf("#ifdef LOCAL_%s  // Stub(%s):\n\n",name,name);
    write_body_class_stub(0);
    write_body_class_proxy(1);
    outf("#else   // Proxy(%s):\n\n",name);
    write_body_class_proxy(0);
    write_body_class_stub(1);
    outf("\n#endif  // end class %s\n",name);
}

void ModuleInfo::write_body_class_proxy(int cb)
{
    int fn = 0;
    ProcInfo *pi;
    for (pi=procs; pi; pi=pi->next) {
        fn++;
        if (cb!=pi->callback)
            continue;
        pi->out_method(name,true);
        outs("\n{\n");
        if (pi->callback) {
            outs("\tHRPCcallframe _callframe(&_server->Sync(),cbbuff);\n");
        }
        else {
            outs("\tHRPCcallframe _callframe(sync,inbuff);\n");
        }
        outf("\tHRPC_d_%s__%s _params",name,pi->name);
        if (pi->params) {
            outs("(");
            ParamInfo *p;
            ForEachParam(pi,p,0,0) {
                outf("%s",p->name);
                if (p->next)
                    outs(", ");
            }
            outs(")");
        }
        outs(";\n");
        if (pi->conntimeout&&*pi->conntimeout) {
            outf("\tTryConnect(%s,false);\n",pi->conntimeout);
        }
        if (pi->calltimeout&&*pi->calltimeout) {
            outf("\tSetCallTimeLimit(%s);\n",pi->calltimeout);
        }
        if (pi->callback) {
            outs("\t_params.pushparams(cbbuff);\n");
            outf("\t_callbackproxy(_callframe,%d);\n",fn);
            if (!pi->async)
                outs("\t_params.popreturn(cbbuff);\n");
        }
        else {
            outs("\t_params.pushparams(inbuff);\n");
            outf("\t_proxy(_callframe,%d);\n",fn);
            if (!pi->async)
                outs("\t_params.popreturn(inbuff);\n");
        }
        if (pi->rettype) {
            outf("\treturn _params.%s;\n",RETURNNAME);
        }
        outs("}\n\n");
    }
    outs("\n\n");
}

void ModuleInfo::write_body_class_stub(int cb)
{
    outf("void %s::_%sstub(HRPCbuffer &_b,HRPCbuffer &_br,int fn)\n{\n",name,cb?"callback":"");
    int fn=0;
    int switchdone = 0;
    ProcInfo *pi;
    for (pi=procs; pi; pi=pi->next) {
        fn++;
        if (cb!=pi->callback)
            continue;
        if (!switchdone) {
            outs("\tswitch(fn) {\n");
            switchdone = 1;
        }
        outf("\tcase %d: {\n",fn);
        outf("\t\t\tHRPC_d_%s__%s _params;\n",name,pi->name);
        outs("\t\t\t_params.popparams(_b);\n");
        if (pi->async) {
            outs("\t\t\t_returnasync(_br);\n");
        }
        outs("\t\t\t");
        if (pi->rettype) {
            outf("_params.%s = ",RETURNNAME);
        }
        outf("%s(",pi->name);
        ParamInfo *p;
        ForEachParam(pi,p,0,0) {
            if (p->flags&PF_REF)
                outs("*");
            outf("_params.%s",p->name);
            if (p->next)
                outs(", ");
        }
        outs(");\n");
        if (!pi->async) {
            outs("\t\t\t_returnOK(_br);\n");
            outs("\t\t\t_params.pushreturn(_br);\n");
        }
        outs("\t\t\tbreak;\n");
        outs("\t\t}\n");
    }
    if (switchdone) {
        outs("\t}\n");
    }
    outs("}\n\n");
}

void ModuleInfo::write_define()
{
    outf("#define LOCAL_%s       // implementation of %s\n",name,name);
}

void ModuleInfo::write_example_module()
{
    outf("void %s_Server()\n",name);
    outs("{\n");
    outs("\tHRPCserver server(MakeTcpTransport(NULL,PORTNO)); // PORTNO TBD\n");
    outf("\t%s stub;\n",name);
    outs("\tserver.AttachStub(&stub);   // NB a server can service more than one module\n");
    outs("\tserver.Listen();\n");
    outs("}\n\n");
    ProcInfo *pi;
    for (pi=procs; pi; pi=pi->next) {
        pi->out_method(name,true);
        outs("\n{\n");
        outf("\t // TBD\n");
        if (pi->rettype) {
            outs("\treturn TBD;\n");
        }
        outs("}\n\n");
    }
}

void ModuleInfo::write_header_class()
{
    int hasvirts = 0;
    ProcInfo *pi;
    for (pi=procs; pi; pi=pi->next) {
        if (pi->virt) {
            hasvirts = 1;
            break;
        }
    }
    if (isSCM) {
        if (base)
            outf("interface %s : extends %s\n",name,base);
        else
            outf("interface %s\n",name);
        outs("{\n");
        for (pi=procs; pi; pi=pi->next) {
            outs("\t");
            pi->out_method();
            outs(";\n");
        }
        outs("};\n");
    }
    else {
        outf("#ifdef LOCAL_%s\n",name);
        outf("#define %s  STUB_%s\n",name,name);
        if (hasvirts) {
            outs("#define HRPCvirtual virtual\n");
            outs("#define HRPCpure    =0\n");
            outs("#define HRPCvirtualcallback\n");
            outs("#define HRPCpurecallback\n");
        }
        outf("class %s : public HRPCstub\n",name);
        outs("#else\n");
        if (hasvirts) {
            outs("#define HRPCvirtual\n");
            outs("#define HRPCpure\n");
            outs("#define HRPCvirtualcallback virtual\n");
            outs("#define HRPCpurecallback    =0\n");
        }

        outf("class %s : public HRPCmodule\n",name);
        outs("#endif\n");
        outs("{\npublic:\n");

        outf("\t%s();\n",name);
        for (pi=procs; pi; pi=pi->next) {
            outs("\t");
            pi->out_method();
            outs(";\n");
        }
        outf("private:\n");
        outf("#ifdef LOCAL_%s\n",name);
        outf("\tvoid _stub(HRPCbuffer &_b,HRPCbuffer &_rb,int fn);\n");
        outs("#else\n");
        outf("\tvoid _callbackstub(HRPCbuffer &_b,HRPCbuffer &_rb,int fn);\n");
        outs("#endif\n");
        if (hasvirts) {
            outs("#undef HRPCvirtual\n");
            outs("#undef HRPCpure\n");
            outs("#undef HRPCvirtualcallback\n");
            outs("#undef HRPCpurecallback\n");
        }
        outs("};\n");
    }
}

//-------------------------------------------------------------------------------------------------------------
// class EspMessageInfo

void EspMessageInfo::write_esp_ipp()
{
    ParamInfo *pi;
    const char *myparent = getParentName();

    if (espm_type_ == espm_enum)
    {
        //const char* defaultValue = getParams()->getMetaString("enum",NULL); // first enum item
        outf("class CX%s : public SoapEnumParamNew<C%s>\n",name_,name_);
        outf("{\n");
        outs("public:\n");
        outf("\tCX%s(nilBehavior nilB) : SoapEnumParamNew<C%s>(nilB)\n", name_, name_);
        outf("\t{ doInit(); }\n");
        outf("\tCX%s(C%s defvalue_) : SoapEnumParamNew<C%s>(defvalue_)\n", name_, name_, name_);
        outf("\t{ doInit(); }\n");
        outf("\tCX%s(const char* defvalue_) : SoapEnumParamNew<C%s>()\n", name_, name_);
        outf("\t{ doInit(); setDefaultValue(defvalue_); }\n");

        // getMapInfo()
        outs("\tstatic void getMapInfo(IMapInfo& info, BoolHash& added) { getSharedInstance().getMapInfo_(info,added); }\n\n");
        outf("\tstatic const char* stringOf(C%s val) { return getSharedInstance().toString(val); }\n\n",name_);
        outf("\tstatic C%s enumOf(const char* s) { return getSharedInstance().toEnum(s); }\n\n",name_);

        outf("static const char *queryXsdElementName() { return \"%s\"; }\n", name_);

        // internal: getSharedInstance()
        outs("private:\n");
        outf("\tstatic CX%s& getSharedInstance();\n", name_);

        // TODO: getMapInfo_() internal implementation
        outs("\tvoid getMapInfo_(IMapInfo& info, BoolHash& added) {  }\n");

        outf("\tvoid doInit();\n");

        outs("};\n\n");
        return;
    }


    ParamInfo *contentVar=NULL;

    for (pi=getParams();pi!=NULL;pi=pi->next)
    {
        if (pi->getMetaString("http_content", NULL)!=NULL)
        {
            contentVar=pi;
            break;
        }
    }

    const char *baseclass = myparent;
    if (!baseclass)
    {
        switch(espm_type_)
        {
        case espm_struct:
            baseclass="SoapComplexType";
            break;
        case espm_request:
            baseclass="SoapRequestBinding";
            break;
        default:
            baseclass="SoapResponseBinding";
            break;
        }
    }
    outf("class C%s : public C%s,\n", name_, baseclass);

    outf("   implements IEsp%s,\n", name_);
    outf("   implements IClient%s\n", name_);
    outs("{\n");

    outs("protected:\n");
    for (pi=getParams();pi!=NULL;pi=pi->next)
    {
        pi->write_esp_declaration();
    }

    if (getMetaInt("element")!=0)
        outs(1, "StringBuffer m_tag_value;\n");

    if (contentVar!=NULL)
        outf("\tStringBuffer m_%s_mimetype;\n", contentVar->name);

    outs("\n\tvoid *m_eventSink = nullptr;\n");
    outs("\n\tIInterface* m_RequestState = nullptr;\n");
    outs("\tStringBuffer m_serviceName;\n");
    outs("\tStringBuffer m_methodName;\n");
    outs("\tStringBuffer m_msgName;\n");

    outs("\n\tlong soap_reqid = 0;\n");
    outs("\tMutex m_mutex;\n");
    outs("public:\n");
    outs("\tIMPLEMENT_IINTERFACE;\n");

    //default constructor
    outf("\n\tC%s(const char *serviceName, const char *bcompat);\n", name_);
    outf("\n\tC%s(const char *serviceName, IRpcMessageBinding *init=NULL);", name_);

    if (espm_type_==espm_struct)
    {
        //Raw message constructor
        //outf("\n\tC%s(const char *serviceName, const char * msg);", name_);
    }
    else
    {
        //rpc message constructor
        outf("\n\tC%s(const char *serviceName, IRpcMessage* rpcmsg);", name_);

        //IProperties constructor
        outf("\n\tC%s(IEspContext* ctx, const char *serviceName, IProperties *params, MapStrToBuf *attachments);", name_);
    }

    if (espm_type_==espm_request)
        outs("\n\tIEspClientRpcSettings &rpc(){return *static_cast<IEspClientRpcSettings*>(this);}\n\n");

    outf("\n\tvirtual const char *getNsURI(){return %s;}\n", getMetaString("ns_uri", "NULL"));
    outf("\n\tvirtual const char *getNsPrefix(){return %s;}\n", getMetaString("ns_var", "NULL"));
    outs("\n\tvirtual const char *getRootName(){return m_msgName.str();}\n");

    outs("\n\tvoid setMsgName(const char *msgname)\n");
    outs("\t{\n");
    outs("\t\tm_msgName.set(msgname);\n");
    outs("\t}\n\n");

    outs("\tstatic const char *queryXsdElementName()\n");
    outs("\t{\n");
    outf("\t\treturn \"%s\";\n", name_);
    outs("\t}\n\n");

    //method ==> getMapInfo
    outs("\tstatic void getMapInfo(IMapInfo& info);\n");
    outs("\tstatic void getMapInfo(IMapInfo& info, BoolHash& added);\n");

    //method ==> hasCustomHttpContent
    outs("\tstatic bool hasCustomHttpContent()\n");
    outs("\t{\n");
    if (contentVar)
        outs("\t\treturn true;\n");
    else
        outs("\t\treturn false;\n");
    outs("\t}\n");

    //method ==> serialize (IRpcMessage&)
    outs("\n\tvoid serialize(IRpcMessage& rpc_resp);\n");

    //method ==> copy
    outf("\n\tvoid copy(C%s &from);\n", name_);

    //method ==> copy from interface
    outf("\n\tvoid copy(IConst%s &ifrom);\n", name_);

    //method ==> serializeContent (StringBuffer&)
    outs("\n\tvoid serializeContent(IEspContext* ctx, StringBuffer& buffer, IProperties **pprops=NULL);\n");
    outs("\n\tvoid serializeAttributes(IEspContext* ctx, StringBuffer& s);\n");
    outs("\n\tvoid getAttributes(IProperties &attributes);\n");

    //method ==> serialize (StringBuffer&)
    outf("\n\tstatic void serializer(IEspContext* ctx, IConst%s &ifrom, StringBuffer& buffer, bool keepRootTag=true);\n", name_);

    //method ==> serialize (MemoryBuffer&, StringBuffer &)
    if (contentVar)
        outs("\n\tvoid appendContent(IEspContext* ctx, MemoryBuffer& buffer, StringBuffer &mimetype);\n");

    outs("\tvoid setEventSink(void * val){m_eventSink=val;}\n");
    outs("\tvoid * getEventSink(){return m_eventSink;}\n");

    outs("\tvoid setState(IInterface * val){m_RequestState = val;}\n");
    outs("\tIInterface * queryState(){return m_RequestState;}\n");

    outs("\tvoid setMethod(const char * method){m_methodName.set(method);}\n");
    outs("\tconst char * getMethod(){return m_methodName.str();}\n\n");
    outs("\tvoid setReqId(unsigned val){soap_reqid=val;}\n");
    outs("\tunsigned getReqId(){return soap_reqid;}\n\n");

    outs("\tvoid lock(){m_mutex.lock();}\n");
    outs("\tvoid unlock(){m_mutex.unlock();}\n\n");

    if (getMetaInt("element")!=0)
    {
        outs(1, "void set_tag_value(const char * value){m_tag_value.set(value);}\n");
        outs(1, "const char * get_tag_value(){return m_tag_value.str();}\n\n");
    }

    outs("\n\tbool unserialize(IRpcMessage& rpc_request, const char *tagname, const char *basepath);\n");
    if (myparent)
    {
        outs("\n\tbool localUnserialize(IRpcMessage& rpc_request, const char *tagname, const char *basepath);\n");
        outs("\n\tbool unserialize(IEspContext* ctx, CSoapValue& soapval, bool localOnly=false);\n");
        outs("\n\tbool unserialize(IEspContext* ctx, IProperties& params, MapStrToBuf *attachments, const char *basepath=NULL, bool localOnly=false);\n");
    }
    else
    {
        outs("\n\tbool unserialize(IEspContext* ctx, CSoapValue& soapval);\n");
        outs("\n\tbool unserialize(IEspContext* ctx, IProperties& params, MapStrToBuf *attachments, const char *basepath=NULL);\n");
    }

    if (espm_type_==espm_response)
    {
        outs("\n\tvirtual void setRedirectUrl(const char *url)\n");
        outs("\t{ CSoapResponseBinding::setRedirectUrl(url); }\n");


        outs("\n\tvirtual const IMultiException& getExceptions()\n");
        outs("\t{ return CSoapResponseBinding::getExceptions(); }\n");

        outs("\n\tvirtual int queryClientStatus()\n");
        outs("\t{ return CSoapResponseBinding::getRpcState(); }\n");

        outs("\n\tvirtual void noteException(IException& e)\n");
        outs("\t{  CSoapResponseBinding::noteException(e); }\n");
    }

    outs("\n");
    write_esp_methods(espaxm_both, true, false);
    outs("};\n\n");
}

bool EspMessageInfo::hasMapInfo()
{
    for (ParamInfo* pi=getParams();pi!=NULL;pi=pi->next)
        if (pi->hasMapInfo())
            return true;
    return false;
}

void EspMessageInfo::write_esp()
{
    if (espm_type_ == espm_enum)
    {
        outf("CX%s& CX%s::getSharedInstance() { static CX%s instance(nilIgnore); return instance; }\n", name_, name_, name_);

        outf("void CX%s::doInit()\n", name_);
        outs("{\n");
        outs("\tstatic const char* inits[] = {");

        for (ParamInfo* pi = getParams(); pi!=NULL; pi=pi->next)
        {
            if (strcmp(parent,"string")==0)
            {
                const char* def = pi->getMetaString("enum",NULL);
                outf("%s", def);
            }
            else if (strcmp(parent,"int")==0 || strcmp(parent,"short")==0)
            {
                int def = pi->getMetaInt("enum");
                outf("\"%d\"",def);
            }
            else if (strcmp(parent,"double")==0 || strcmp(parent,"float")==0)
            {
                double def = pi->getMetaDouble("enum");
                outf("\"%g\"",def);
            }
            else
                throw "Unhandled base type";

            outs(",");
        }
        outs("NULL};\n");
        outf("\tinit(\"%s\",\"%s\",inits);\n",name_,parent);
        outs("}\n");

        return;
    }

    const char *myparent=getParentName();

    ParamInfo *contentVar=NULL;
    ParamInfo *pi=NULL;

    bool removeNil=(getMetaInt("nil_remove", 0)!=0);
    for (pi=getParams();pi!=NULL;pi=pi->next)
    {
        if (pi->getMetaString("http_content", NULL)!=NULL)
        {
            contentVar=pi;
            break;
        }
    }

    //comment
    outs("\n//=======================================================");
    outf("\n// class C%s Implementation", name_);
    outs("\n//=======================================================");
    outs("\n");

    //default constructor
    outf("\nC%s::C%s(const char *serviceName, IRpcMessageBinding *init)", name_, name_);
    bool isFirstInited=true;
    if (myparent)
    {
        outf(" : C%s(serviceName, init)", myparent);
        isFirstInited=false;
    }

    for (pi=getParams();pi!=NULL;pi=pi->next)
    {
        pi->write_esp_init(isFirstInited, removeNil);
    }
    if (contentVar)
    {
        outs((isFirstInited) ? "\n\t: " : ",");
        outf("m_%s_mimetype(%s)", contentVar->name, contentVar->getMetaString("http_content", "\"text/xml; charset=UTF-8\""));
    }
    outs("\n{\n");
    outs("\tm_eventSink=NULL;\n");
    outs("\tm_RequestState=NULL;\n");

    outs("\tm_serviceName.append(serviceName);\n");
    outf("\tm_msgName.append(\"%s\");\n", name_);
    outs("\tif (init)\n");
    outs("\t{\n");
    outs("\t\tsetClientValue(init->getClientValue());\n");
    outs("\t\tsetReqId(init->getReqId());\n");
    outs("\t\tsetEventSink(init->getEventSink());\n");
    outs("\t\tsetState(init->queryState());\n");
    outs("\t\tsetThunkHandle(init->getThunkHandle());\n");
    outs("\t\tsetMethod(init->getMethod());\n");
    outs("\t}\n");

    outs("}\n");

    outf("\nC%s::C%s(const char *serviceName, const char *bc)", name_, name_);
    isFirstInited=true;
    if (myparent)
    {
        outf(" : C%s(serviceName)", myparent);
        isFirstInited=false;
    }

    for (pi=getParams();pi!=NULL;pi=pi->next)
    {
        pi->write_esp_init(isFirstInited, removeNil);
    }
    if (contentVar)
    {
        outs((isFirstInited) ? " : " : ", ");
        outf("m_%s_mimetype(%s)", contentVar->name, contentVar->getMetaString("http_content", "\"text/xml; charset=UTF-8\""));
    }
    outs("\n{\n");
    outs("\tm_eventSink=NULL;\n");
    outs("\tm_RequestState=NULL;\n");

    outs("\tm_serviceName.append(serviceName);\n");
    outf("\tm_msgName.append(\"%s\");\n", name_);
    outs("}\n");

    if (espm_type_==espm_struct)
    {
        //Raw message constructor
        /*
        outf("\nC%s::C%s(const char *serviceName, const char * msg)", name_, name_);
        isFirstInited=true;
        if (myparent)
        {
            outf(" : C%s(serviceName, msg)", myparent);
            isFirstInited=false;
        }
        for (pi=getParams();pi!=NULL;pi=pi->next)
        {
            pi->write_esp_init(isFirstInited, removeNil);
        }
        if (contentVar)
        {
            outs((isFirstInited) ? " : " : ", ");
            outf("m_%s_mimetype(%s)", contentVar->name, contentVar->getMetaString("http_content", "\"text/xml; charset=UTF-8\""));
        }

        outs("\n\t{\n\t\tm_eventSink=NULL;\n");
        outs("\t\tm_RequestState=NULL;\n");
        outs("\t\tm_serviceName.append(serviceName);\n");
        outf("\t\tm_msgName.append(\"%s\");\n", name_);
        outs("\t\tunserialize(msg);\n\t}\n");
        */
    }
    else
    {
        //rpc message constructor
        outf("\nC%s::C%s(const char *serviceName, IRpcMessage* rpcmsg)", name_, name_);
        isFirstInited=true;
        if (myparent)
        {
            outf(" : C%s(serviceName, rpcmsg)", myparent);
            isFirstInited=false;
        }
        for (pi=getParams();pi!=NULL;pi=pi->next)
        {
            pi->write_esp_init(isFirstInited, removeNil);
        }
        if (contentVar)
        {
            outs((isFirstInited) ? " : " : ", ");
            outf("m_%s_mimetype(%s)", contentVar->name, contentVar->getMetaString("http_content", "\"text/xml; charset=UTF-8\""));
        }
        outs("\n{\n");
        outs("\tm_eventSink=NULL;\n");
        outs("\tm_RequestState=NULL;\n");
        outs("\tm_serviceName.append(serviceName);\n");
        outf("\tm_msgName.append(\"%s\");\n", name_);
        if (myparent)
            outs("\tlocalUnserialize(*rpcmsg,NULL,NULL);\n");
        else
            outs("\tunserialize(*rpcmsg,NULL,NULL);\n");
        outs("}\n");

        //IProperties constructor
        outf("\nC%s::C%s(IEspContext* ctx, const char *serviceName, IProperties *params, MapStrToBuf *attachments)", name_, name_);
        isFirstInited=true;
        if (myparent)
        {
            outf(" : C%s(ctx, serviceName, params, attachments)", myparent);
            isFirstInited=false;
        }
        for (pi=getParams();pi!=NULL;pi=pi->next)
        {
            pi->write_esp_init(isFirstInited, removeNil);
        }
        if (contentVar)
        {
            outs((isFirstInited) ? " : " : ", ");
            outf("m_%s_mimetype(%s)", contentVar->name, contentVar->getMetaString("http_content", "\"text/xml; charset=UTF-8\""));
        }

        outs("\n{\n\tm_eventSink=NULL;\n");
        outs("\tm_RequestState=NULL;\n");
        outs("\tm_serviceName.append(serviceName);\n");
        outf("\tm_msgName.append(\"%s\");\n", name_);
        if (myparent)
            outs("\tunserialize(ctx,*params,attachments, NULL,true);\n}\n");
        else
            outs("\tunserialize(ctx,*params,attachments, NULL);\n}\n");
    }

    //=======================================================================================
    //method ==> getMapInfo
    outf("\nvoid C%s::getMapInfo(IMapInfo& info) {  BoolHash added; getMapInfo(info, added); }\n",name_);

    outf("\nvoid C%s::getMapInfo(IMapInfo& info, BoolHash& added)\n",name_);
    outf("{\n");

    for (pi=getParams();pi!=NULL;pi=pi->next)
    {
        if (pi->hasMapInfo())
        {
            StrBuffer ver;
            bool hasVer = pi->getMetaVerInfo("min_ver",ver);
            if (hasVer)
                outf("\tinfo.addMinVersion(\"%s\",\"%s\",%s);\n", name_, pi->name, ver.str());

            hasVer = pi->getMetaVerInfo("depr_ver",ver.clear());
            if (hasVer)
                outf("\tinfo.addDeprVersion(\"%s\",\"%s\",%s);\n", name_, pi->name, ver.str());

            hasVer = pi->getMetaVerInfo("max_ver",ver.clear());
            if (hasVer)
                outf("\tinfo.addMaxVersion(\"%s\",\"%s\",%s);\n", name_, pi->name, ver.str());

            const char* opt = pi->getMetaString("optional", NULL);
            if (opt)
            {
                const char* quote = (*opt=='"' || *opt=='\'') ? "" : "\"";
                outf("\tinfo.addOptional(\"%s\",\"%s\",%s%s%s);\n", name_, pi->name,quote,opt,quote);
            }
        }
    }

    outs("}\n");

    indentReset();

    //method ==> serialize (IRpcMessage&)
    outf("\nvoid C%s::serialize(IRpcMessage& rpc_resp)\n{\n", name_);
    if (parent)
        outf("\tC%s::serialize(rpc_resp);\n", parent);

    // versioning
    if (hasMapInfo())
    {
        outf("\tIEspContext* ctx = rpc_resp.queryContext();\n");
        outf("\t[[maybe_unused]] double clientVer= ctx ? ctx->getClientVersion() : -1; /* no context gets everything */\n");
    }

    outf("\trpc_resp.set_ns(%s);\n", getMetaString("ns_var", "\"\""));
    outs("\trpc_resp.set_name(m_msgName.str());\n");

    const char *nsuri = getMetaString("ns_uri", NULL);
    if (nsuri)
        outf("\trpc_resp.set_nsuri(%s);\n\n", nsuri);
    else
    {
        outs("\tStringBuffer nsuri;\n");
        outs("\tnsuri.append(\"urn:hpccsystems:ws:\").appendLower(m_serviceName.length(), m_serviceName.str());\n");
        outs("\trpc_resp.set_nsuri(nsuri.str());\n\n");
    }

    int soap_encode = getMetaInt("soap_encode", -1);
    if (soap_encode ==-1)
        soap_encode = getMetaInt("encode", 1);
    if (soap_encode==0)
        outs("\trpc_resp.setEncodeXml(false);\n");

    if (espm_type_==espm_response)
    {
        outs(
            "\tconst IMultiException& exceptions = getExceptions();\n"
            "\tif (exceptions.ordinality() > 0)\n"
            "\t{\n"
            "\t\tStringBuffer xml;\n"
            "\t\texceptions.serialize(xml, 0, true, false);\n"
            "\t\trpc_resp.add_value(\"\", \"\", \"Exceptions\", \"\", xml.str(), false);\n"
            "\t}\n"
            "\telse\n"
            "\t{\n");
    }
    //attributes first
    int attrCount=0;
    for (pi=getParams();pi!=NULL;pi=pi->next)
    {
        if (pi->getMetaInt("attribute"))
        {
            attrCount++;
            if (attrCount==1)
                outs(1, "Owned<IProperties> props=createProperties();\n");

            outf(1, "if (!m_%s.is_nil())\n", pi->name);
            outf(2, "props->setProp(\"%s\", m_%s.getValue());\n", pi->getXmlTag(), pi->name);
        }
    }

    if (attrCount!=0)
        outs(1, "rpc_resp.add_attr(NULL, NULL, NULL, *props.get());\n");

    for (pi=getParams();pi!=NULL;pi=pi->next)
    {
        pi->write_esp_marshall(true, true, true, (espm_type_==espm_response)?2:1);
    }

    if (espm_type_==espm_response)
        outs("\t}\n");

    outs("}\n\n");

    //method ==> copy
    outf("\nvoid C%s::copy(C%s &from)\n{\n", name_, name_);
    if (parent)
    {
        outf(1, "C%s *baseFrom = static_cast<C%s*>(&from);\n", parent, parent);
        outf(2, "C%s::copy(*baseFrom);\n", parent);
    }
    for (pi=getParams();pi!=NULL;pi=pi->next)
        outf("\tm_%s.copy(from.m_%s);\n", pi->name, pi->name);
    if (getMetaInt("element"))
        outf("\tset_tag_value(from.get_tag_value());\n");
    outs("}\n\n");

    //method ==> copy from interface
    outf("\nvoid C%s::copy(IConst%s &ifrom)\n{\n", name_, name_);
    if (parent)
    {
        outf(1, "C%s *classFrom = static_cast<C%s*>(&ifrom);\n", name_, name_);
        outf(1, "IConst%s *baseICFrom = static_cast<IConst%s*>(classFrom);\n", parent, parent);
        outf(2, "C%s::copy(*baseICFrom);\n", parent);
    }
    for (pi=getParams();pi!=NULL;pi=pi->next)
    {
        char *uname=strdup(pi->name);
        *uname=upperchar(*uname);

        outf("\tset%s(ifrom.get%s());\n", uname, uname);
        free(uname);
    }
    if (getMetaInt("element"))
        outf("\tset_tag_value(ifrom.get_tag_value());\n");
    outs("}\n\n");

    //method ==> getAttributes (IProperties &attributes)
    outf("\nvoid C%s::getAttributes(IProperties &attributes)\n{\n", name_);
    for (pi=getParams(); pi!=NULL; pi=pi->next)
    {
        if (pi->getMetaInt("attribute"))
            outf(2, "attributes.setProp(\"%s\", m_%s.getValue());\n", pi->getXmlTag(), pi->name);
    }
    outs("}\n\n");

    //method ==> serializeContent (StringBuffer&)
    outf("\nvoid C%s::serializeContent(IEspContext* ctx, StringBuffer& buffer, IProperties **pprops)\n{\n", name_);
    int http_encode = getMetaInt("http_encode", -1);
    if (http_encode ==-1)
        http_encode = getMetaInt("encode", 1);
    bool encodeXML = http_encode==1;
    if (espm_type_==espm_response)
    {
        outs(
            "\tconst IMultiException& exceptions = getExceptions();\n"
            "\tif (exceptions.ordinality() > 0)\n"
            "\t{\n"
            "\t\tif(ctx && ctx->getResponseFormat()==ESPSerializationJSON)\n"
            "\t\t\texceptions.serializeJSON(buffer, 0, true);\n"
            "\t\telse\n"
            "\t\t\texceptions.serialize(buffer, 0, true);\n"
            "\t}\n"
            "\telse\n"
            "\t{\n");
        if (parent)
            outf("\t\tC%s::serializeContent(ctx,buffer);\n", parent);

        if (hasMapInfo())
            outf("\t\t[[maybe_unused]] double clientVer = ctx ? ctx->getClientVersion() : -1;\n");

        bool encodeJSON = true;
        const char * name = getName();
        unsigned nameLength = strlen(name);
        if (nameLength >= 2)
        {
            const char * nameEnding = &name[nameLength - 2];
            bool isResponseEx = strcmp(nameEnding, "Ex") == 0;
            encodeJSON = !(isResponseEx && (stricmp(getParams()->getXmlTag(), "Response") == 0));
        }

        for (pi=getParams();pi!=NULL;pi=pi->next)
        {
            if (!pi->getMetaInt("attribute"))
                pi->write_esp_marshall(false, encodeXML, true, 2, encodeJSON);
        }
        outs("\t}\n");
    }
    else
    {
        if (parent)
            outf("\tC%s::serializeContent(ctx,buffer);\n", parent);
        if (hasMapInfo())
            outf("\t[[maybe_unused]] double clientVer = ctx ? ctx->getClientVersion() : -1;\n");
        //attributes first
        int attribCount=0;
        for (pi=getParams();pi!=NULL;pi=pi->next)
        {
            if (pi->getMetaInt("attribute"))
            {
                attribCount++;
                if (attribCount==1)
                {
                    outs(1, "if (pprops)\n");
                    outs(1, "{\n");
                    outs(2, "*pprops=NULL;\n");
                }

                outf(2, "if (!m_%s.is_nil())\n", pi->name);
                outs(2, "{\n");
                outs(3, "if (!*pprops)\n");
                outs(4, "*pprops=createProperties();\n");
                outf(3, "(*pprops)->setProp(\"%s\", m_%s.getValue());\n", pi->getXmlTag(), pi->name);
                outs(2, "}\n");
            }
        }
        if (attribCount!=0)
            outs(1, "}\n");

        for (pi=getParams();pi!=NULL;pi=pi->next)
        {
            if (!pi->getMetaInt("attribute"))
                pi->write_esp_marshall(false, encodeXML, true);
        }

        if (getMetaInt("element")!=0)
        {
            outs(1, "if (m_tag_value.length()) {\n");
            outs(2, "StringBuffer encoded;\n");
            outs(2, "encodeXML(m_tag_value, encoded);\n");
            outs(2, "buffer.append(encoded);\n");
            outs(1, "}\n");
        }
    }

    outs("}\n\n");

    //method ==> serialize (StringBuffer&)
    outf("\nvoid C%s::serializeAttributes(IEspContext* ctx, StringBuffer& s)\n{\n", name_);

    for (pi=getParams();pi!=NULL;pi=pi->next)
    {
        if (pi->getMetaInt("attribute"))
        {
            outf(1, "if (!m_%s.is_nil()) {\n", pi->name);
            outf(2, "StringBuffer enc;\n");
            outf(2, "encodeXML(m_%s.getValue(), enc);\n", pi->name);
            outf(2, "s.appendf(\" %s=\\\"%%s\\\"\", enc.str());\n", pi->getXmlTag());
            outf(1, "}\n");
        }
    }
    outs("}\n");

    //method ==> serializer(IEspContext* ctx, ..., StringBuffer&, ...)
    outf("\nvoid C%s::serializer(IEspContext* ctx, IConst%s &src, StringBuffer& buffer, bool keepRootTag)\n{\n", name_, name_);

    // attributes
    int nAttrs = 0;
    for (pi=getParams();pi!=NULL;pi=pi->next)
        if (pi->getMetaInt("attribute"))
            nAttrs++;

    if (nAttrs)
    {
        outf(1,"if (keepRootTag)\n\t{\n");
        outf(2,"buffer.append(\"<%s\");\n", name_);
        for (pi=getParams();pi!=NULL;pi=pi->next)
        {
            if (pi->getMetaInt("attribute"))
            {
                char* fname = getFieldName(pi->name);
                outf(2, "%sattr = src.get%s();\n", (pi==getParams())?"const char* ":"", fname);
                free(fname);
                outf(2, "if (attr && *attr) {\n");
                outf(3, "StringBuffer encoded;\n");
                outf(3, "encodeXML(attr,encoded);\n");
                outf(3, "buffer.appendf(\" %s=\\\"%%s\\\"\",encoded.str());\n", pi->getXmlTag());
                outf(2, "}\n");
            }
        }
        outf(2,"buffer.append(\">\");\n");
        outf(1,"}\n");
    }
    else
        outf(1,"if (keepRootTag)\n\tbuffer.append(\"<%s>\");\n", name_);

    if (parent)
    {
        outf(1, "C%s *classSrc = static_cast<C%s*>(&src);\n", name_, name_);
        outf(1, "C%s *baseSrc = static_cast<C%s*>(classSrc);\n", parent, parent);
        outf(2, "C%s::serializer(ctx, *baseSrc, buffer, false);\n",parent);
    }

    // -- versioning
    if (hasMapInfo())
    {
        outf("\t[[maybe_unused]] double clientVer = ctx ? ctx->getClientVersion() : -1;\n");
    }

    // not respecting nil_remove: backward compatible
    for (pi=getParams();pi!=NULL;pi=pi->next)
    {
        if (pi->getMetaInt("attribute"))
            continue;

        outf("\t// field %s\n", pi->name);

        char *uname=getFieldName(pi->name);

        if (pi->flags & PF_TEMPLATE) // array
        {
            outf("\t{\n");
            if (pi->isPrimitiveArray())
            {
                const char *item_tag = pi->getMetaString("item_tag", "Item");
                const char *type = pi->getArrayImplType();
                outf("\t\t%s& v = src.get%s();\n",type,uname);
                outf("\t\tif (v.length()>0)\n");
                outf("\t\t\tbuffer.append(\"<%s>\");\n", pi->getXmlTag());
                outf("\t\tfor (size32_t i=0;i<v.length();i++)\n");

                const char* fmt = "%"; // print %% when undefined
                switch(pi->kind)
                {
                case TK_BOOL:
                case TK_SHORT:
                case TK_INT: fmt = "d"; break;
                case TK_UNSIGNED: fmt = "u"; break;
                case TK_LONG: fmt = "ld"; break;
                case TK_UNSIGNEDLONG: fmt = "lu"; break;
                case TK_FLOAT:
                case TK_DOUBLE: fmt = "g"; break;
                case TK_null:
                case TK_CHAR: fmt = "s"; break;
                default:
                    {
                        char buf[128];
                        sprintf(buf,"Unhandled array type: %s (%s)", getTypeKindName(pi->kind), name_);
                        yyerror(buf);
                    }
                }

                outf("\t\t\tbuffer.appendf(\"<%s>%%%s</%s>\",v.item(i));\n",item_tag,fmt,item_tag);
                outf("\t\tif (v.length()>0)\n");
                outf("\t\t\tbuffer.append(\"</%s>\");\n", pi->getXmlTag());
            }
            else if (pi->typname)
            {
                if (pi->kind == TK_ESPENUM)
                {
                    outf("\t\t%sArray& v = src.get%s();\n",pi->typname,uname);
                    outf("\t\tint size = v.length();\n");
                    const char *item_tag = pi->getMetaString("item_tag", "Item");
                    outf("\t\tif (size>0)\n");
                    outf("\t\t\tbuffer.append(\"<%s>\");\n", pi->getXmlTag());
                    outf("\t\tfor (int i=0;i<size;i++)\n");
                    //outf("\t\t{\n");
                    outf("\t\t\tbuffer.appendf(\"<%s>%%s</%s>\", CX%s::stringOf(v.item(i)));\n",item_tag, item_tag, pi->typname);
                    //outf("\t\t\tC%s::serializer(ctx,v.item(i),buffer,false);\n",pi->typname);
                    //outf("\t\t\tbuffer.append(\"</%s>\");\n",item_tag);
                    //outf("\t\t}\n");
                    outf("\t\tif (size>0)\n");
                    outf("\t\t\tbuffer.append(\"</%s>\");\n", pi->getXmlTag());
                }
                else if (pi->kind == TK_ESPSTRUCT || pi->kind == TK_null) // should be fixed at lex/yacc
                {
                    outf("\t\tIArrayOf<IConst%s>& v = src.get%s();\n",pi->typname,uname);
                    outf("\t\tint size = v.length();\n");
                    const char *item_tag = pi->getMetaString("item_tag", "Item");
                    outf("\t\tif (size>0)\n");
                    outf("\t\t\tbuffer.append(\"<%s>\");\n", pi->getXmlTag());
                    outf("\t\tfor (int i=0;i<size;i++)\n");
                    outf("\t\t{\n");
                    outf("\t\t\tbuffer.append(\"<%s>\");\n",item_tag);
                    outf("\t\t\tC%s::serializer(ctx,v.item(i),buffer,false);\n",pi->typname);
                    outf("\t\t\tbuffer.append(\"</%s>\");\n",item_tag);
                    outf("\t\t}\n");
                    outf("\t\tif (size>0)\n");
                    outf("\t\t\tbuffer.append(\"</%s>\");\n", pi->getXmlTag());
                }
                else
                    outf("\t\t**** TODO: unhandled array: kind=%s, type=%s, name=%s, xsd-type=%s\n", getTypeKindName(pi->kind), pi->typname, uname, pi->getXsdType());
            }
            else
            {
                outf("\t\t**** TODO: unhandled array: type=<NULL>, name=%s, xsd-type=%s\n", uname, pi->getXsdType());
            }
            outf("\t}\n");
        }
        else if (pi->kind == TK_ESPSTRUCT)
        {
            outf("\t{\n");
            outf("\t\tStringBuffer tmp;\n");
            outf("\t\tC%s::serializer(ctx,src.get%s(), tmp, false);\n", pi->typname, uname);
            outf("\t\tif (tmp.length()>0)\n");
            const char* tag = pi->getXmlTag();
            outf("\t\t\tbuffer.appendf(\"<%s>%%s</%s>\",tmp.str());\n", tag, tag);
            outf("\t}\n");
        }
        else if (pi->kind == TK_ESPENUM)
        {
            outs("\t{\n");
            outf("\t\tconst char* s = src.get%sAsString();\n",uname);
            outf("\t\tbuffer.append(\"<%s>\");\n",pi->getXmlTag());
            outs("\t\tencodeUtf8XML(s,buffer);\n");
            outf("\t\tbuffer.append(\"</%s>\");\n",pi->getXmlTag());
            outs("\t}\n");
        }
        else
        {
            esp_xlate_info* info = esp_xlat(pi);
            switch(info->access_kind)
            {
            case TK_CHAR:
                outf("\t{\n");
                outf("\t\tconst char* s = src.get%s();\n", uname);
                outf("\t\tif (s && *s)\n");
                if (!getMetaInt("encode",1))
                {
                    outf("\t\tbuffer.appendf(\"<%s>%%s</%s>\",s);\n",pi->name,pi->name);
                }
                else
                {
                    outf("\t\t{\n");
                    outf("\t\t\tbuffer.append(\"<%s>\");\n", pi->getXmlTag());
                    outf("\t\t\tencodeUtf8XML(s,buffer);\n");
                    outf("\t\t\tbuffer.append(\"</%s>\");\n", pi->getXmlTag());
                    outf("\t\t}\n");
                }
                outf("\t}\n");
                break;

            case TK_INT:
            case TK_SHORT:
                {
                    outf("\t{\n");
                    outf("\t\t%s n = src.get%s();\n", esp_xlat(pi)->access_type, uname);
                    outf("\t\tif (n)\n");
                    const char* tag = pi->getXmlTag();
                    outf("\t\t\tbuffer.appendf(\"<%s>%%d</%s>\", n);\n", tag, tag);
                    outf("\t}\n");
                    break;
                }
            case TK_LONG:
                {
                    outf("\t{\n");
                    outf("\t\t%s n = src.get%s();\n", esp_xlat(pi)->access_type, uname);
                    outf("\t\tif (n)\n");
                    const char* tag = pi->getXmlTag();
                    outf("\t\t\tbuffer.appendf(\"<%s>%%\" I64F \"d</%s>\", n);\n", tag, tag);
                    outf("\t}\n");
                    break;
                }
            case TK_BOOL:
                {
                    outf("\t{\n");
                    outf("\t\t%s b = src.get%s();\n", esp_xlat(pi)->access_type, uname);
                    outf("\t\tif (b)\n");
                    const char* tag = pi->getXmlTag();
                    outf("\t\t\tbuffer.appendf(\"<%s>1</%s>\");\n", tag, tag);
                    outf("\t}\n");
                    break;
                }

            default:
                if (pi->kind == TK_STRUCT && info->eam_type == EAM_jmbin) // binary
                {
                    //TODO: should we encode binary data?
                    outf("\t{\n");
                    outf("\t\tStringBuffer tmp;\n");
                    outf("\t\tJBASE64_Encode(src.get%s().toByteArray(), src.get%s().length(), tmp, true);\n", uname, uname);
                    outf("\t\tif (tmp.length()>0)\n");
                    const char* tag = pi->getXmlTag();
                    outf("\t\t\tbuffer.appendf(\"<%s>%%s</%s>\",tmp.str());\n", tag, tag);
                    outf("\t}\n");
                }
                else
                {
                    outf("\t{\n");
                    outf("\t\t//*** default kind: %s; type=%s, name=%s\n", getTypeKindName(pi->kind), pi->typname, uname);
                    outf("\t\tbuffer.append(\"<%s>\");\n", pi->getXmlTag());
                    outf("\t\tbuffer.append(src.get%s());\n", uname);
                    outf("\t\tbuffer.append(\"</%s>\");\n", pi->getXmlTag());
                    outf("\t}\n");
                }
                break;
            }
        }
        free(uname);
    }


    outf("\tif (keepRootTag)\n\t\tbuffer.append(\"</%s>\");\n", name_);
    outs("}\n");



    //=============================================================================================================
    //method ==> serialize (MemoryBuffer&, StringBuffer &)
    if (contentVar)
    {
        outf("\nvoid C%s::appendContent(IEspContext* ctx, MemoryBuffer& buffer, StringBuffer &mimetype)\n{\n", name_);
        esp_xlate_info *xinfo = esp_xlat(contentVar);

        if (strcmp(xinfo->store_type, "StringBuffer")!=0)
            outf("\tbuffer.clear().append(m_%s.getValue());\n", contentVar->name);
        else
            outf("\tbuffer.clear().append(m_%s.getValue().length(), m_%s.getValue().str());\n", contentVar->name, contentVar->name);

        outf("\tmimetype.set(m_%s_mimetype.str());\n", contentVar->name);
        outs("}\n");
    }

    //=============================================================================================================
    //method: unserialize(IRcpMessage...)
    outf("\nbool C%s::unserialize(IRpcMessage& rpc_request, const char *tagname, const char *basepath)\n{\n", name_);
    if (parent)
    {
        outf("\tbool hasValue = C%s::unserialize(rpc_request, tagname, basepath);\n", parent);
        outf("\treturn hasValue | localUnserialize(rpc_request, tagname, basepath);\n");
        outs("}\n");

        //method: localUnserialize(IRcpMessage...)
        outf("\nbool C%s::localUnserialize(IRpcMessage& rpc_request, const char *tagname, const char *basepath)\n{\n", name_);
    }

    outs("\trpc_request.setEncodeXml(false);\n");
    outs("\tbool hasValue = false;\n");

    if (espm_type_==espm_response)
    {
        outs(
            "\tStringBuffer xml;\n"
            "\trpc_request.get_value(\"Exceptions\", xml, false);\n\n"

            "\tOwned<IMultiException> me = MakeMultiException();\n"
            "\tif(xml.length() > 0)\n"
            "\t\tme->deserialize(xml.str());\n\n"

            "\tif (me->ordinality() > 0 )\n"
            "\t{\n"
            "\t\tIArrayOf<IException>& exceptions = me->getArray();\n"
            "\t\tForEachItemIn(i, exceptions)\n"
            "\t\t\tnoteException(*LINK(&exceptions.item(i)));\n"
            "\t}\n"
            "\telse\n"
            "\t{\n");
    }

    for (pi=getParams();pi!=NULL;pi=pi->next)
    {
        pi->write_esp_unmarshall("rpc_request", true, (espm_type_==espm_response)?2:1);
    }

    if (getMetaInt("element"))
    {
        outs(1, "hasValue |= rpc_request.get_value(basepath, m_tag_value);\n");
    }

    if (espm_type_==espm_response)
        outs("\t}\n");

    outs("\treturn hasValue;\n");

    outs("}\n");

    //=============================================================================================================
    //method: unserialize(CSoapValue...)
    if (parent)
    {
        outf("\nbool C%s::unserialize(IEspContext* ctx, CSoapValue& soapval, bool localOnly)\n{\n", name_);
        outf("\tbool hasValue = false;\n");
        outf("\tif(!localOnly)\n");
        outf("\t\thasValue |= C%s::unserialize(ctx,soapval);\n", parent);
    }
    else
    {
        outf("\nbool C%s::unserialize(IEspContext* ctx, CSoapValue& soapval)\n{\n", name_);
        outf("\tbool hasValue = false;\n");
    }

    for (pi=getParams();pi!=NULL;pi=pi->next)
    {
        pi->write_esp_unmarshall_soapval("soapval");
    }
    if (getMetaInt("element"))
        outs(1, "hasValue |= soapval.get_value(\"\",m_tag_value);\n");

    outs("\treturn hasValue;\n");
    outs("}\n");

    //=============================================================================================================
    //method: unserialize(IProperties...)
    if (parent)
    {
        outf("\nbool C%s::unserialize(IEspContext* ctx, IProperties& params, MapStrToBuf *attachments, const char *basepath, bool localOnly)\n{\n", name_);
        outf("\tbool hasValue = false;\n");
        outf("\tif(!localOnly)\n");
        outf("\t\thasValue |= C%s::unserialize(ctx,params,attachments, basepath);\n", parent);
    }
    else
    {
        outf("\nbool C%s::unserialize(IEspContext* ctx, IProperties& params, MapStrToBuf *attachments, const char *basepath)\n{\n", name_);
        outf("\tbool hasValue = false;\n");
    }

    for (pi=getParams();pi!=NULL;pi=pi->next)
    {
        if (pi->typname && !strcmp(pi->typname, "EspTextFile"))
        {
            pi->write_esp_unmarshall_attachments("params", "attachments");
            indent(1);
            outf("hasValue |= m_%s_name.unmarshall(ctx, params, attachments, \"%s\", basepath%s);\n", pi->name, pi->name, pi->getOptionalParam());
        }
        else
            pi->write_esp_unmarshall_properties("params", "attachments");;
    }
    if (getMetaInt("element"))
    {
        outs(1, "const char* val = params.queryProp(basepath);\n");
        outs(1, "if (val && *val) {\n");
        outs(2, "m_tag_value.set(val);\n");
        outs(2, "hasValue = true;\n");
        outs(1, "}\n");
    }

    outs("\treturn hasValue;\n");
    outs("}\n");

    //outf("\n\tvoid C%s::unserialize(const char * msg)\n\t{\n", name_);

    //for (pi=getParams();pi!=NULL;pi=pi->next)
    //{
    //  pi->write_esp_unmarshall("msg");
    //}
    //outs("\t}\n\n");

    outs("\n");
    write_esp_methods();

    //outs("};\n\n");

    write_factory_impl();
}

void EspMessageInfo::write_esp_mapinfo(bool isDecl)
{
#ifdef MAP_INFO
    outs("\nstatic IEspMapInfo& getMapInfo();");
#endif
}

char* makeXsdType(const char* s)
{
    if (!s)
        return NULL;

    if (*s == '"')
        s++;
    if (strncmp(s,"tns:",4)==0)
    {
        s+=4;
        size_t len = strlen(s);
        if (*(s+len-1)=='"')
            len--;
        char* t = (char*)malloc(len+1);
        memcpy(t,s,len);
        t[len] = 0;
        return t;
    }
    else
        return NULL;
}

void EspMessageInfo::write_esp_methods(enum espaxm_type axstype, bool isDecl, bool isPure)
{
    ParamInfo *pi;


    if (axstype!=espaxm_setters)
    {
        for (pi=getParams();pi!=NULL;pi=pi->next)
        {
            char* xsd = makeXsdType(pi->getMetaString("format_as",NULL));
            pi->write_esp_attr_method(name_, false, getMetaInt("nil_remove")!=0, isDecl, isPure, getMetaInt("trim")!=0,xsd);
            if (xsd)
                free(xsd);
        }
    }

    if (axstype!=espaxm_getters)
    {
        for (pi=getParams();pi!=NULL;pi=pi->next)
        {
            char* xsd = makeXsdType(pi->getMetaString("format_as",NULL));
            pi->write_esp_attr_method(name_, true, getMetaInt("nil_remove")!=0, isDecl, isPure, getMetaInt("trim")!=0,xsd);
            if (xsd)
                free(xsd);
        }
    }
}

void EspMessageInfo::write_esp_parms(bool isClientImpl)
{
    ParamInfo *pi=getParams();

    if (pi)
    {
        if (isClientImpl)
            pi->write_esp_client_impl();
        else
            pi->write_esp_param();

        for (pi=pi->next;pi!=NULL;pi=pi->next)
        {
            if (isClientImpl)
                pi->write_esp_client_impl();
            else
            {
                outs(", ");
                pi->write_esp_param();
            }
        }
    }
}

void EspMessageInfo::write_esp_client_method(const char *serv, const char *respname, const char *methname, bool isDecl, bool isPure)
{
    outs("\n");
    if (isDecl)
        outs("\tvirtual ");
    outf("IClient%s *", respname);
    if (!isDecl && !isPure)
        outf("CClient%s::", serv);
    outf("%sFn(", methname);
    write_esp_parms(false);
    outs(")");

    if (isPure)
        outs("=0");
    if (isDecl)
        outs(";\n");
    else
    {
        outs("\n{\n");
        outf("\tOwned<IClient%s> req =  create%sRequest();\n", name_, methname);
        write_esp_parms(true);
        outf("\treturn %s(req.get());\n", methname);
        outs("}\n");
    }

}

void EspMessageInfo::write_cpp_interfaces()
{
    if (espm_type_ == espm_enum)
    {
        // C enum type
        outf("enum C%s { %s_Undefined=-1,", name_, name_);

        const char* base = getParentName();
        assert(base);
        bool isIntBase = strieq(base,"int") || strieq(base,"long") || strieq(base,"uint") || strieq(base,"short");
        for (ParamInfo* pi=getParams();pi!=NULL;pi=pi->next)
        {
            outf("C%s_%s", name_, pi->name);
            if (isIntBase) {
                int v = pi->getMetaInt("enum",-1);
                if (v==-1)
                    outf("*** invalid value of Enum type");
                outf("=%d",v);
            }
            outs(", ");
        }
        outs("};\n");

        // array of values
        outf("typedef ArrayOf<C%s> %sArray;\n", name_, name_);
        return;
    }

    outf("interface IConst%s : extends ", name_);
    switch (espm_type_)
    {
    case espm_request:
        outs("IEspRequest\n{\n");
        break;
    case espm_response:
        outs("IEspResponse\n{\n");
        break;
    case espm_struct:
        outs("IEspStruct\n{\n");
        break;
    case espm_enum:
    case espm_none:
        assert(!"Code shouldn't be reached");
        break;
    }

    write_esp_methods(espaxm_getters, true, true);

    if (getMetaInt("element")!=0)
        outs(1, "virtual const char * get_tag_value()=0;\n");

    outs("};\n\n");


    outf("interface IEsp%s : extends IConst%s\n{\n", name_, name_);
    write_esp_methods(espaxm_setters, true, true);
    outf("\tvirtual void copy(IConst%s &from)=0;\n", name_);
    if (getMetaInt("element"))
        outs(1, "virtual void set_tag_value(const char *value)=0;\n");
    outs("};\n\n");

    outf("interface IClient%s : extends IInterface\n", name_);
    outs("{\n");

    switch (espm_type_)
    {
    case espm_request:
        outs("\n\tvirtual IEspClientRpcSettings &rpc() = 0;\n\n");
        write_esp_methods(espaxm_setters, true, true);
        write_esp_mapinfo(true);
        break;
    case espm_response:
        outs("\n\tvirtual int queryClientStatus()=0;\n");
        write_esp_methods(espaxm_getters, true, true);
        if (getMetaInt("exceptions_inline")!=0)
            outs("\n\tvirtual const IMultiException& getExceptions()=0;\n");
        write_esp_mapinfo(true);
        break;
    case espm_struct:
        write_esp_methods(espaxm_setters, true, true);
        write_esp_methods(espaxm_getters, true, true);
        break;
    case espm_enum:
    case espm_none:
        assert(!"Code shouldn't be reached");
        break;
    }

    outs("};\n\n");
}

void EspMessageInfo::write_factory_decl()
{
    switch (espm_type_)
    {
    case espm_struct:
        outf("extern \"C\" %s IEsp%s *create%s(const char *serv=NULL, const char *msgname=NULL);\n", esp_def_export_tag.c_str(), name_, name_);
        outf("extern \"C\" %s IClient%s *createClient%s(const char *serv=NULL, const char *msgname=NULL);\n", esp_def_export_tag.c_str(), name_, name_);
        break;
    case espm_request:
    case espm_response:
        outf("extern \"C\" %s IEsp%s *create%s(const char *serv=NULL);\n", esp_def_export_tag.c_str(), name_, name_);
        outf("extern \"C\" %s IClient%s *createClient%s(const char *serv=NULL);\n", esp_def_export_tag.c_str(), name_, name_);
        break;
    case espm_enum:
        // no factory for enum
        return;

    default:
        assert(!"Unhandled espm type");
    }
}

void EspMessageInfo::write_factory_impl()
{
    switch (espm_type_)
    {
    case espm_struct:
        outf("extern \"C\" %s IEsp%s *create%s(const char *serv, const char *msgname){return ((IEsp%s *)new C%s(serv /*, msgname*/));}\n", esp_def_export_tag.c_str(), name_, name_, name_, name_);
        outf("extern \"C\" %s IClient%s *createClient%s(const char *serv, const char *msgname){return ((IClient%s *)new C%s(serv /*, msgname*/));}\n", esp_def_export_tag.c_str(), name_, name_, name_, name_);
        break;
    case espm_request:
    case espm_response:
        outf("extern \"C\" %s IEsp%s *create%s(const char *serv){return ((IEsp%s *)new C%s(serv));}\n", esp_def_export_tag.c_str(), name_, name_, name_, name_);
        outf("extern \"C\" %s IClient%s *createClient%s(const char *serv){return ((IClient%s *)new C%s(serv));}\n", esp_def_export_tag.c_str(), name_, name_, name_, name_);
        break;
    case espm_enum:
        break;
    default:
        assert(!"Unhandled espm type");
    }
}


EspMessageInfo *EspMethodInfo::getRequestInfo()
{
    EspMessageInfo *msg = hcp->msgs;

    for(;msg!=NULL; msg=msg->next)
    {
        if (!strcmp(msg->getName(), request_))
            return msg;
    }
    return NULL;
}

bool EspMethodInfo::write_mapinfo_check(const char* ctxvar)
{
    StrBuffer minVer, maxVer;
    bool hasMin = getMetaVerInfo("min_ver", minVer);
    bool hasMax = getMetaVerInfo("max_ver", maxVer);

    bool hasOutput = false;
    if (hasMin || hasMax)
    {
        hasOutput = true;
        indentOuts("if (");
        if (hasMin && hasMax)
            outf("(%s.getClientVersion()>=%s && %s.getClientVersion()<=%s)", ctxvar, minVer.str(), ctxvar, maxVer.str());
        else if (hasMin)
            outf("%s.getClientVersion()>=%s", ctxvar,minVer.str());
        else
            outf("%s.getClientVersion()<=%s", ctxvar,maxVer.str());
    }
    const char* optional = getMetaString("optional", NULL);
    if (optional)
    {
        if (hasOutput)
            outs(" && ");
        else
        {
            indentOuts("if (");
            hasOutput = true;
        }
        const char* quote = (*optional == '"') ? "":"\"";
        outf("%s.checkOptional(%s%s%s)", ctxvar, quote,optional,quote);
    }

    if (hasOutput)
    {
        outs(") {\n");
        indentInc(1);
    }

    return hasOutput;
}

void EspMethodInfo::write_esp_method(const char *serv, bool isDecl, bool isPure)
{
    EspMessageInfo *req = getRequestInfo();

    if (req)
    {
        req->write_esp_client_method(serv, getResp(), name_, isDecl, isPure);
    }
}

void EspServInfo::write_factory_impl()
{
    outs("extern \"C\"");
    if (!esp_def_export_tag.empty())
        outf(" %s", esp_def_export_tag.c_str());
    outf(" IClient%s * create%sClient() {  return new CClient%s(); }\n", name_, name_, name_);
}


using HidlAccessMapGenerator = TAccessMapGenerator<const char*>;

using HidlAccessMapScopeMapper = HidlAccessMapGenerator::ScopeMapper;

struct HidlAccessMapLevelMapper : public HidlAccessMapGenerator::LevelMapper
{
    const char* levelUnavailable() const override { return "SecAccess_Unavailable"; }
    const char* levelNone() const override { return "SecAccess_None"; }
    const char* levelDeferred() const override { return "SecAccess_None"; }
    const char* levelAccess() const override { return "SecAccess_Access"; }
    const char* levelRead() const override { return "SecAccess_Read"; }
    const char* levelWrite() const override { return "SecAccess_Write"; }
    const char* levelFull() const override { return "SecAccess_Full"; }
    const char* levelUnknown() const override { return "SecAccess_Unknown"; }

    bool isEqual(const char* lhs, const char* rhs) const override
    {
        return (lhs != nullptr && rhs != nullptr && strieq(lhs, rhs));
    }

    const char* toString(const char* level) const override
    {
        return level;
    }
};

struct HidlAccessMapReporter : public HidlAccessMapGenerator::Reporter
{
    StrBuffer indent;

    HidlAccessMapReporter(int tabs)
    {
        for (int tabindex = 0; tabindex < tabs; tabindex++)
            indent.append('\t');
    }

    bool reportInfo() const override { return false; }
    bool reportDebug() const override { return false; }

    void preEntry(size_t termCount) const override
    {
        outf("%sMapStringTo<SecAccessFlags> accessmap;\n", indent.str());
    }
    void entry(const char* name, const char* level) const override
    {
        outf("%saccessmap.setValue(\"%s\", %s);\n", indent.str(), name, level);
    }

protected:

    __attribute__((format(printf,2,0)))
    void reportError(const char* fmt, va_list& args) const override
    {
        reportSomething("\nERROR: ", fmt, args);
    }

    __attribute__((format(printf,2,0)))
    void reportWarning(const char* fmt, va_list& args) const override
    {
        reportSomething("//WARNING: ", fmt, args);
    }

    __attribute__((format(printf,2,0)))
    void reportInfo(const char* fmt, va_list& args) const override
    {
        reportSomething("//INFO: ", fmt, args);
    }

    __attribute__((format(printf,2,0)))
    void reportDebug(const char* fmt, va_list& args) const override
    {
        reportSomething("//DEBUG: ", fmt, args);
    }

    __attribute__((format(printf,3,0)))
    inline void reportSomething(const char* prefix, const char* fmt, va_list& args) const
    {
        outs(prefix);
        voutf(fmt, args);
        outs("\n");
    }
};

void writeAccessMap(int indentLevel, EspServInfo& svci, const char* serviceName, const char* serviceFragment, EspMethodInfo& mthi)
{
    HidlAccessMapScopeMapper scopeMapper({"EsdlService", "EsdlMethod"});
    HidlAccessMapLevelMapper levelMapper;
    HidlAccessMapReporter    reporter(indentLevel);
    HidlAccessMapGenerator   generator(scopeMapper, levelMapper, reporter);

    generator.setVariable("service", serviceName);
    generator.setVariable("method", mthi.getName());
    generator.insertScope("EsdlService", serviceFragment);
    generator.insertScope("EsdlMethod", mthi.getMetaString(FEATEACCESSATTRIBUTE, NULL));
    generator.setDefaultSecurity("${service}Access:FULL");
    generator.generateMap();
}

void EspServInfo::write_esp_binding_ipp()
{
    EspMethodInfo *mthi=NULL;

    outf("\n\nclass C%sSoapBinding : public CHttpSoapHidlBinding\n", name_);
    outs("{\npublic:\n");

    //dom
    outf("\tC%sSoapBinding(http_soap_log_level level=hsl_none);\n", name_);
    outf("\tC%sSoapBinding(IPropertyTree* cfg, const char *bindname=NULL, const char *procname=NULL, http_soap_log_level level=hsl_none);\n", name_);

    outs("\tvirtual void init_strings();\n");
    outs("\tvoid init_metrics();\n");
    outs("\tvoid init_maps();\n");

    outs("\tvirtual unsigned getCacheMethodCount(){return m_cacheMethodCount;}\n");

    //method ==> processRequest
    outs("\tvirtual int processRequest(IRpcMessage* rpc_call, IRpcMessage* rpc_response);\n");

    // method ===> getServiceXmlFilename
    outs("\tint getServiceXmlFilename(StringBuffer &filename);\n");

    //method ==> getQualifiedNames
    outs("\tint getQualifiedNames(IEspContext& ctx, MethodInfoArray & methods);\n");

    //method ==> getServiceName
    outs("\tStringBuffer & getServiceName(StringBuffer &resp);\n");

    //method ==> isValidServiceName
    outs("\tbool isValidServiceName(IEspContext &context, const char *name);\n");

    //method ==> qualifyServiceName
    outs("\tbool qualifyServiceName(IEspContext &context, const char *servname, const char *methname, StringBuffer &servQName, StringBuffer *methQName);\n");

    //method ==> onGetFile
    outs("\tvirtual int onGetFile(IEspContext &context, CHttpRequest* request, CHttpResponse* response, const char *pathex);\n");

    //Method ==> onGetForm
    outs("\tvirtual int onGetForm(IEspContext &context, CHttpRequest* request, CHttpResponse* response, const char *service, const char *method);\n");

    //Method ==> onGetXForm
    outs("\tvirtual int onGetXForm(IEspContext &context, CHttpRequest* request, CHttpResponse* response, const char *service, const char *method);\n");

    //Method ==> supportGeneratedForms
    if (getMetaInt("noforms", 0))
        outs("\tvirtual bool supportGeneratedForms(){return false;}\n");

    if (getMetaInt("no_ws_index", 0))
    {
        //Method ==> onGetIndex
        outs("\tvirtual int onGetIndex(IEspContext &context, CHttpRequest* request, CHttpResponse* response, const char *service)\n");
        outs("\t{\n");
        outs("\t\treturn onGetNotFound(context, request, response, service);\n");
        outs("\t}\n");
    }

    //Method ==> onGetService
    outs("\tvirtual int onGetService(IEspContext &context, CHttpRequest* request, CHttpResponse* response, const char *service, const char *method, const char *pathex);\n");

    //Method ==> createReqBinding
    outs(1, "virtual IRpcRequestBinding *createReqBinding(IEspContext &context, IHttpMessage* request, const char *service, const char *method);\n");

    //Method ==> onGetInstantQuery
    outs("\tvirtual int onGetInstantQuery(IEspContext &context, CHttpRequest* request, CHttpResponse* response, const char *service, const char *method);\n");

    //Method ==> getDefaultClientVersion
    outs("\tvirtual bool getDefaultClientVersion(double &ver);\n");

    //Method ==> xslTransform
    if (needsXslt)
    {
        outs(1, "void setXslProcessor(IInterface *xslp_)\n");
        outs(1, "{\n");
        outs(2, "IXslProcessor *ixslp = dynamic_cast<IXslProcessor *>(xslp_);\n");
        outs(2, "if (!ixslp)\n");
        outs(3, "xslp.clear();\n"); //set(NULL) would basically be same, but be explicit
        outs(2, "else\n");
        outs(3, "xslp.set(ixslp);\n");
        outs(1, "}\n");
        outs("private:\n");

        outs("\tOwned<IXslProcessor> xslp;\n");
        outs("\tvoid xslTransform(const char* xml, const char* xslFile, StringBuffer& output, IProperties *params)\n"
            "\t{\n"
            "\t\tif (xslp)\n"
            "\t\t{\n"
            "\t\t\tOwned<IXslTransform> xform = xslp->createXslTransform();\n"
            "\t\t\tStringBuffer xslpath;\n"
            "\t\t\tif (!strnicmp(xslFile, \"/esp/xslt/\", 10))\n"
            "\t\t\t\tif (!checkFileExists(xslpath.append(getCFD()).append(\"smc_xslt/\").append(xslFile+10).str()) && !checkFileExists(xslpath.append(getCFD()).append(\"xslt/\").append(xslFile+10).str()))\n"
            "\t\t\t\t\treturn;\n"
            "\t\t\txform->loadXslFromFile((xslpath.length()) ? xslpath.str() : xslFile);\n"
            "\t\t\txform->setXmlSource(xml, strlen(xml)+1);\n"
            "\t\t\tif (params) xform->copyParameters(params);\n"
            "\t\t\txform->transform(output.clear());\n"
            "\t\t}\n"
            "\t}\n");
    }
    else
        outs("\tvoid setXslProcessor(IInterface *xslp){}\n");

    outs("\tunsigned m_cacheMethodCount = 0;\n");

    outs("protected:\n");

    //
    // Create scaled histogram metric member variables enabled methods
    // Always output, even if they are never initialised to prevent problems
    // where the header is included with inconsistent #defines
    for (mthi = methods; mthi != NULL; mthi = mthi->next)
    {
        if (mthi->isExecutionProfilingEnabled())
        {
            outs("\tstd::shared_ptr<hpccMetrics::ScaledHistogramMetric> ");
            outs(mthi->getExecutionProfilingMetricVariableName());
            outs(";\n");
        }
    }

    outs("};\n\n");
}

void EspServInfo::write_esp_binding(const char *packagename)
{
    EspMethodInfo *mthi=NULL;
    StrBuffer wsdlVer;
    bool hasVersion = getMetaVerInfo(tags,"version",wsdlVer);
    if (!hasVersion)
        wsdlVer.append("1");

    //comment
    outs("\n//=======================================================");
    outf("\n// class C%sSoapBinding Implementation", name_);
    outs("\n//=======================================================");
    outs("\n");

    StrBuffer servicefeatureurl;
    getMetaStringValue(servicefeatureurl,FEATEACCESSATTRIBUTE);

    outf("\nC%sSoapBinding::C%sSoapBinding(http_soap_log_level level):CHttpSoapHidlBinding(NULL, NULL, NULL, level)\n", name_, name_);
    outf("{\n");
    outf("\tinit_strings();\n");
    outf("\tsetWsdlVersion(%s);\n", wsdlVer.str());
    outf("}\n");

    outf("\nC%sSoapBinding::C%sSoapBinding(IPropertyTree* cfg, const char *bindname, const char *procname, http_soap_log_level level):CHttpSoapHidlBinding(cfg, bindname, procname, level)\n", name_, name_);
    outf("{\n");
    outf("\tinit_strings();\n");
    outf("\tinit_metrics();\n");
    outf("\tinit_maps();\n");
    outf("\tsetWsdlVersion(%s);\n", wsdlVer.str());
    outf("}\n");

    outf("\nvoid C%sSoapBinding::init_strings()\n", name_);
    outs("{\n");

    bool cacheDefined = false;
    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        StrBuffer val;
        mthi->getMetaStringValue(val,"description");
        if (val.length()) {
            StrBuffer tmp;
            outf("\taddMethodDescription(\"%s\", \"%s\");\n", mthi->getName(), printfEncode(val.str(), tmp).str());
        }
        mthi->getMetaStringValue(val.clear(),"help");
        if (val.length()) {
            StrBuffer tmp;
            outf("\taddMethodHelp(\"%s\", \"%s\");\n", mthi->getName(), printfEncode(val.str(), tmp).str());
        }
        int cacheGlobal = mthi->getMetaInt("cache_global", 0);
        int cacheSeconds = mthi->getMetaInt("cache_seconds", -1);
        if (cacheSeconds > -1) {
            cacheDefined = true;
            if (cacheGlobal > 0)
                outf("\tsetCacheTimeout(\"%s\", %d, 1);\n", mthi->getName(), cacheSeconds);
            else
                outf("\tsetCacheTimeout(\"%s\", %d, 0);\n", mthi->getName(), cacheSeconds);
            outs("\tm_cacheMethodCount++;\n");

            StrBuffer methodCacheGroupID;
            mthi->getMetaStringValue(methodCacheGroupID,"cache_group");
            if (methodCacheGroupID.length() > 0)
                outf("\tsetCacheGroupID(\"%s\", \"%s\");\n", mthi->getName(), methodCacheGroupID.str());
        }
    }

    StrBuffer serviceCacheGroupID;
    if (cacheDefined)
    {
        getMetaStringValue(serviceCacheGroupID,"cache_group");
        if (serviceCacheGroupID.length() == 0)
            serviceCacheGroupID.set(name_);
        outf("\tsetCacheGroupID(nullptr, \"%s\");\n", serviceCacheGroupID.str());
    }
    outs("}\n");

    // Create init_metrics for execution profiling
    outf("\nvoid C%sSoapBinding::init_metrics()\n", name_);
    outs("{\n");
    if (executionProfilingEnabled)
    {
        outf("#ifdef ESP_SERVICE_%s\n", name_);

        outf("\tStringBuffer rootName;\n");
        outf("\trootName.append(queryProcessName()).append(\".\").append(getPort());\n");

        // For each method with execution profiling enabled, add code to initialize the histogram metric
        for (mthi = methods; mthi != NULL; mthi = mthi->next)
        {
            if (mthi->isExecutionProfilingEnabled())
            {
                outf("\t%s = registerServiceMethodProfilingMetric(rootName.str(), \"%s\", \"%s\", \"\", \"%s\");\n",
                     mthi->getExecutionProfilingMetricVariableName(), name_, mthi->getName(), mthi->getExecutionProfilingOptions().c_str());
            }
        }
        outf("#endif\n");
    }
    outs("}\n");

    // init_maps implementation
    outf("\nvoid C%sSoapBinding::init_maps()\n", name_);
    outs("{\n");
    outs("\tstd::initializer_list<const char *> names = {\n");
    for (mthi=methods; mthi!= nullptr; mthi=mthi->next)
    {
        outf("\t\t\"%s\"", mthi->getName());
        if (mthi->next != nullptr)
        {
            outs(",\n");
        }
        else
        {
            outs("\n");
        }
    }
    outs("\t};\n");

    outs("\tregisterMethodNames(names);\n");
    outs("}");

    outf("\nint C%sSoapBinding::processRequest(IRpcMessage* rpc_call, IRpcMessage* rpc_response)\n", name_);
    outs("{\n");
    outs("\tif(rpc_call == NULL || rpc_response == NULL)\n\t\treturn -1;\n\n");

    outs(1, "IEspContext *ctx=rpc_call->queryContext();\n");
    outs(1, "DBGLOG(\"Client version: %g\", ctx->getClientVersion());\n");
    outs(1, "StringBuffer serviceName;\n");
    outs(1, "[[maybe_unused]] double clientVer=(ctx) ? ctx->getClientVersion() : 0.0;\n");
    outs(1, "qualifyServiceName(*ctx, ctx->queryServiceName(NULL), NULL, serviceName, NULL);\n");
    outs(1, "CRpcCall* thecall = static_cast<CRpcCall *>(rpc_call);\n"); //interface must be from a class derived from CRpcCall
    outs(1, "CRpcResponse* response = static_cast<CRpcResponse*>(rpc_response);\n");  //interface must be from a class derived from CRpcResponse
    outs(1, "CHttpRequest* httprequest = thecall->getHttpReq();\n");
    outs(1, "CHttpResponse* httpresponse = response->getHttpResp();\n\n");

    outf("\tOwned<IEsp%s> iserv = (IEsp%s*)getService();\n", name_, name_);
    outs("\tif(iserv == NULL)\n");
    outs("\t{\n");
    outs("\t\tresponse->set_status(SOAP_SERVER_ERROR);\n");
    outs("\t\tresponse->set_err(\"Service not available\");\n");
    outs("\t\tDBGLOG(\"Service not available\");\n");
    outs("\t\treturn -1;\n\t}\n");
    outs("\tif (thecall->get_name() == NULL)\n");
    outs("\t{\n");
    outs("\t\tresponse->set_status(SOAP_CLIENT_ERROR);\n");
    outs("\t\tresponse->set_err(\"No service method specified\");\n");
    outs("\t\tERRLOG(\"No service method specified\");\n");
    outs("\t\treturn -1;\n");
    outs("\t}\n");

    outs("\n\tIEspContext& context = *rpc_call->queryContext();\n\n");
    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        outf("\tif(!stricmp(thecall->get_name(), \"%s\")||!stricmp(thecall->get_name(), \"%s\"))\n", mthi->getName(), mthi->getReq());
        outs("\t{\n");

        // metrics
        if (mthi->isExecutionProfilingEnabled())
        {
            outf("#ifdef ESP_SERVICE_%s\n", name_);
            outf("\t\thpccMetrics::HistogramExecutionTimer timer(%s);\n", mthi->getExecutionProfilingMetricVariableName());
            outf("#endif\n");
        }

        //esp_request + esp_response can persist longer than the scope of this method
        outf("\t\tOwned<C%s> esp_request = new C%s(serviceName.str(), thecall);\n", mthi->getReq(), mthi->getReq());
        outs("\t\tcheckRequest(context);\n");
        outf("\t\tOwned<C%s> esp_response = new C%s(serviceName.str());\n", mthi->getResp(), mthi->getResp());

        StrBuffer minVer;
        bool hasMinVer = mthi->getMetaVerInfo("min_ver", minVer);

        if (hasMinVer) {
            outs(2, "if (!clientVer) {\n");
            outf(3, "clientVer = %s;\n", minVer.str());
            outs(3, "ctx->setClientVersion(clientVer);\n");
            outs(2, "}\n");
        }

        bool bHandleExceptions = 0 != mthi->getMetaInt("exceptions_inline", 0);
        if (!bHandleExceptions)
            bHandleExceptions = 0 != getMetaInt("exceptions_inline", 0);

        writeAccessMap(2, *this, name_, servicefeatureurl, *mthi);

        StrBuffer clearCacheGroupIDs;
        if (mthi->hasMetaTag("clear_cache_group"))
        {
            StrBuffer cCGIDs;
            mthi->getMetaStringValue(cCGIDs,"clear_cache_group");
            if (cacheDefined || (cCGIDs.length() != 0))
                clearCacheGroupIDs.set((cCGIDs.length() != 0) ? cCGIDs.str() : serviceCacheGroupID.str());
        }
        //begin try block
        if (bHandleExceptions)
        {
            outs("\t\tStringBuffer source;\n");
            outf("\t\tsource.appendf(\"%s::%%s()\", thecall->get_name());\n", name_);
            outf("\t\tOwned<IMultiException> me = MakeMultiException(source.str());\n");

            outs("\t\ttry\n");
            outs("\t\t{\n");
            if (hasMinVer)
            {
                outf("\t\t\tif (clientVer!=-1.0 && clientVer<%s)\n", minVer.str());
                outs("\t\t\t\tthrow MakeStringException(-1, \"Client version is too old, please update your client application.\");\n");
            }

            if (mthi->getMetaInt("do_not_log",0))
                outs(2, "context.queryRequestParameters()->setProp(\"do_not_log\",1);\n");

            outs("\t\t\tresponse->set_status(SOAP_OK);\n");

            if (servicefeatureurl.length() != 0)
                outf("\t\t\tif( accessmap.ordinality() > 0 )\n\t\t\t\tonFeaturesAuthorize(context, accessmap, \"%s\", \"%s\");\n", name_, mthi->getName());

            outf("\t\t\tiserv->on%s(context, *esp_request, *esp_response);\n", mthi->getName());
            if (clearCacheGroupIDs.length() > 0)
                outf("\t\t\tclearCacheByGroupID(\"%s\");\n", clearCacheGroupIDs.str());

            outs("\t\t}\n");

            write_catch_blocks(mthi, ct_soapresp, 2);
        }
        else
        {
            if (hasMinVer)
            {
                outf(2, "if (clientVer!=-1.0 && clientVer<%s)\n", minVer.str());
                outf(3, "throw MakeStringException(-1, \"This method is not supported in version %%g, minimum version is %s. Please update your client application.\", clientVer);\n", minVer.str());
            }
            if (mthi->getMetaInt("do_not_log",0))
                outs(2, "context.queryRequestParameters()->setProp(\"do_not_log\",1);\n");

            if (servicefeatureurl.length() != 0) {
                outs(2, "if( accessmap.ordinality() > 0 )\n");
                outf(3, "onFeaturesAuthorize(context, accessmap, \"%s\", \"%s\");\n", name_, mthi->getName());
            }
            outf(2, "iserv->on%s(*rpc_call->queryContext(), *esp_request, *esp_response);\n", mthi->getName());
            if (clearCacheGroupIDs.length() > 0)
                outf(2, "clearCacheByGroupID(\"%s\");\n", clearCacheGroupIDs.str());
            outs(2, "response->set_status(SOAP_OK);\n");
        }

        outf("\t\tresponse->set_name(\"%s\");\n", mthi->getResp());
        outs("\t\tif(!httprequest || !httpresponse)\n");
        outs("\t\t{\n");
        outs("\t\t\tesp_response->serialize(*response);\n");
        outs("\t\t}\n");
        outs("\t\telse\n");
        outs("\t\t{\n");
        outs("\t\t\tMemoryBuffer content;\n");
        outs("\t\t\tStringBuffer mimetype;\n");
        outs("\t\t\tesp_response->appendContent(&context,content, mimetype);\n");
        outs("\t\t\tonBeforeSendResponse(context,httprequest,content,serviceName.str(),thecall->get_name());\n");
        outs("\t\t\thttpresponse->setContent(content.length(), content.toByteArray());\n");
        outs("\t\t\thttpresponse->setContentType(mimetype.str());\n");
        outs("\t\t\thttpresponse->send();\n");
        outs("\t\t\thttpresponse->setRespSent(true);\n");
        outs("\t\t}\n");
        outs("\t\treturn 0;\n\t}\n\n");
    }

    outs("\tresponse->set_status(SOAP_CLIENT_ERROR);\n");
    outs("\tStringBuffer msg, svcName;\n");
    outs("\tmsg.appendf(\"Method %s not available in service %s\",thecall->get_name(),getServiceName(svcName).str());\n");
    outs("\tERRLOG(\"%s\", msg.str());\n");
    outs("\tresponse->set_err(msg);\n");
    outs("\treturn -1;\n");
    outs("}\n");


    //method ==> getServiceXmlFilename for xsd and wsdl transformations
    outf("\nint C%sSoapBinding::getServiceXmlFilename(StringBuffer &filename)\n", name_);
    outs("{\n");
    outf("\tfilename.append(\"%s.xml\");\n", packagename);
    outs("\treturn 1;\n");
    outs("}\n");

    //method ==> getQualifiedNames
    outf("\nint C%sSoapBinding::getQualifiedNames(IEspContext& ctx, MethodInfoArray & methods)\n", name_);
    outs("{\n");
    outs(1, "double ver = ctx.getClientVersion();\n");
    outs(1, "if (ver<=0)\n");
    outs(2,     "ver = getWsdlVersion();\n");
    outs(1, "const char *servname=ctx.queryServiceName(NULL);\n");
    outf(1, "bool fullservice = (!stricmp(servname, \"esp\")||!stricmp(servname, \"%s\"));\n", name_);
    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        if (!mthi->getMetaInt("noform",0))
        {
            const char *optional=mthi->getMetaString("optional", "NULL");
            const char *access=mthi->getMetaString("access", "NULL");
            const char *method_name = (getMetaInt("use_method_name")!=0) ? mthi->getName() : mthi->getReq();

            StrBuffer minVer, maxVer;
            bool hasMinVer = mthi->getMetaVerInfo("min_ver",minVer);
            bool hasMaxVer = mthi->getMetaVerInfo("max_ver",maxVer);

            outf("\tif ((fullservice || isMethodInSubService(ctx, servname, \"%s\")) && ctx.isMethodAllowed(ver,%s, %s, %s, %s))\n",
                mthi->getName(), optional, access, hasMinVer ? minVer.str() : "-1",  hasMaxVer ? maxVer.str() : "-1");
            outf("\t\tmethods.append(*new CMethodInfo(\"%s\", \"%s\", \"%s\"));\n", mthi->getName(), method_name, mthi->getResp());

        }
    }
    outs("\treturn methods.ordinality();\n");
    outs("}\n");

    //method ==> getServiceName
    outf("\nStringBuffer & C%sSoapBinding::getServiceName(StringBuffer &resp)\n", name_);
    outs("{\n");
    outf("\tresp.append(\"%s\");\n", name_);
    outs("\treturn resp;\n");
    outs("}\n");

    //method ==> isValidServiceName
    outf("\nbool C%sSoapBinding::isValidServiceName(IEspContext &context, const char *name)\n", name_);
    outs("{\n");
    outf(1, "if (!Utils::strcasecmp(name, \"%s\"))\n", name_);
    outs(2,     "return true;\n");
    outs(1, "else\n");
    outs(2,     "return (hasSubService(context, name));\n");
    outs("}\n");

    //method ==> qualifyServiceName
    outf("\nbool C%sSoapBinding::qualifyServiceName(IEspContext &context, const char *servname, const char *methname, StringBuffer &servQName, StringBuffer *methQName)\n", name_);
    outs("{\n");
    outs(1, "servQName.clear();\n");
    outf(1, "if (!Utils::strcasecmp(servname, \"%s\"))\n", name_);
    outs(1, "{\n");
    outf(2,     "servQName.append(\"%s\");\n", name_);
    outs(2,     "return qualifyMethodName(context, methname, methQName);\n");
    outs(1, "}\n");
    outs(1, "return qualifySubServiceName(context, servname, methname, servQName, methQName);\n");
    outs("}\n");

    //method ==> onGetFile
    outf("\nint C%sSoapBinding::onGetFile(IEspContext &context, CHttpRequest* request, CHttpResponse* response, const char *pathex)\n", name_);
    outs("{\n");
    outs("\tif(request == NULL || response == NULL)\n");
    outs("\t\treturn -1;\n");
    outs("\tStringBuffer mimetype;\n");
    outs("\tMemoryBuffer content;\n\n");
    outs("\tStringBuffer filepath;\n");
    outs("\tgetBaseFilePath(filepath);\n");
    outs("\tif (strchr(\"\\\\/\", filepath.charAt(filepath.length()-1))==NULL)\n");
    outs("\t\tfilepath.append(\"/\");\n");
    outs("\tfilepath.append(pathex);\n");
    outs("\tresponse->httpContentFromFile(filepath.str());\n");
    outs("\tresponse->send();\n");
    outs("\treturn 0;\n");
    outs("}\n");

    //Method ==> onGetForm
    outf("\nint C%sSoapBinding::onGetForm(IEspContext &context, CHttpRequest* request, CHttpResponse* response, const char *service, const char *method)\n", name_);
    outs("{\n");

    if (getMetaInt("noforms", 0))
    {
        outs("\treturn onGetNotFound(context, request, response, service);\n");
    }
    else
    {
        for (mthi=methods;mthi!=NULL;mthi=mthi->next)
        {
            if (mthi->getMetaInt("noform", 0))
            {
                outf("\tif (!stricmp(\"%s\", method))\n", mthi->getName());
                outs("\t\treturn onGetNotFound(context, request, response, service);\n");
            }
            else
            {
                const char *formHtmlPath = mthi->getMetaString("form_html", NULL);
                if (formHtmlPath)
                {
                    outf("\tif (!stricmp(\"%s\", method))\n", mthi->getName());
                    outs("\t{\n");
                    outf("\t\tresponse->httpContentFromFile(%s);\n", formHtmlPath);
                    outs("\t\tresponse->send();\n");
                    outs("\t\treturn 0;\n");
                    outs("\t}\n");
                }
            }
        }

        // normal test form
        if (hasVersion)
        {
            outs("\tif (context.getClientVersion()<=0)\n");
            outf("\t\tcontext.setClientVersion(%s);\n\n", wsdlVer.str());
        }
        for (mthi=methods;mthi!=NULL;mthi=mthi->next)
        {
            outf("\tif (!stricmp(\"%s\", method)) {\n", mthi->getName());
            if (mthi->getMetaInt("use_new_form",0))
                outs("\t\treturn EspHttpBinding::onGetXForm(context, request, response, service, method);\n");
            else {
                outf("\t\tC%s::getMapInfo(context.queryMapInfo());\n", mthi->getReq());
                outf("\t\tC%s::getMapInfo(context.queryMapInfo());\n", mthi->getResp());
            }
            outs("\t}\n");
        }
        outs("\n\treturn EspHttpBinding::onGetForm(context, request, response, service, method);\n");
    }
    outs("}\n");

    // method ==> onGetXForm
    outf("int C%sSoapBinding::onGetXForm(IEspContext &context, CHttpRequest* request, CHttpResponse* response, const char *service, const char *method)\n", name_);
    outs("{\n");
    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        if (mthi->getMetaInt("use_new_form",0))
        {
            outf("\tif (!stricmp(\"%s\", method))\n", mthi->getName());
            outs("\t\treturn EspHttpBinding::onGetForm(context, request, response, service, method);\n");
        }
    }
    outs("\treturn EspHttpBinding::onGetXForm(context, request, response, service, method);\n");
    outs("}\n");

    if (getMetaInt("no_ws_index", 0))
    {
        //Method ==> onGetIndex
        outf("\nint C%sSoapBinding::onGetIndex(IEspContext &context, CHttpRequest* request, CHttpResponse* response, const char *service)\n", name_);
        outs("{\n");
        outs("\treturn onGetNotFound(context, request, response, service);\n");
        outs("}\n");
    }

    //Method ==> onGetService
    outf("\nint C%sSoapBinding::onGetService(IEspContext &context, CHttpRequest* request, CHttpResponse* response, const char *service, const char *method, const char *pathex)\n", name_);
    outs("{\n");
    outs("\tif(request == NULL || response == NULL)\n");
    outs("\t\treturn -1;\n");

    EspMountInfo *mnt;
    for (mnt=mounts;mnt!=NULL;mnt=mnt->next)
    {
        outs("\t");
        if (mnt!=mounts)
            outs("else ");
        outf("if(!stricmp(method, \"%s\"))\n", mnt->getName());
        outs("\t{\n");
        outs("\t\tMemoryBuffer content;\n");
        outs("\t\tStringBuffer mimetype;\n");
        outf("\t\tStringBuffer filepath(%s);\n\n", mnt->getLocalPath());
        outs("\t\tif (filepath.length()>0 && strchr(\"/\\\\\", filepath.charAt(filepath.length()-1))==NULL)\n");
        outs("\t\t{\n");
        outs("\t\t\tfilepath.append(\"/\");\n");
        outs("\t\t}\n");
        outs("\t\tfilepath.append((pathex!=NULL && *pathex!=0) ? pathex : \"index.html\");\n\n");
        outs("\t\tif (!response->httpContentFromFile(filepath.str()))\n");
        outs("\t\t{\n");
        outs("\t\t\treturn onGetQuery(context, request, response, service, method);\n");
        outs("\t\t}\n");
        outs("\t\tresponse->send();\n");
        outs("\t\treturn 0;\n");
        outs("\t}\n");
    }

    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        int formIsDefault = mthi->getMetaInt("form_is_default");
        if (formIsDefault)
        {
            outf("\tif (!stricmp(\"%s\", method))\n", mthi->getName());
            outs("\t{\n");
            outs("\treturn onGetForm(context, request, response, service, method);\n");
            outs("\t}\n");
        }
    }

    outs("\treturn onGetQuery(context, request, response, service, method);\n");
    outs("}\n");

    outf("\n IRpcRequestBinding *C%sSoapBinding::createReqBinding(IEspContext &context, IHttpMessage *ireq, const char *service, const char *method)\n", name_);
    outs("{\n");
    outs(1, "CHttpRequest *request=static_cast<CHttpRequest*>(ireq);\n");
    outs(1, "IProperties *props = (request) ? request->queryParameters() : NULL;\n\n");
    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        outf(1, "if (!stricmp(method, \"%s\") || !stricmp(method, \"%s\"))\n", mthi->getName(), mthi->getReq());
        outf(2, "return new C%s(&context, \"%s\", props, NULL);\n", mthi->getReq(), name_);
    }

    outs(1, "return NULL;\n");
    outs("}\n");

    //Method ==> getDefaultClientVersion
    outf("\nbool C%sSoapBinding::getDefaultClientVersion(double &ver)\n", name_);
    outs("{\n");
    StrBuffer defVer;
    bool hasDefVer = getMetaVerInfo(tags,"default_client_version",defVer);
    if (!hasDefVer)
        hasDefVer = getMetaVerInfo(tags,"version",defVer);
    if (hasDefVer)
        outf("\tver = %s;\n", defVer.str());
    outf("\treturn %s;\n", hasDefVer ? "true" : "false");
    outs("}\n");

    //Method ==> onGetInstantQuery
    outf("\nint C%sSoapBinding::onGetInstantQuery(IEspContext &context, CHttpRequest* request, CHttpResponse* response, const char *service, const char *method)\n", name_);
    outs("{\n");
    outf("\tdouble defaultClientVersion = 0.0;\n");
    outf("\tif ((context.getClientVersion()<=0) && getDefaultClientVersion(defaultClientVersion))\n");
    outf("\t\tcontext.setClientVersion(defaultClientVersion);\n\n");
    outs("\tif(request == NULL || response == NULL)\n");
    outs("\t\treturn -1;\n");

    outs("\tStringBuffer respStr;\n");
    outf("\tOwned<IEsp%s> iserv = (IEsp%s*)getService();\n", name_, name_);
    outs("\tif(iserv == NULL)\n");
    outs("\t{\n");
    outs("\t\trespStr.append(\"Service not available\");\n");
    outs("\t\tresponse->setContent(respStr.str());\n");
    outs("\t\tresponse->setContentType(\"text/html\");\n");
    outs("\t\tresponse->send();\n");
    outs("\t}\n");

    outs("\telse\n");
    outs("\t{\n");

    outf("\t\tOwned<CSoapResponseBinding> esp_response;\n");
    outf("\t\tStringBuffer source;\n");
    outf("\t\tIEspContext& context = *request->queryContext();\n");

    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        bool bClientXslt=false;
        const char *respXsl = mthi->getMetaString("resp_xsl_default", NULL);
        const char *respContentType = mthi->getMetaString("http_content_type", "\"text/html\"");
        if (!respXsl)
        {
            respXsl = mthi->getMetaString("client_xslt", NULL);
            bClientXslt=(respXsl!=NULL);
        }

        StrBuffer clearCacheGroupIDs;
        if (mthi->hasMetaTag("clear_cache_group"))
        {
            StrBuffer cCGIDs;
            mthi->getMetaStringValue(cCGIDs,"clear_cache_group");
            if (cacheDefined || (cCGIDs.length() != 0))
                clearCacheGroupIDs.set((cCGIDs.length() != 0) ? cCGIDs.str() : serviceCacheGroupID.str());
        }

        bool bHandleExceptions =  0 != mthi->getMetaInt("exceptions_inline", 0) || mthi->getMetaInt("http_exceptions_inline", 0);
        if (!bHandleExceptions)
            bHandleExceptions = 0 != getMetaInt("exceptions_inline", 0) || getMetaInt("http_exceptions_inline", 0);

        if (respXsl==NULL)
        {
            outf("\t\tif(!stricmp(method, \"%s\")||!stricmp(method, \"%s\"))\n", mthi->getName(), mthi->getReq());
            outs("\t\t{\n");

            if (mthi->isExecutionProfilingEnabled())
            {
                outf("#ifdef ESP_SERVICE_%s\n", name_);
                outf("\t\t\thpccMetrics::HistogramExecutionTimer timer(%s);\n", mthi->getExecutionProfilingMetricVariableName());
                outf("#endif\n");
            }

            outf("\t\t\tOwned<C%s> esp_request = new C%s(&context, \"%s\", request->queryParameters(), request->queryAttachments());\n", mthi->getReq(), mthi->getReq(), name_);
            outf("\t\t\tcheckRequest(context);\n");
            outf("\t\t\tC%s* resp = new C%s(\"%s\");\n", mthi->getResp(), mthi->getResp(), name_);
            outf("\t\t\tesp_response.setown(resp);\n");

            writeAccessMap(3, *this, name_, servicefeatureurl, *mthi);

            if (bHandleExceptions)
            {
                outf("\t\t\tsource.setf(\"%s::%%s()\", method);\n", name_);
                outf("\t\t\tOwned<IMultiException> me = MakeMultiException(source.str());\n");

                //begin try block
                outs("\t\t\ttry\n");
                outs("\t\t\t{\n");

                if (servicefeatureurl.length() != 0)
                    outf("\t\t\t\tif(accessmap.ordinality()>0)\n\t\t\t\t\tonFeaturesAuthorize(context, accessmap, \"%s\", \"%s\");\n", name_, mthi->getName());

                if (mthi->getMetaInt("do_not_log",0))
                    outf("\t\t\t\tcontext.queryRequestParameters()->setProp(\"do_not_log\",1);\n");
                outf("\t\t\t\tiserv->on%s(context, *esp_request.get(), *resp);\n", mthi->getName());
                if (clearCacheGroupIDs.length() > 0)
                    outf("\t\t\t\tclearCacheByGroupID(\"%s\");\n", clearCacheGroupIDs.str());
                outs("\t\t\t}\n");

                write_catch_blocks(mthi, ct_httpresp, 3);
            }
            else
            {
                if (servicefeatureurl.length() != 0)
                    outf("\t\t\tif(accessmap.ordinality()>0)\n\t\t\t\tonFeaturesAuthorize(context, accessmap, \"%s\", \"%s\");\n", name_, mthi->getName());
                if (mthi->getMetaInt("do_not_log",0))
                    outf("\t\t\t\tcontext.queryRequestParameters()->setProp(\"do_not_log\",1);\n");
                outf("\t\t\tiserv->on%s(*request->queryContext(), *esp_request.get(), *resp);\n", mthi->getName());
                if (clearCacheGroupIDs.length() > 0)
                    outf("\t\t\tclearCacheByGroupID(\"%s\");\n", clearCacheGroupIDs.str());
            }

            outs("\t\t}\n");
        }
        else
        {
            outf("\t\tif(!stricmp(method, \"%s\")||!stricmp(method, \"%s\"))\n", mthi->getName(), mthi->getReq());
            outs("\t\t{\n");

            if (mthi->isExecutionProfilingEnabled())
            {
                outf("#ifdef ESP_SERVICE_%s\n", name_);
                outf("\t\t\thpccMetrics::HistogramExecutionTimer timer(%s);\n", mthi->getExecutionProfilingMetricVariableName());
                outf("#endif\n");
            }

            outf("\t\t\tOwned<C%s> esp_request = new C%s(&context, \"%s\", request->queryParameters(), request->queryAttachments());\n", mthi->getReq(), mthi->getReq(), name_);
            outf("\t\t\tcheckRequest(context);\n");
            outf("\t\t\tOwned<C%s> esp_response = new C%s(\"%s\");\n", mthi->getResp(), mthi->getResp(), name_);

            if (bHandleExceptions)
            {
                outs("\t\t\tStringBuffer source;\n");
                outf("\t\t\tsource.appendf(\"%s::%%s()\", method);\n", name_);
                outf("\t\t\tOwned<IMultiException> me = MakeMultiException(source.str());\n");

                //begin try block
                outs("\t\t\ttry\n");
                outs("\t\t\t{\n");
                outf("\t\t\t\tiserv->on%s(*request->queryContext(), *esp_request.get(), *esp_response.get());\n", mthi->getName());
                if (clearCacheGroupIDs.length() > 0)
                    outf("\t\t\t\tclearCacheByGroupID(\"%s\");\n", clearCacheGroupIDs.str());
                outs("\t\t\t}\n");

                write_catch_blocks(mthi, ct_httpresp,3);
            }
            else
            {
                outf("\t\t\t\tiserv->on%s(*request->queryContext(), *esp_request.get(), *esp_response.get());\n", mthi->getName());
                if (clearCacheGroupIDs.length() > 0)
                    outf("\t\t\tclearCacheByGroupID(\"%s\");\n", clearCacheGroupIDs.str());
            }

            outs("\t\t\tif (canRedirect(*request) && esp_response->getRedirectUrl() && *esp_response->getRedirectUrl())\n");
            outs("\t\t\t{\n");
            outs("\t\t\t\tresponse->redirect(*request, esp_response->getRedirectUrl());\n");
            outs("\t\t\t}\n");
            outs("\t\t\telse\n");
            outs("\t\t\t{\n");

            outs("\t\t\t\t[[maybe_unused]] IProperties *props=request->queryParameters();\n");
            outs("\t\t\t\tif (skipXslt(context))\n");
            outs("\t\t\t\t{\n");
            outs("\t\t\t\t\tMemoryBuffer content;\n");
            outs("\t\t\t\t\tStringBuffer mimetype;\n");
            outs("\t\t\t\t\tesp_response->appendContent(&context,content, mimetype);\n");
            outs("\t\t\t\t\tonBeforeSendResponse(context,request,content,service,method);\n");
            outs("\t\t\t\t\tresponse->setContent(content.length(), content.toByteArray());\n");
            outs("\t\t\t\t\tresponse->setContentType(mimetype.str());\n");
            outs("\t\t\t\t}\n");
            outs("\t\t\t\telse\n");
            outs("\t\t\t\t{\n");

            outs("\t\t\t\t\tStringBuffer xml;\n");
            outs("\t\t\t\t\tStringBuffer sResponse;\n");
            if (bClientXslt)
            {
                outs("\t\t\t\t\tif (request->supportClientXslt())\n");
                outf("\t\t\t\t\t\txml.appendf(\"<?xml version=\\\"1.0\\\" encoding=\\\"UTF-8\\\"?><?xml-stylesheet type=\\\"text/xsl\\\" href=\\\"%%s\\\"?>\", %s);\n", respXsl);
            }
            outs("\t\t\t\t\tesp_response->serializeStruct(&context, xml, NULL);\n\n");
            if (bClientXslt)
            {
                outs("\t\t\t\t\tif (request->supportClientXslt()){\n");
                outs("\t\t\t\t\t\txml.swapWith(sResponse);\n");
                outs("\t\t\t\t\t\tresponse->setContentType(\"text/xml\");\n");
                outs("\t\t\t\t\t}else{\n");
            }
            if(respXsl[1] == '/')
            {
                outf("\t\t\t\t\txslTransform(xml.str(), %s, sResponse.clear(), context.queryXslParameters());\n", respXsl);
            }
            else
            {
                outf("\t\t\t\t\txslTransform(xml.str(), StringBuffer(getCFD()).append(%s).str(), sResponse.clear(), context.queryXslParameters());\n", respXsl);
            }
            outf("\t\t\t\t\tresponse->setContentType(%s);\n", respContentType);

            needsXslt = true;

            if (bClientXslt)
                outs("\t\t\t\t\t}\n");

            outs("\t\t\t\t\tresponse->setContent(sResponse.str());\n");
            outs("\t\t\t\t}\n");

            outs("\t\t\t\tresponse->send();\n");
            outs("\t\t\t}\n");
            outs("\t\t\treturn 0;\n");
            outs("\t\t}\n");
        }
    }

    outs("\n");
    indentReset(2);
    indentOuts("if (esp_response.get())\n");
    indentOuts("{\n");
    indentOuts(1,"if (canRedirect(*request) && esp_response->getRedirectUrl() && *esp_response->getRedirectUrl())\n");
    indentOuts(1,"response->redirect(*request, esp_response->getRedirectUrl());\n");
    indentOuts(-1,"else\n");
    indentOuts("{\n");

    indentOuts(1,"MemoryBuffer content;\n");
    indentOuts("StringBuffer mimetype;\n");
    indentOuts("esp_response->appendContent(&context,content, mimetype);\n");
    indentOuts("onBeforeSendResponse(context,request,content,service,method);\n");
    indentOuts("response->setContent(content.length(), content.toByteArray());\n");
    indentOuts("response->setContentType(mimetype.str());\n");

    indentOuts("response->send();\n");
    indentOuts(-1,"}\n");
    indentOuts("return 0;\n");
    indentOuts(-1,"}\n");
    outs("\t}\n");

    outs("\treturn onGetNotFound(context, request,  response, service);\n");
    outs("}\n");
}


//-------------------------------------------------------------------------------------------------------------
// class EspServInfo

void EspServInfo::write_catch_blocks(EspMethodInfo* mthi, catch_type ct, int indents)
{
    const char* errorXslt=NULL;
    if (ct==ct_httpresp)
    {
        errorXslt = mthi->getMetaString("exceptions_inline", NULL);
        if (!errorXslt)
            errorXslt = mthi->getMetaString("http_exceptions_inline", NULL);
        if (!errorXslt)
            errorXslt = getMetaString("exceptions_inline", NULL);
        if (!errorXslt)
            errorXslt = getMetaString("http_exceptions_inline", NULL);
    }

    outs(indents,"catch (IMultiException* mex)\n");
    outs(indents,"{\n");
    outs(indents+1,"me->append(*mex);\n");
    outs(indents+1,"mex->Release();\n");
    outs(indents,"}\n");

    //catch IException
    outs(indents,"catch (IException* e)\n");
    outs(indents,"{\n");

    outs(indents+1,"me->append(*e);\n");
    outs(indents,"}\n");

    //catch ...
    outs(indents,"catch (...)\n");
    outs(indents,"{\n");

    outs(indents+1,"me->append(*MakeStringExceptionDirect(-1, \"Unknown Exception\"));\n");
    outs(indents,"}\n");

    //apply any xslt on the error(s), if it is specified in scm file
    //
    if (errorXslt)
    {
        if(errorXslt[1] == '/')
        {
            outf(indents, "if (response->handleExceptions(xslp, me, \"%s\", \"%s\", %s))\n", name_, mthi->getName(), errorXslt);
        }
        else
        {
            outf(indents, "if (response->handleExceptions(xslp, me, \"%s\", \"%s\", StringBuffer(getCFD()).append(%s).str()))\n", name_, mthi->getName(), errorXslt);
        }
        outs(indents+1, "return 0;\n");
        needsXslt=true;
    }
    else
        outf(indents, "esp_response->handleExceptions(me, \"%s\", \"%s\");\n", name_, mthi->getName());
}


void EspServInfo::write_esp_service_ipp()
{
    outf("class C%s : public CInterface,\n", name_);
    outf("\timplements IEsp%s\n", name_);
    outs("{\n");
    outs("private:\n");
    outs("\tIEspContainer* m_container = nullptr;\n");
    outs("public:\n");
    outs("\tIMPLEMENT_IINTERFACE;\n\n");
    outf("\tC%s(){}\n\tvirtual ~C%s(){}\n", name_, name_);

    outs("\tvirtual void init(IPropertyTree *cfg, const char *process, const char *service)\n\t{\n\t}\n");
    outs("\tvirtual bool init(const char * service, const char * type, IPropertyTree * cfg, const char * process)\n\t{\n\t\treturn true;\n\t}\n");
    outs("\tvirtual void setContainer(IEspContainer *c)\n\t{\n\t\tm_container = c;\n\t}\n");
    outs("\tvirtual IEspContainer *queryContainer()\n\t{\n\t\treturn m_container;\n\t}\n");

    outf("\tvirtual const char* getServiceType(){return \"%s\";}\n\n", name_);

    outf("\tvirtual bool unsubscribeServiceFromDali(){return false;}\n\n");
    outf("\tvirtual bool subscribeServiceToDali(){return false;}\n\n");
    outf("\tvirtual bool detachServiceFromDali(){return false;}\n\n");
    outf("\tvirtual bool attachServiceToDali(){return false;}\n\n");

    outf("\tvirtual bool canDetachFromDali(){return false;}\n\n");

    EspMethodInfo *mthi;
    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        bool stubbed = (findMetaTag(mthi->tags,"stubbed")!=NULL);
        if (streq(mthi->getName(), "Ping")) //We'll implement the onPing automatically for all ESP Services.
        {
            outf(1, "bool on%s(IEspContext &context, IEsp%s &req, IEsp%s &resp)\n",  mthi->getName(), mthi->getReq(), mthi->getResp());
            outs(1, "{\n");
            outs(2, "return true;\n");
            outs(1, "}\n");
        }
        else
        {
            outf(1, "%sbool on%s(IEspContext &context, IEsp%s &req, IEsp%s &resp)\n", (stubbed) ? "" : "//", mthi->getName(), mthi->getReq(), mthi->getResp());
            outf(1, "%s{\n", (stubbed) ? "" : "//");
            outf(2, "%sreturn false;\n", (stubbed) ? "" : "//");
            outf(1, "%s}\n", (stubbed) ? "" : "//");
        }
    }

    outs("};\n\n");
}

void EspServInfo::write_esp_service()
{
}

void EspServInfo::write_esp_client_ipp()
{
    outf("class CClient%s : public CInterface,\n", name_);
    outf("\timplements IClient%s\n", name_);
    outs("{\nprotected:\n");
    outs("\tStringBuffer soap_proxy;\n");
    outs("\tStringBuffer soap_url;\n");
    //dom

    outs("\tStringBuffer soap_userid;\n");
    outs("\tStringBuffer soap_password;\n");
    outs("\tStringBuffer soap_realm;\n");
    outs("\tStringBuffer soap_action;\n");
    outs("\tlong soap_reqid = 0;\n");

    outs("\npublic:\n");
    outs("\tIMPLEMENT_IINTERFACE;\n\n");

    outf("\tCClient%s()\n\t{\n", name_);
    outs("\t\tsoap_reqid=0;\n");
    outf("\t\tsoap_action.append(\"%s\");\n", name_);
    // use latest 'version' unless 'generated_client_version' provided
    const char *ver = getMetaString("generated_client_version", nullptr);
    if (!ver || !*ver)
        ver = getMetaString("version", nullptr);
    if (ver && *ver)
        outf("\t\tsoap_action.append(\"?ver_=\").append(%s);\n", ver);
    outf("\t}\n\tvirtual ~CClient%s(){}\n", name_);

    outs("\tvirtual void setProxyAddress(const char *address)\n\t{\n\t\tsoap_proxy.set(address);\n\t}\n");
    outs("\tvirtual void addServiceUrl(const char *url)\n\t{\n\t\tsoap_url.set(url);\n\t}\n");
    outs("\tvirtual void removeServiceUrl(const char *url)\n\t{\n\t}\n");
    //domsetUsernameToken
    outs("\tvirtual void setUsernameToken(const char *userid,const char *password,const char *realm)\n\t{\n\t\t soap_userid.set(userid);\n\t\t soap_password.set(password);\n\t\t soap_realm.set(realm);\n\t}\n");
    outs("\tvirtual void setAction(const char *action)\n\t{\n\t\tsoap_action.set(action);\n\t}\n");

    EspMethodInfo *mthi;
    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        outs("\n");
        outf("\tvirtual IClient%s * create%sRequest();\n", mthi->getReq(), mthi->getName());
        outf("\tvirtual IClient%s * %s(IClient%s *request);\n", mthi->getResp(), mthi->getName(), mthi->getReq());
        outf("\tvirtual void async_%s(IClient%s *request, IClient%sEvents *events,IInterface* state=0);\n", mthi->getName(), mthi->getReq(), name_);
        mthi->write_esp_method(name_, true, false);

    }

    outs("\tstatic int transferThunkEvent(void *data);\n");


    outs("#ifdef _WIN32\n");
    outs("\tstatic void espWorkerThread(void* data);\n");
    outs("#else\n");
    outs("\tstatic void *espWorkerThread(void *data);\n");
    outs("#endif\n");

    outs("};\n\n");
}

void EspServInfo::write_esp_client()
{
    int useMethodName = getMetaInt("use_method_name", 0);

    //comment
    outs("\n//=======================================================");
    outs("\n// client util methods");
    outs("\n//=======================================================");
    outs("\n");

    EspMethodInfo *mthi;
    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        outf("\n//------ method %s ---------\n", mthi->getName());
        outf("\nIClient%s * CClient%s::create%sRequest()\n", mthi->getReq(), name_, mthi->getName());
        outf("{\n\tC%s* request = new C%s(\"%s\");\n", mthi->getReq(), mthi->getReq(), name_);
        outs("\trequest->setProxyAddress(soap_proxy.str());\n");
        outs("\trequest->setUrl(soap_url.str());\n");
        if (useMethodName)
            outf("\trequest->setMsgName(\"%s\");\n", mthi->getName());

        outs("\treturn request;\n}\n");

        outf("\nIClient%s * CClient%s::%s(IClient%s *request)\n", mthi->getResp(), name_, mthi->getName(), mthi->getReq());
        outs("{\n");
        outs("\tif(soap_url.length()== 0){ throw MakeStringExceptionDirect(-1, \"url not set\"); }\n\n");
        outf("\tC%s* esprequest = static_cast<C%s*>(request);\n", mthi->getReq(), mthi->getReq());
        outf("\tOwned<C%s> espresponse = new C%s(\"%s\");\n\n", mthi->getResp(), mthi->getResp(), name_);
        outs("\tespresponse->setReqId(soap_reqid++);\n");
        //dom
        outs("\tesprequest->soap_setUserId( soap_userid.str());\n");
        outs("\tesprequest->soap_setPassword(soap_password.str());\n");
        outs("\tesprequest->soap_setRealm(soap_realm.str());\n");
        outs("\tconst char *soapaction=(soap_action.length()) ? soap_action.str() : NULL;\n");
        outs("\tesprequest->post(soap_proxy.str(), soap_url.str(), *espresponse, soapaction);\n");
        outs("\treturn espresponse.getClear();\n");
        outs("}\n");

        outf("\nvoid CClient%s::async_%s(IClient%s *request, IClient%sEvents *events,IInterface* state)\n", name_, mthi->getName(), mthi->getReq(), name_);
        outs("{\n");
        outs("\tif(soap_url.length()==0){ throw MakeStringExceptionDirect(-1, \"url not set\"); }\n\n");
        outf("\tC%s* esprequest = static_cast<C%s*>(request);\n", mthi->getReq(), mthi->getReq());
        outf("\tesprequest->setMethod(\"%s\");\n", mthi->getName());
        outs("\tesprequest->setReqId(soap_reqid++);\n");
        outs("\tesprequest->setEventSink(events);\n");
        outs("\tesprequest->setState(state);\n");

        outs("\tesprequest->soap_setUserId( soap_userid.str());\n");
        outs("\tesprequest->soap_setPassword( soap_password.str());\n");
        outs("\tesprequest->soap_setRealm( soap_realm.str());\n");

        outs("#ifdef USE_CLIENT_THREAD\n");
        outs("\tesprequest->setThunkHandle(GetThunkingHandle());\n");
        outs("#endif\n");
        outs("\tesprequest->Link();\n\n");
        outs("\tif(state!=NULL)\n");
        outs("\t\tstate->Link();\n\n");


        outs("#ifdef _WIN32\n");
        outs("\t_beginthread(espWorkerThread, 0, (void *)(IRpcRequestBinding *)(esprequest));\n");
        outs("#else\n");

        outs("\tpthread_attr_t attr;\n");
        outs("\tpthread_attr_init(&attr);\n");
        outs("\tpthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);\n");
        outs("\tpthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);\n");
        outs("\tpthread_attr_setstacksize(&attr, 0x10000);\n");
        outs("\tThreadId threadid;\n");
        outs("\tint status;\n");
        outs("\tdo\n");
        outs("\t{\n");
        outf("\t\tstatus = pthread_create(&threadid, &attr, CClient%s::espWorkerThread, (void *)(IRpcRequestBinding *)(esprequest));\n", name_);
        outs("\t} while (0 != status && (errno == EINTR));\n");
        outs("\tif (status) {\n");
        outs("\t\tRelease();\n");
        outs("\t\tthrow makeOsException(errno);\n");
        outs("\t}\n");

        outs("#endif\n");
        outs("}\n");

        mthi->write_esp_method(name_, false, false);
    }

    outf("\nint CClient%s::transferThunkEvent(void *data)\n", name_);
    outs("{\n");
    outs("\tIRpcResponseBinding *response = (IRpcResponseBinding *)data;\n");
    outs("\tif (response!=NULL)\n");
    outs("\t{\n");
    outf("\t\tIClient%sEvents *eventSink = (IClient%sEvents *)response->getEventSink();\n", name_, name_);
    outs("\t\tresponse->lock();\n\n");

    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        outf(2, "if (stricmp(response->getMethod(), \"%s\")==0)\n", mthi->getName());
        outs(2, "{\n");
        outf(3, "IClient%s* icresp = dynamic_cast<IClient%s*>(response);\n", mthi->getResp(), mthi->getResp());
        outf(3, "if (icresp) {\n");
        outs(4,  "if (response->getRpcState() == RPC_MESSAGE_OK)\n");
        outf(5,   "eventSink->on%sComplete(icresp, response->queryState());\n", mthi->getName());
        outf(4,  "else\n");
        outf(5,    "eventSink->on%sError(icresp,response->queryState());\n", mthi->getName());
        outs(3, "}\n");
        outs(2, "}\n");
    }
    outs("\t\tresponse->unlock();\n");
    outs("\t}\n");
    outs("\treturn 0;\n");
    outs("}\n");

    //=============================================================================
    // method: espWorkerThread(void* data)

    outf("\nstatic IRpcResponseBinding* create%sResponseObject(IRpcRequestBinding *request)\n",name_);
    outs("{\n");
    outs("\tconst char* method = request->getMethod();\n");
    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        outf("\tif (stricmp(method, \"%s\")==0)\n", mthi->getName());
        outf("\t\treturn new C%s(\"%s\", request);\n", mthi->getResp(), name_);
    }
    outf("\treturn NULL;\n");
    outs("}\n");

    outf("\n#ifdef _WIN32\n");
    outf("void CClient%s::espWorkerThread(void* data)\n", name_);
    outf("#else\n");
    outf("void *CClient%s::espWorkerThread(void *data)\n", name_);
    outf("#endif\n");


    outs("{\n");
    outs("\tIRpcRequestBinding *request = (IRpcRequestBinding *) data;\n\n");

    outs("\tif (request != NULL)\n");
    outs("\t{\n");
    outs("\t\trequest->lock();\n");

    outf("\t\tIRpcResponseBinding *response=create%sResponseObject(request);\n",name_);

    /*
    const char *preif="";
    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        outf("\t\t%sif (stricmp(request->getMethod(), \"%s\")==0)\n\t\t{\n", preif, mthi->getName());
        outf("\t\t\tresponse = new C%s(\"%s\", request);\n\t\t}\n", mthi->getResp(), name_);
        preif="else ";
    }
    outf("\tresponse = createResponseObject(request);\n");
    */

    outs(2, "if (response!=NULL)\n");
    outs(2, "{\n");
    outs(3,     "try{\n");
    outs(4,         "request->post(*response);\n");
    outs(3,     "}\n");
    outs(3,     "catch(IException* ex){\n");
    outs(4,         "StringBuffer errorStr;\n");
    outs(4,         "ex->errorMessage(errorStr);\n");
    outf(4,         "ERRLOG(\"CClient%s::espWorkerThread(%%s)--Exception caught while posting async request: %%s\", request->getMethod(), errorStr.str());\n", name_);
    outs(4,         "ex->Release();\n");
    outs(3,     "}\n");
    outs(3,     "catch(...){\n");
    outs(4,         "ERRLOG(\"Unknown exception caught while posting async request\");\n");
    outs(3,     "}\n");
    outs(2, "}\n");

    outs("#ifdef USE_CLIENT_THREAD\n");
    outs("\t\tThunkToClientThread(request->getThunkHandle(), transferThunkEvent, (void *)response);\n");
    outs("#else\n");
    outs("\t\ttransferThunkEvent((void *)response);\n");
    outs("#endif\n");

    outs("\t\trequest->unlock();\n");

    outs("\t\tif(request->queryState()!=NULL)\n");
    outs("\t\t\trequest->queryState()->Release();\n\n");

    outs("\t\tif(response!=NULL)\n");
    outs("\t\t\tresponse->Release();\n\n");


    outs("\t\trequest->Release();\n");

    outs("\t}\n");

    outs("#if defined(_WIN32)\n");
    outs("#else\n");
    outs("\treturn (void *) 0 ;\n");
    outs("#endif\n");


    outs("}\n\n");
}

//interface IEspInstantEcl

void EspServInfo::write_event_interface()
{
    outf("interface IClient%sEvents : extends IInterface\n", name_);
    outs("{");

    EspMethodInfo *mthi;
    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        outs("\n");
        outf("\tvirtual int on%sComplete(IClient%s *resp,IInterface* state)=0;\n", mthi->getName(), mthi->getResp());
        outf("\tvirtual int on%sError(IClient%s *resp,IInterface* state)=0;", mthi->getName(), mthi->getResp());
    }

    outs("\n};\n\n");
}

void EspServInfo::write_esp_interface()
{
    outf("interface IEsp%s : extends IEspService\n", name_);
    outs("{");

    EspMethodInfo *mthi;
    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        outs("\n");
        outf("\tvirtual bool on%s(IEspContext &context, IEsp%s &req, IEsp%s &resp)=0;", mthi->getName(), mthi->getReq(), mthi->getResp());
    }

    outs("\n};\n\n");
}

void EspServInfo::write_client_interface()
{
    outf("interface IClient%s : extends IInterface\n", name_);
    outs("{\n");

    outs("\tvirtual void setProxyAddress(const char *address)=0;\n");
    outs("\tvirtual void addServiceUrl(const char *url)=0;\n");
    outs("\tvirtual void removeServiceUrl(const char *url)=0;\n");
    outs("\tvirtual void setUsernameToken(const char *userName,const char *passWord,const char *realm)=0;\n");
    outs("\tvirtual void setAction(const char *action)=0;\n");

    EspMethodInfo *mthi;
    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        outs("\n");
        outf("\tvirtual IClient%s * create%sRequest()=0;\n", mthi->getReq(), mthi->getName());
        outf("\tvirtual IClient%s * %s(IClient%s *request)=0;\n", mthi->getResp(), mthi->getName(), mthi->getReq());
        outf("\tvirtual void async_%s(IClient%s *request, IClient%sEvents *events,IInterface* state=0)=0;\n", mthi->getName(), mthi->getReq(), name_);
    }

    //add the new "flattened" client methods at the end
    outs("\n");
    for (mthi=methods;mthi!=NULL;mthi=mthi->next)
    {
        mthi->write_esp_method(name_, true, true);
    }

    outs("};\n\n");
}

static EspMethodInfo* sortMethods(EspMethodInfo* ms)
{
    if (ms==NULL)
        return ms;

    // find the smallest node
    EspMethodInfo* smallest = ms;
    EspMethodInfo* prev = NULL; // the node right before the smallest node
    for (EspMethodInfo* p = ms; p->next!=NULL; p = p->next)
    {
        if (strcmp(p->next->getName(), smallest->getName())<0)
        {
            prev = p;
            smallest = p->next;
        }
    }

    // move the smallest to the head
    if (smallest != ms)
    {
        if (prev == ms)
        {
            ms->next = smallest->next;
            smallest->next = ms;
        }
        else
        {
            EspMethodInfo* tmp = smallest->next;
            smallest->next = ms->next;
            prev->next = ms;
            ms->next = tmp;
        }
    }

    // recurively sort
    smallest->next = sortMethods(smallest->next);

    return smallest;
}

void EspServInfo::sortMethods()
{
    methods = ::sortMethods(methods);
}

//-------------------------------------------------------------------------------------------------------------
// class HIDLcompiler

char* getTargetBase(const char* outDir, const char* src)
{
    if (outDir && *outDir)
    {
        size_t dirlen = strlen(outDir);
        size_t srclen = strlen(src);
        char* buf = (char*)malloc(dirlen+srclen+5);

        // get file name only
        const char* p = src+srclen-1;
        while(p>src && *p!='/' && *p!='\\') p--;
        if (*p == '/' || *p == '\\') p++;

        // absolute path
        if (*outDir=='/' || *outDir=='\\' || outDir[1]==':')
        {
            // dir: outDir+'/'+fileName
            strcpy(buf,outDir);
        }
        else // relative path
        {
            // dir: srcPath + '/' + outDir+'/'+fileName
            size_t len = p-src;
            if (len>0)
            {
                strncpy(buf,src,len);
                if (buf[len-1]=='/' || buf[len-1]=='\\')
                    buf[len-1]='/';
                else
                    buf[len++] = '/';
            }

            strcpy(buf+len,outDir);
        }

        size_t len = strlen(buf);
        if (buf[len-1]=='/' || buf[len-1]=='\\')
        {
            buf[len-1]=0;
            len--;
        }

        // now buf has the directory name for output: make the directory if not exist
        createDirectory(buf);

        // copy the file name
        buf[len] = '/';
        strcpy(buf+len+1, p);
        //printf("src: %s. dir: %s.\n", src,outDir);
        //printf("buf: %s\n", buf);
        return buf;
    }
    else
        return strdup(src);
}

static void safeclose(int fh)
{
    if (fh >= 0)
        close(fh);
}

HIDLcompiler::HIDLcompiler(const char * sourceFile,const char *outDir)
{
    modules = NULL;
    enums = NULL;
    apis = NULL;
    servs = NULL;
    msgs = NULL;
    includes = NULL;

    filename = strdup(sourceFile);
    yyin = fopen(sourceFile, "rt");
    if (!yyin) {
        printf("Fatal Error: Cannot read %s\n",sourceFile);
        exit(1);
    }
    packagename = gettail(sourceFile);

    char* targetBase = getTargetBase(outDir, sourceFile);

    ho = createFile(targetBase,"hpp");
    cppo = createFile(targetBase, isSCM ? "ipp" : "cpp");
#if 0
    xsvo = createFile(targetBase, "xsv");
#endif

    espx = isESP ? createFile(targetBase,"esp") : -1;
    espng = isESPng ? createFile(targetBase,"_esp_ng", "ipp") : -1;
    espngc= isESPng ? createFile(targetBase,"_esp_ng", "cpp") : -1;
    espi= isESP ? createFile(targetBase, "_esp", "ipp") : -1;
    espc= isESP ? createFile(targetBase, "_esp", "cpp") : -1;

    free(targetBase);
}

HIDLcompiler::~HIDLcompiler()
{
    fclose(yyin);
    close(ho);
    close(cppo);
    //close(xsvo);
    safeclose(espx);
    safeclose(espng);
    safeclose(espngc);
    safeclose(espi);
    safeclose(espc);
    free(packagename);
    free(filename);

    delete modules;
    delete enums;
    delete apis;
    delete msgs;
    delete servs;
    delete includes;
}

void HIDLcompiler::Process()
{
    hcp = this;

    write_header_class_intro();
    nCommentStartLine = -1;
    yyparse();
    if (nCommentStartLine > -1)
    {
        char tempBuf[256];
        sprintf(tempBuf, "The comment that started at line %d is not ended yet", nCommentStartLine);
        yyerror(tempBuf);
    }
    write_header_class_outro();
    write_source_file_classes();
    //write_example_implementation_module();
    if (isESP)
    {
        processExecutionProfiling();
        write_esp();
        write_esp_ex_ipp();
    }
    if (isESPng)
    {
        write_esp_ng();
        write_esp_ng_cpp();
    }

}

void HIDLcompiler::processExecutionProfiling()
{
    EspServInfo *si;
    for (si=servs; si; si=si->next)
    {
        StrBuffer serviceProfilingOptions;

        si->executionProfilingEnabled = si->getMetaStringValue(serviceProfilingOptions,"profile_execution");

#ifdef ENABLE_DEFAULT_EXECUTION_PROFILING
        if (!si->executionProfilingEnabled)
        {
            si->executionProfilingEnabled = !si->getMetaInt("disable_profile_execution");
            // set the default to the following buckets 100us 200us, 500us, 1ms 2ms 5ms 10ms 20ms 50ms 100ms 200ms 500ms 1s 5s 10s (in microsecond units)
            serviceProfilingOptions.append("us,100,200,500,1000,2000,5000,10000,20000,50000,100000,200000,500000,1000000,5000000,10000000");
        }
#endif

        //
        // Go through each method and save any profile information to make if faster later when
        // generating code. Note that the default for the method is either what is specified in the
        // method or what is set at the service level. Still track the executionProfileEnabled flag for HIDL at the top
        EspMethodInfo *mthi=NULL;
        for (mthi=si->methods;mthi!=NULL;mthi=mthi->next)
        {
            //
            // Collect method profile execution values
            StrBuffer methodProfilingOptions;
            bool methodProfileExecutionEnabled = mthi->getMetaStringValue(methodProfilingOptions, "profile_execution");
            si->executionProfilingEnabled |= methodProfileExecutionEnabled;   // again, if a method is enabled, set top flag
            if (si->executionProfilingEnabled || methodProfileExecutionEnabled)
            {
                if (!mthi->getMetaInt("disable_profile_execution"))
                {
                    mthi->setExecutionProfilingEnabled();
                    mthi->setExecutionProfilingOptions(methodProfileExecutionEnabled ? methodProfilingOptions.str() : serviceProfilingOptions.str());
                }
            }
        }
    }
}


bool HIDLcompiler::isProcessExecutionEnabled()
{
    EspServInfo *si;
    for (si=servs;si;si=si->next)
    {
        if (si->executionProfilingEnabled)
        {
            return true;
        }
    }
    return false;
}

void HIDLcompiler::write_esp()
{
    //create the *.esp file
    gOutfile = espx;
    outf("// *** Source file generated by " HIDL " Version %s from %s.%s ***\n", HIDLVER, packagename, srcFileExt);
    outf("// *** Not to be hand edited (changes will be lost on re-generation) ***\n\n");

    outf("#ifndef %s_ESPGEN_INCLUDED\n", packagename);
    outf("#define %s_ESPGEN_INCLUDED\n\n", packagename);
    outf("#include \"%s_esp.ipp\"\n", packagename);

    outs("#include \"espcommon.hpp\"\n");

    // If any defined service has execution profiling enabled, add the required includes
    if (isProcessExecutionEnabled())
    {
        outs("#include \"jmetrics.hpp\"\n");
    }

    outs("\n");
    outs("#ifdef _WIN32\n");
    outs("#include \"edwin.h\"\n");
    outs("#include <process.h>\n");
    outs("#endif\n");

    outs("\n\n");

    EspMessageInfo * mi;
    for (mi=msgs;mi;mi=mi->next)
    {
        mi->write_esp();
    }

    EspServInfo *si;
    for (si=servs;si;si=si->next)
    {
        si->write_esp_binding(packagename);
        outs("\n\n");
        si->write_esp_service();
        outs("\n\n");
        si->write_esp_client();
        outs("\n\n");
        si->write_factory_impl();
        outs("\n\n");
    }

    outf("#endif //%s_ESPGEN_INCLUDED\n", packagename);

    gOutfile = espc;
    outf("// *** Source file generated by " HIDL " Version %s from %s.%s ***\n", HIDLVER, packagename, srcFileExt);
    outf("// *** Not to be hand edited (changes will be lost on re-generation) ***\n\n");

    outf("#include \"%s.esp\"\n", packagename);
    outs("\n\n");
}

void HIDLcompiler::write_esp_ex_ipp()
{
    gOutfile = espi;
    outf("// *** Source file generated by " HIDL " Version %s from %s.%s ***\n", HIDLVER, packagename, srcFileExt);
    outf("// *** Not to be hand edited (changes will be lost on re-generation) ***\n\n");

    outf("#ifndef %s_EX_ESPGEN_INCLUDED\n", packagename);
    outf("#define %s_EX_ESPGEN_INCLUDED\n\n", packagename);
    outs("#ifdef _MSC_VER\n");
    outs("#pragma warning(push)\n");
    outs("#pragma warning( disable : 4786)\n");
    outs("#else\n");
    outs("#pragma GCC diagnostic push\n");
    outs("#pragma GCC diagnostic ignored \"-Woverloaded-virtual\"\n");
    outs("#endif\n\n");
    outs("//JLib\n");
    outs("#include \"jliball.hpp\"\n");
    outs("\n");
    outs("//SCM Interfaces\n");
    outs("#include \"esp.hpp\"\n");
    outs("#include \"soapesp.hpp\"\n");
    outf("#include \"%s.hpp\"\n", packagename);
    outs("//ESP Bindings\n");
    outs("#include \"SOAP/Platform/soapmessage.hpp\"\n");
    outs("#include \"SOAP/Platform/soapmacro.hpp\"\n");
    outs("#include \"SOAP/Platform/soapservice.hpp\"\n");
    outs("#include \"SOAP/Platform/soapparam.hpp\"\n");
    outs("#include \"SOAP/Platform/soaphidlbind.hpp\"\n");
    outs("#include \"SOAP/client/soapclient.hpp\"\n");
    outs("\n\n");

    // metrics execution profiling requires the memory header
    if (isProcessExecutionEnabled())
    {
        outs("#include <memory>\n");
    }

    outf("namespace %s\n{\n\n", packagename);

    EspMessageInfo * mi;
    for (mi=msgs;mi;mi=mi->next)
    {
        mi->write_esp_ipp();
    }

    EspServInfo *si;
    for (si=servs;si;si=si->next)
    {
        si->write_esp_service_ipp();
        outs("\n\n");
        si->write_esp_binding_ipp();
        outs("\n\n");
        si->write_esp_client_ipp();
        outs("\n\n");
    }

    outs("}\n");
    outf("using namespace %s;\n\n", packagename);

    outs("#ifdef _MSC_VER\n");
    outs("#pragma warning(pop)\n");
    outs("#else\n");
    outs("#pragma GCC diagnostic pop\n");
    outs("#endif\n");

    outf("#endif //%s_ESPGEN_INCLUDED\n", packagename);
}


void HIDLcompiler::write_source_file_classes()
{
    gOutfile = cppo;
    outf("// *** Source file generated by " HIDL " Version %s from %s.%s ***\n", HIDLVER, packagename, srcFileExt);
    outf("// *** Not to be hand edited (changes will be lost on re-generation) ***\n\n");
    outf("#include \"%s.hpp\"\n\n",packagename);
    ModuleInfo * mi;
    for (mi=modules;mi;mi=mi->next)
    {
        if (!isSCM)
        {
            mi->write_body_class();
        }
    }
}

void HIDLcompiler::write_example_implementation_module()
{
    gOutfile = xsvo;
    outs("// Example Server Implementation Template\n");
    outf("// Source file generated by " HIDL " Version %s from %s.%s\n", HIDLVER, packagename, srcFileExt);
    outs("// *** You should copy this file before changing, as it will be overwritten next time " HIDL " is run ***\n\n");
    outs("#include <stddef.h>\n");
    outs("#include <stdlib.h>\n");
    outs("#include <assert.h>\n\n");
    outs("#include \"hrpcsock.hpp\"// default use TCP/IP sockets\n\n");
    outs("// TBD - Add other includes here\n\n");
    ModuleInfo * mi;
    for (mi=modules;mi;mi=mi->next)
    {
        mi->write_define();
    }
    outf("#include \"%s.cpp\"\n\n",packagename);
    for (mi=modules;mi;mi=mi->next)
    {
        mi->write_example_module();
    }
}

void HIDLcompiler::write_header_class_intro()
{
    gOutfile=ho;
    outf("// *** Include file generated by " HIDL " Version %s from %s.%s ***\n", HIDLVER, packagename, srcFileExt);
    outf("// *** Not to be hand edited (changes will be lost on re-generation) ***\n\n");
    outf("#ifndef %s_%s_INCL\n",packagename,isSCM?"SCM":"HID");
    outf("#define %s_%s_INCL\n\n",packagename,isSCM?"SCM":"HID");

    if (isESP)
    {
        outf("#include \"esp.hpp\"\n\n");
    }
    else if (isSCM)
    {
        //outf("#include \"scm.hpp\"\n\n");
    }
    else
        outf("#include \"hrpc.hpp\"\n\n");
}

void HIDLcompiler::write_header_class_outro()
{
    outs("\n");
    EspMessageInfo * mi;
    for (mi=msgs;mi;mi=mi->next)
    {
        mi->write_factory_decl();
    }
    outs("\n");

    outf("#endif // _%s_%s_INCL\n", packagename,isSCM?"SCM":"HID");
}

//-------------------------------------------------------------------------------------------------------------
// class EnumInfo

void EnumInfo::write_header_enum()
{
    outf("enum %s\n{\n", name);
    for (EnumValInfo *vi=vals;vi;vi=vi->next) {
        outf("\t%s = %d",vi->name,vi->val);
        if (vi->next)
            outs(",\n");
        else
            outs("\n");
    }
    outs("};\n\n");
}


// end
//-------------------------------------------------------------------------------------------------------------
