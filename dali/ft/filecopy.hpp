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

#ifndef FILECOPY_HPP
#define FILECOPY_HPP

#include "jsocket.hpp"
#include "dafdesc.hpp"
#include "daft.hpp"
#include "junicode.hpp"

typedef enum
{
    FFTunknown,
    FFTfixed, FFTvariable, FFTblocked,
    FFTcsv,
    FFTutf,                             // any format, default to utf-8n
    FFTutf8, FFTutf8n,
    FFTutf16, FFTutf16be, FFTutf16le,
    FFTutf32, FFTutf32be, FFTutf32le,
    FFTrecfmvb, FFTrecfmv, FFTvariablebigendian,
    FFTkey,
    FFTlast
 } FileFormatType;

constexpr const char * FileFormatTypeStr[] =
{       "FFTunknown",
        "FFTfixed", "FFTvariable", "FFTblocked",
        "FFTcsv",
        "FFTutf",                             // any format, default to utf-8n
        "FFTutf8", "FFTutf8n",
        "FFTutf16", "FFTutf16be", "FFTutf16le",
        "FFTutf32", "FFTutf32be", "FFTutf32le",
        "FFTrecfmvb", "FFTrecfmv", "FFTvariablebigendian",
        "FFTkey",
        "FFTlast"
};
enum { FTactionpull, FTactionpush, FTactionpartition };

typedef enum
{
    FMTunknown,
    FMTxml,
    FMTjson,
    FMTlast
 } FileMarkupType;

constexpr const char * FileMarkupTypeStr[] =
{
    "FMTunknown",
    "FMTxml",
    "FMTjson",
    "FMTlast"
};

#define EFX_BLOCK_SIZE          32768

class DALIFT_API FileFormat
{
public:
    FileFormat(FileFormatType _type = FFTunknown, unsigned _recordSize = 0) : markup(FMTunknown), headerLength((unsigned)-1), footerLength((unsigned)-1)
            { set(_type, _recordSize); maxRecordSize = 0; quotedTerminator = true;}

    void deserialize(MemoryBuffer & in);
    void deserializeExtra(MemoryBuffer & in, unsigned version);
    bool equals(const FileFormat & other) const     { return (type == other.type) && (recordSize == other.recordSize); }
    unsigned getUnitSize() const;
    bool isUtf() const                              { return (type >= FFTutf) && (type <= FFTutf32le); }
    bool restore(IPropertyTree * props);
    void save(IPropertyTree * props);
    void serialize(MemoryBuffer & out) const;
    void serializeExtra(MemoryBuffer & out, unsigned version) const;
    void set(FileFormatType _type, unsigned _recordSize = 0) { type = _type, recordSize = _recordSize; }
    void set(const FileFormat & src);
    bool hasQuote() const                           { return (quote == NULL) || (*quote != '\0'); }
    bool hasQuotedTerminator() const                { return quotedTerminator; }
    const char * getFileFormatTypeString() const        { return FileFormatTypeStr[type]; }
    void updateMarkupType(const char *rowLocator, const char *kind);
    const char *getPartSeparatorString(){return (markup==FMTjson) ? ",\n" : NULL;}
    bool isCsv() const                              { return (type == FFTcsv); }

public:
    FileFormatType      type;
    unsigned            recordSize;
    unsigned            maxRecordSize;
    StringAttr          separate;
    StringAttr          quote;
    StringAttr          terminate;
    StringAttr          escape;
    StringAttr          rowTag;

    //These values aren't serialized/deserialized:
    FileMarkupType      markup;
    unsigned            headerLength;
    unsigned            footerLength;
    bool                quotedTerminator;
};
UtfReader::UtfFormat getUtfFormatType(FileFormatType type);
bool sameEncoding(const FileFormat & src, const FileFormat & tgt);

typedef enum {
        dfu_unknown,
        dfu_copy,
        dfu_export,
        dfu_import,
        dfu_move,
        dfu_replicate_distributed,
        dfu_replicate,
        dfu_transfer,
    } dfu_operation;

constexpr const char * DfuOperationStr[] =
    {
        "DFUunknown",
        "DFUcopy",
        "DFUexport",
        "DFUimport",
        "DFUmove",
        "DFUreplicate_distributed",
        "DFUreplicate",
        "DFUtransfer"
    };
interface IFileSprayer : public IInterface
{
public:
    virtual void removeSource() = 0;
    virtual void setAbort(IAbortRequestCallback * _abort) = 0;
    virtual void setPartFilter(IDFPartFilter * _filter) = 0;
    virtual void setProgress(IDaftProgress * _progress) = 0;
    virtual void setReplicate(bool _replicate) = 0;
    virtual void setSource(IDistributedFile * source) = 0;
    virtual void setSource(IFileDescriptor * source) = 0;
    virtual void setSource(IDistributedFilePart * part) = 0;
    virtual void setSourceTarget(IFileDescriptor * fd, DaftReplicateMode mode) = 0;
    virtual void setTarget(IDistributedFile * target) = 0;
    virtual void setTarget(IFileDescriptor * target, unsigned copy=0) = 0;
    virtual void setTarget(IGroup * target) = 0;
    virtual void setTarget(INode * target) = 0;
    virtual void spray() = 0;
    virtual void setOperation(dfu_operation op) = 0;
    virtual dfu_operation getOperation() const = 0;
    virtual const char * getOperationTypeString() const = 0;

};

extern DALIFT_API IFileSprayer * createFileSprayer(IPropertyTree * _options, IPropertyTree * _progress, IRemoteConnection * recoveryConnection, const char *wuid);

extern DALIFT_API void testPartitions();

#endif
