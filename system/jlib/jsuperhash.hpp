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



#ifndef SUPERHASH_HPP
#define SUPERHASH_HPP

//#define TRACE_HASH
#undef expand

#include "jiface.hpp"
#include "jiter.hpp"
#include "jstring.hpp"
#include "jmutex.hpp"

constexpr unsigned fnvInitialHash32 = 0x811C9DC5;
constexpr unsigned fnvPrime32 = 0x01000193;

extern jlib_decl unsigned hashc( const unsigned char *k, unsigned length, unsigned initval);
extern jlib_decl unsigned hashnc( const unsigned char *k, unsigned length, unsigned initval);
extern jlib_decl unsigned hashcz( const unsigned char *k, unsigned initval);
extern jlib_decl unsigned hashncz( const unsigned char *k, unsigned initval);
extern jlib_decl unsigned hashc_fnv1a(const unsigned char *k, unsigned length, unsigned initval);
extern jlib_decl unsigned hashnc_fnv1a(const unsigned char *k, unsigned length, unsigned initval);
extern jlib_decl unsigned hashcz_fnv1a(const unsigned char *k, unsigned initval);
extern jlib_decl unsigned hashncz_fnv1a(const unsigned char *k, unsigned initval);

class jlib_decl SuperHashTable : public CInterface
{
public:
    SuperHashTable(void);
    SuperHashTable(unsigned initsize);
    ~SuperHashTable();
    // Derived class destructor expected to call _releaseAll()
    
    void             reinit(unsigned initsize);
    void             kill(void);
    inline unsigned  count() const { return tablecount; }
    inline unsigned  ordinality() const { return tablecount; }
    inline memsize_t queryMem() const { return tablesize * sizeof(void *); } // hash table table memory size
    void *           next(const void *et) const;
    void             ensure(unsigned mincount);
    void             releaseAll(); // like kill(), but does not resize the table

    void dumpStats() const;

protected:
    void             init(unsigned initsize);
    void             _releaseAll(void); // not guaranteed to be thread safe, typically called from destructor
    inline bool      add(void * et) { return doAdd(et, false); }
    inline bool      replace(void * et) { return doAdd(et, true); }
    void             addNew(void * et); //use this when you are sure the key does not already exist in the table (saves some needless matching)
    void             addNew(void * donor, unsigned hash);
    void *           addOrFind(void *);
    void *           addOrFindExact(void * donor);
    inline void *    find(const void * param) const { return table[doFind(param)]; }
    inline void *    find(unsigned hashcode, const void * param) const { return table[doFind(hashcode, param)]; }
    void *           findElement(unsigned hashcode, const void * searchE) const;
    void *           findElement(const void * searchE) const;
    void *           findExact(const void * et) const;
    // remove(void *) zaps key (i.e. a match using matchesFindParam method)
    // removeExact(void *) zaps element (i.e. a match using pointer==pointer)
    bool             remove(const void * param);
    bool             removeExact(void * et);
    inline void      setCache(unsigned v) const { cache = v; }

    inline unsigned  doFind(const void * findParam) const
      { return doFind(getHashFromFindParam(findParam), findParam); }

    unsigned firstIdx() const { return tablecount == 0 ? tablesize : validIdx(0); }
    unsigned validIdx(unsigned i) const;

private:
    bool             doAdd(void *, bool);
    void             doDeleteElement(unsigned);
    unsigned         doFind(unsigned, const void *) const;
    unsigned         doFindElement(unsigned, const void *) const;
    unsigned         doFindNew(unsigned) const;
    unsigned         doFindExact(const void *) const;
    void             doKill(void);
    void             expand();
    void             expand(unsigned newsize);
    void             note_searchlen(unsigned) const;

    virtual void     onAdd(void *et) = 0;
    virtual void     onRemove(void *et) = 0;
    virtual unsigned getHashFromElement(const void *et) const = 0;
    virtual unsigned getHashFromFindParam(const void *fp) const = 0;
    virtual const void * getFindParam(const void *et) const = 0;
    virtual unsigned getTableLimit(unsigned max);
    virtual bool     matchesFindParam(const void *et, const void *key, unsigned fphash) const = 0;
    virtual bool     matchesElement(const void *et, const void *searchET) const;

protected:
    mutable unsigned cache;             // before pointer to improve 64bit packing.
    void * *         table;
    unsigned         tablesize;
    unsigned         tablecount;
#ifdef TRACE_HASH
    mutable unsigned __int64 search_tot;
    mutable unsigned search_num;
    mutable unsigned search_max;
#endif
};

template <class ET, class FP>
class SuperHashTableOf : public SuperHashTable
{
public:
    typedef SuperHashTableOf<ET, FP> SELF;
    friend class ConstHashItem;
    class ConstHashItem
    {
    public:
        ConstHashItem(const SELF & _self, unsigned _idx) : self(_self), idx(_idx) {}

        ET & operator * () const { return self.element(idx); }
        bool operator != (const ConstHashItem & other) const { return &self != &other.self || idx != other.idx; }
        ConstHashItem & operator ++ () { idx = self.validIdx(idx+1); return *this; }
    private:
        const SELF & self;
        unsigned idx;
    };

  public:
    SuperHashTableOf(void) : SuperHashTable() {}
    SuperHashTableOf(unsigned initsize) : SuperHashTable(initsize) {}
    inline bool      add(ET & et)
      { return SuperHashTable::add(&et); }
    inline bool      replace(ET & et)
      { return SuperHashTable::replace(&et); }
    inline ET *      addOrFind(ET & et)
      { return static_cast<ET *>(SuperHashTable::addOrFind(&et)); }
    inline ET *      addOrFindExact(ET & et)
      { return static_cast<ET *>(SuperHashTable::addOrFindExact(&et)); }
    inline ET *      find(const FP * fp) const
      { return static_cast<ET *>(SuperHashTable::find(fp)); }
    inline ET *      next(const ET * et) const
      { return static_cast<ET *>(SuperHashTable::next(et)); }
    inline ET *      find(unsigned hashCode, const FP * fp) const
      { return static_cast<ET *>(SuperHashTable::find(hashCode, fp)); }
    inline ET *      findExact(const ET & et) const
      { return static_cast<ET *>(SuperHashTable::findExact(&et)); }
    inline bool      remove(const FP * fp)
      { return SuperHashTable::remove((const void *)(fp)); }
    inline bool      removeExact(ET * et)
      { return SuperHashTable::removeExact(et); }

    ConstHashItem begin() const { return ConstHashItem(*this, firstIdx()); }
    ConstHashItem end() const { return ConstHashItem(*this, SELF::tablesize); }

  private:
    ET & element(unsigned idx) const { return *static_cast<ET *>(this->table[idx]); }

};

// Macro to provide find method taking reference instead of pointer (yuk!)

#define IMPLEMENT_SUPERHASHTABLEOF_REF_FIND(ET, FP)                        \
    inline ET *      find(FP & fp) const                                   \
      { return SuperHashTableOf<ET, FP>::find(&fp); }                      \
    inline ET *      find(unsigned hash, FP & fp) const                    \
      { return SuperHashTableOf<ET, FP>::find(hash, &fp); }


// simple type hashing HT impl.
// elements (ET) must implement queryFindParam.
template <class ET, class FP>
class SimpleHashTableOf : public SuperHashTableOf<ET, FP>
{
    typedef SimpleHashTableOf<ET, FP> SELF;
public:
    SimpleHashTableOf(void) : SuperHashTableOf<ET, FP>() { }
    SimpleHashTableOf(unsigned initsize) : SuperHashTableOf<ET, FP>(initsize) { }
    ~SimpleHashTableOf() { SELF::_releaseAll(); }

    IMPLEMENT_SUPERHASHTABLEOF_REF_FIND(ET, FP);

    virtual void onAdd(void * et __attribute__((unused))) { }
    virtual void onRemove(void * et __attribute__((unused))) { }
    virtual unsigned getHashFromElement(const void *et) const
    {
        return hashc((const unsigned char *) ((const ET *) et)->queryFindParam(), sizeof(FP), 0);
    }
    virtual unsigned getHashFromFindParam(const void *fp) const
    {
        return hashc((const unsigned char *) fp, sizeof(FP), 0);
    }
    virtual const void *getFindParam(const void *et) const
    {
        return ((const ET *)et)->queryFindParam();
    }
    virtual bool matchesFindParam(const void *et, const void *fp, unsigned fphash __attribute__((unused))) const
    {
        return *(FP *)((const ET *)et)->queryFindParam() == *(FP *)fp;
    }
};

template <class ET, class FP>
class OwningSimpleHashTableOf : public SimpleHashTableOf<ET, FP>
{
    typedef OwningSimpleHashTableOf<ET, FP> SELF;
public:
    OwningSimpleHashTableOf(void) : SimpleHashTableOf<ET, FP>() { }
    OwningSimpleHashTableOf(unsigned initsize) : SimpleHashTableOf<ET, FP>(initsize) { }
    ~OwningSimpleHashTableOf() { SELF::_releaseAll(); }

    virtual void onRemove(void *et) { ((ET *)et)->Release(); }
};

class jlib_decl SuperHashIterator : public CInterface
{
public:
    SuperHashIterator(const SuperHashTable & _table, bool _linkTable=true) : linkTable(_linkTable), table(_table) { cur = NULL; if (linkTable) table.Link(); }
    ~SuperHashIterator() { if (linkTable) table.Release(); }

    virtual bool     first(void)
      { cur = table.next(NULL); return cur != NULL; }
    virtual bool     isValid(void) { return cur != NULL; }
    virtual bool     next(void)
      { if (cur) cur = table.next(cur); return (cur != NULL); }
 
protected:
    void *           queryPointer() const { assertex(cur); return cur; }

private:
    bool linkTable;
    const SuperHashTable & table;
    void * cur;
};

template <class ET>
class SuperHashIteratorOf : public SuperHashIterator
{
  public:
    SuperHashIteratorOf(const SuperHashTable & _table, bool linkTable=true) : SuperHashIterator(_table, linkTable) {}
    ET &             query() const
      { return *(static_cast<ET *>(queryPointer())); }
};

template <class ET, typename INTERFACE, bool LINKTABLE>
class SuperHashIIteratorOf : public CInterfaceOf<INTERFACE>
{
  public:
    SuperHashIIteratorOf(const SuperHashTable & _table) : table(_table) { cur = NULL; if (LINKTABLE) table.Link(); }
    ~SuperHashIIteratorOf() { if (LINKTABLE) table.Release(); }

    virtual bool     first(void)
    {
        cur = table.next(NULL);
        return cur != NULL;
    }
    virtual bool     isValid(void)
    {
        return cur != NULL;
    }
    virtual bool     next(void)
    {
        if (cur) cur = table.next(cur);
        return (cur != NULL);
    }
    virtual ET & query()
    {
        assertex(cur);
        return *(static_cast<ET *>(cur));
    }
    virtual ET & get()
    {
        assertex(cur);
        return OLINK(*(static_cast<ET *>(cur)));
    }

private:
    const SuperHashTable & table;
    void*            cur;
};

template <class ET>
class StringSuperHashTableOf : public SuperHashTableOf<ET, const char>
{
    typedef StringSuperHashTableOf<ET> SELF;
public:
    StringSuperHashTableOf(void) : SuperHashTableOf<ET, const char>() { }
    StringSuperHashTableOf(unsigned initsize) : SuperHashTableOf<ET, const char>(initsize) { }
    ~StringSuperHashTableOf() { SELF::_releaseAll(); }

    virtual void onAdd(void *et __attribute__((unused))) { }
    virtual void onRemove(void *et __attribute__((unused))) { }
    virtual unsigned getHashFromElement(const void *et) const
    {
        const char *str = ((const ET *) et)->queryFindString();
        return hashcz((const unsigned char *) str, 0);
    }
    virtual unsigned getHashFromFindParam(const void *fp) const
    {
        return hashcz((const unsigned char *) fp, 0);
    }
    virtual const void *getFindParam(const void *et) const
    {
        return ((const ET *)et)->queryFindString();
    }
    virtual bool matchesFindParam(const void *et, const void *fp, unsigned fphash __attribute__((unused))) const
    {
        return (0==strcmp(((const ET *)et)->queryFindString(), (const char *)fp));
    }
};

template <class ET>
class OwningStringSuperHashTableOf : public StringSuperHashTableOf<ET>
{
    typedef OwningStringSuperHashTableOf<ET> SELF;
public:
    OwningStringSuperHashTableOf(void) : StringSuperHashTableOf<ET>() { }
    OwningStringSuperHashTableOf(unsigned initsize) : StringSuperHashTableOf<ET>(initsize) { }
    ~OwningStringSuperHashTableOf() { SELF::_releaseAll(); }

    virtual void onRemove(void *et) { ((ET *)et)->Release(); }
};

// thread safe simple hash table impl. 
template <class ET, class FP>
class ThreadSafeSimpleHashTableOf : private SuperHashTable
{
    typedef ThreadSafeSimpleHashTableOf<ET, FP> SELF;

    virtual void onAdd(void *et __attribute__((unused))) { }
    virtual void onRemove(void *et __attribute__((unused))) { }
    virtual unsigned getHashFromElement(const void *et) const
    {
        return hashc((const unsigned char *) ((const ET *) et)->queryFindParam(), sizeof(FP), 0);
    }
    virtual unsigned getHashFromFindParam(const void *fp) const
    {
        return hashc((const unsigned char *) fp, sizeof(FP), 0);
    }
    virtual const void *getFindParam(const void *et) const
    {
        return ((const ET *)et)->queryFindParam();
    }
    virtual bool matchesFindParam(const void *et, const void *fp, unsigned fphash __attribute__((unused))) const
    {
        return *(FP *)((const ET *)et)->queryFindParam() == *(FP *)fp;
    }
protected:
    using SuperHashTable::_releaseAll;
public:
    mutable CriticalSection crit;

    ThreadSafeSimpleHashTableOf(void) : SuperHashTable() { }
    ThreadSafeSimpleHashTableOf(unsigned initsize) : SuperHashTable(initsize) { }
    ~ThreadSafeSimpleHashTableOf() { _releaseAll(); }

    ET *find(FP & fp) const
    {
        CriticalBlock block(crit);
        return (ET *) SuperHashTable::find(&fp);
    }

    SuperHashTable &queryBaseTable() { return *this; }
    void kill()
    {
        CriticalBlock block(crit);
        SuperHashTable::kill();
    }
    void releaseElements()
    {
        CriticalBlock block(crit);
        SuperHashTable::releaseAll();
    }
    bool add(ET & et)
    { 
        CriticalBlock block(crit);
        return SuperHashTable::add(&et); 
    }
    bool replace(ET & et)
    { 
        CriticalBlock block(crit);
        return SuperHashTable::replace(&et); 
    }
    ET * addOrFind(ET & et)
    { 
        CriticalBlock block(crit);
        return static_cast<ET *>(SuperHashTable::addOrFind(&et)); 
    }
    ET * find(const FP * fp) const
    { 
        CriticalBlock block(crit);
        return static_cast<ET *>(SuperHashTable::find(fp)); 
    }
    ET * findExact(const ET & et) const
    { 
        CriticalBlock block(crit);
        return static_cast<ET *>(SuperHashTable::findExact(&et)); 
    }
    bool remove(const FP * fp)
    { 
        CriticalBlock block(crit);
        return SuperHashTable::remove((const void *)(fp)); 
    }
    bool removeExact(ET * et)
    { 
        CriticalBlock block(crit);
        return SuperHashTable::removeExact(et); 
    }
    unsigned count() const
    {
        CriticalBlock block(crit);
        return SuperHashTable::count();
    }
};

template <class ET, class FP>
class ThreadSafeOwningSimpleHashTableOf : public ThreadSafeSimpleHashTableOf<ET, FP>
{
    typedef ThreadSafeOwningSimpleHashTableOf<ET, FP> SELF;
public:
    ~ThreadSafeOwningSimpleHashTableOf() { SELF::_releaseAll(); }
    virtual void onRemove(void *et) { ((ET *)et)->Release(); }
};

// template mapping object for base type to arbitrary object
template <class ET, class FP>
class HTMapping : public CInterface
{
protected:
    ET &et;
    FP fp;
public:
    HTMapping(ET &_et, const FP &_fp) : et(_et), fp(_fp) { }
    const void *queryFindParam() const { return &fp; }
    ET &queryElement() const { return et; }
    const FP &queryFindValue() const { return fp; }
};

// template mapping object for base type to IInterface object
template <class ET, class FP>
class OwningHTMapping : public HTMapping<ET, FP>
{
public:
    OwningHTMapping(ET &et, FP &fp) : HTMapping<ET, FP>(et, fp) { }
    ~OwningHTMapping() { this->et.Release(); }
};

template <class ET, class FP>
class LinkedHTMapping : public OwningHTMapping<ET, FP>
{
public:
    LinkedHTMapping(ET &et, FP &fp) : OwningHTMapping<ET, FP>(et, fp) { this->et.Link(); }
};

// template mapping object for string to arbitrary object
template <class ET>
class StringHTMapping : public CInterface
{
public:
    StringHTMapping(const char *_fp, ET &_et) : et(_et), fp(_fp) { }
    const char *queryFindString() const { return fp; }

protected:
    ET &et;
    StringAttr fp;
};

// template mapping object for string to IInterface object
template <class ET>
class OwningStringHTMapping : public StringHTMapping<ET>
{
public:
    OwningStringHTMapping(const char *fp, ET &et) : StringHTMapping<ET>(fp, et) { }
    ~OwningStringHTMapping() { this->et.Release(); }
    ET &query() { return this->et; }
    ET &get() { this->et.Link(); return this->et; }
};

// NB: only really here, because of circular include problems

// utility atom class, holding hash,string and count
class jlib_decl HashKeyElement
{
public:
    const char *get() { return (const char *)keyPtr(); }
    unsigned length() { return (size32_t)strlen((const char *)keyPtr()); }
    unsigned queryHash() const { return hashValue; }
    unsigned queryReferences() { return linkCount+1; } // 1 implicit

private:        
    const char *keyPtr() { return ((const char *)this)+sizeof(*this); }

    unsigned hashValue;
    unsigned linkCount;
    HashKeyElement();

friend class AtomRefTable;
};

#ifdef _MSC_VER
#pragma warning(disable : 4275 )
#endif
typedef const char constcharptr;
class jlib_decl AtomRefTable : public SuperHashTableOf<HashKeyElement, constcharptr>
{
public:
    static HashKeyElement *createKeyElement(const char *key, bool nocase)
    {
        size32_t l = (size32_t)strlen(key);
        HashKeyElement *hke = (HashKeyElement *) checked_malloc(sizeof(HashKeyElement)+l+1,-605);
        memcpy((void *) (hke->keyPtr()), key, l+1);
        if (nocase)
            hke->hashValue = hashnc_fnv1a((const unsigned char *)key, l, fnvInitialHash32);
        else
            hke->hashValue = hashc_fnv1a((const unsigned char *)key, l, fnvInitialHash32);
        hke->linkCount = 0;
        return hke;
    }

protected:
    CriticalSection crit;
    bool nocase;

    inline HashKeyElement *createKeyElement(const char *key)
    {
        HashKeyElement *hke = createKeyElement(key, nocase);
        verifyex(add(*hke));
        return hke;
    }

public:
    IMPLEMENT_SUPERHASHTABLEOF_REF_FIND(HashKeyElement, constcharptr);

    AtomRefTable(bool _nocase=false) : SuperHashTableOf<HashKeyElement, constcharptr>(3000), nocase(_nocase) { }
    ~AtomRefTable() { _releaseAll(); }

    inline HashKeyElement *findLink(const char *_key)
    {
        CriticalBlock b(crit);
        HashKeyElement *key = find(*_key);
        if (key) key->linkCount++;
        return key;
    }

    // assumes key is member of this table.

    inline HashKeyElement *queryCreate(const char *_key)
    {
        CriticalBlock b(crit);
        HashKeyElement *key = find(*_key);
        if (key)
            key->linkCount++;
        else
            key = createKeyElement(_key);
        return key;
    }

    inline HashKeyElement *queryCreate(const char *_key, bool &didCreate)
    {
        CriticalBlock b(crit);
        HashKeyElement *key = find(*_key);
        if (key)
        {
            didCreate = false;
            key->linkCount++;
        }
        else
        {
            didCreate = true;
            key = createKeyElement(_key);
        }
        return key;
    }

    inline void linkKey(const char *key)
    {
        queryCreate(key);
    }

    inline bool releaseKey(HashKeyElement *key)
    {
        CriticalBlock b(crit);
        if (0 == key->linkCount)
        {
            verifyex(removeExact(key));
            return true;
        }
        --key->linkCount;
        return false;
    }

protected:
// SuperHashTable definitions
    virtual void onAdd(void *e __attribute__((unused))) { }
    virtual void onRemove(void *e) 
    { 
        free(e); 
    }

    virtual unsigned getHashFromElement(const void *e) const
    {
        return ((HashKeyElement *) e)->queryHash();
    }

    virtual unsigned getHashFromFindParam(const void *fp) const
    {
        if (nocase)
            return hashncz_fnv1a((const unsigned char *)fp, fnvInitialHash32);
        else
            return hashcz_fnv1a((const unsigned char *)fp, fnvInitialHash32);
    }

    virtual const void *getFindParam(const void *e) const
    {
        return ((HashKeyElement *) e)->get();
    }

    virtual bool matchesFindParam(const void *e, const void *fp, unsigned fphash __attribute__((unused))) const;
};

#endif
