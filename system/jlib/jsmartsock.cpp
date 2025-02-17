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


#include "jsmartsock.ipp"
#include "jsecrets.hpp"
#include "jdebug.hpp"

ISmartSocketException *createSmartSocketException(int errorCode, const char *msg)
{
    return new SmartSocketException(errorCode, msg);
}

class SmartSocketListParser
{
public:
    SmartSocketListParser(const char * text)
    {
        assertex(text);
        fullText = strdup(text);
    }

    ~SmartSocketListParser()
    {
        free(fullText);
    }

    unsigned getSockets(SmartSocketEndpointArray &array, unsigned defport=0)
    {
        // IPV6TBD

        char *copyFullText = strdup(fullText);
        unsigned port = defport;

        char *saveptr;
        char *hostportstr = strtok_r(copyFullText, "|", &saveptr);
        while (hostportstr != nullptr)
        {
            // strip off http[s]://
            // is strcasestr/stristr available ?
            char *ip = strstr(hostportstr, "http://");
            if (ip == nullptr)
                ip = strstr(hostportstr, "HTTP://");
            if (ip != nullptr)
                ip += 7;
            else
            {
                ip = strstr(hostportstr, "https://");
                if (ip == nullptr)
                    ip = strstr(hostportstr, "HTTPS://");
                if (ip != nullptr)
                    ip += 8;
            }
            if (ip == nullptr)
                ip = hostportstr;

            char *p = strchr(ip, ':');

            if (p)
            {
                *p = 0;
                p++;
                port = atoi(p);
            }

            if (isdigit(*ip))
            {
                char *dash = strrchr(ip, '-');
                if (dash)
                {
                    *dash = 0;
                    int last = atoi(dash+1);
                    char *dot = strrchr(ip, '.');
                    *dot = 0;
                    int first = atoi(dot+1);
                    for (int i = first; i <= last; i++)
                    {
                        StringBuffer t;
                        t.append(ip).append('.').append(i);
                        array.append(new SmartSocketEndpoint(t.str(), port));
                    }
                }
                else
                {
                    array.append(new SmartSocketEndpoint(ip, port));
                }
            }
            else
            {
                array.append(new SmartSocketEndpoint(ip, port));
            }
            hostportstr = strtok_r(NULL, "|", &saveptr);
        }

        free(copyFullText);
        return array.ordinality();
    }

private:
    char *fullText;
};


CSmartSocket::CSmartSocket(ISocket *_sock, SocketEndpoint &_ep, ISmartSocketFactory *_factory) : sock(_sock), ep(_ep), factory(_factory)
{
};


CSmartSocket::~CSmartSocket()
{
    if (sock)
        sock->Release();
};

void CSmartSocket::read(void* buf, size32_t min_size, size32_t max_size, size32_t &size_read, unsigned timeout)
{
    try
    {
        sock->read(buf, min_size, max_size, size_read, timeout);
    }
    catch (IException *)
    {
        factory->setStatus(ep, false);

        if (sock != NULL)
        {
            sock->Release();
            sock = NULL;
        }

        throw;
    }
}

void CSmartSocket::read(void* buf, size32_t size)
{
    try
    {
        sock->read(buf, size);
    }
    catch (IException *)
    {
        factory->setStatus(ep, false);

        if (sock != NULL)
        {
            sock->Release();
            sock = NULL;
        }

        throw;
    }
}
    
size32_t CSmartSocket::write(void const* buf, size32_t size)
{
    try
    {
        return sock->write(buf, size);
    }
    catch (IException *)
    {
        factory->setStatus(ep, false);

        if (sock != NULL)
        {
            sock->Release();
            sock = NULL;
        }

        throw;
    }
}


void CSmartSocket::close()
{
    try
    {
        sock->close();
        sock->Release();
        sock = NULL;
    }
    catch (IException *)
    {
        factory->setStatus(ep, false);

        if (sock != NULL)
        {
            sock->Release();
            sock = NULL;
        }

        throw;
    }
}

CSmartSocketFactory::CSmartSocketFactory(IPropertyTree &service, bool _retry, unsigned _retryInterval, unsigned _dnsInterval)
{
    const char *name = service.queryProp("@name");
    const char *port = service.queryProp("@port");
    if (isEmptyString(name) || isEmptyString(port))
        throw createSmartSocketException(0, "CSmartSocket factory both name and port required for service configuration");

    tlsService  = service.getPropBool("@tls");
    issuer.set(service.queryProp("@issuer"));
    if (tlsService)
        tlsConfig.setown(createIssuerTlsConfig(issuer, nullptr, true, service.getPropBool("@selfSigned"), service.getPropBool("@caCert"), false));

    StringBuffer s;
    s.append(name).append(':').append(port);

    PROGLOG("CSmartSocketFactory::CSmartSocketFactory(service(%s), %s)", name, s.str());

    SmartSocketListParser slp(s);
    if (slp.getSockets(sockArray) == 0)
        throw createSmartSocketException(0, "no endpoints defined");

    shuffleEndpoints();

    nextEndpointIndex = 0;
    dnsInterval=_dnsInterval;

    retry = _retry;
    retryInterval = _retryInterval;
    if (retry)
        this->start(false);
}

CSmartSocketFactory::CSmartSocketFactory(const char *_socklist, IPropertyTree* _tlsConfig, bool _retry, unsigned _retryInterval, unsigned _dnsInterval)
{
    PROGLOG("CSmartSocketFactory::CSmartSocketFactory(%s, tlsConfig(%s))",_socklist?_socklist:"NULL", _tlsConfig?"yes":"no");
    SmartSocketListParser slp(_socklist);
    if (slp.getSockets(sockArray) == 0)
        throw createSmartSocketException(0, "no endpoints defined");

    if (_tlsConfig != nullptr)
    {
        tlsService = true;
        tlsConfig.setown(createSyncedPropertyTree(_tlsConfig));
    }

    shuffleEndpoints();

    nextEndpointIndex = 0;
    dnsInterval=_dnsInterval;

    retry = _retry;
    retryInterval = _retryInterval;
    if (retry)
        this->start(false);
}

CSmartSocketFactory::~CSmartSocketFactory()
{
    stop();
}

void CSmartSocketFactory::stop()
{
    retry = false;
    this->join();
}

void CSmartSocketFactory::resolveHostnames() {
    for(unsigned i=0; i < sockArray.ordinality(); i++) {
        SmartSocketEndpoint *ep=sockArray.item(i);
        
        SmartSocketEndpoint resolveEP=*ep;

        resolveEP.ep.set(resolveEP.name.str(), resolveEP.ep.port);

        {
            synchronized block(lock);
            *ep=resolveEP;
        }
    }   
}

void CSmartSocketFactory::shuffleEndpoints()
{
    Owned<IRandomNumberGenerator> random = createRandomNumberGenerator();
    random->seed((unsigned)get_cycles_now());

    unsigned i = sockArray.ordinality();
    while (i > 1)
    {
        unsigned j = random->next() % i;
        i--;
        sockArray.swap(i, j);
    }
}


SmartSocketEndpoint *CSmartSocketFactory::nextSmartEndpoint(bool validate)
{
    SmartSocketEndpoint *ss=sockArray.item(nextEndpointIndex);
    if (retry)
    {
        unsigned startEndpoint = nextEndpointIndex;
        while (!ss || !ss->status)
        {
            ++nextEndpointIndex %= sockArray.ordinality();
            if (startEndpoint == nextEndpointIndex)
                throw createSmartSocketException(0, "no endpoints are alive");
            ss = sockArray.item(nextEndpointIndex);
        }
    }
    ++nextEndpointIndex %= sockArray.ordinality();

    if (validate)
    {
        synchronized block(lock);
        ss->checkHost(dnsInterval);
    }
    return ss;
}

SocketEndpoint& CSmartSocketFactory::nextEndpoint()
{
    SmartSocketEndpoint *ss=nextSmartEndpoint(true);
    if (!ss)
        throw createSmartSocketException(0, "smartsocket failed to get nextEndpoint");

    return (ss->ep);
}

ISocket *CSmartSocketFactory::connect_sock(unsigned timeoutms, SmartSocketEndpoint *&ss, SocketEndpoint &ep)
{
    ss = nextSmartEndpoint(true);
    if (!ss)
        throw createSmartSocketException(0, "smartsocket failed to get nextEndpoint");

    ISocket *sock = nullptr;
    try 
    {
        ep = ss->ep;
        if (timeoutms)
            sock = ISocket::connect_timeout(ep, timeoutms);
        else
            sock = ISocket::connect(ep);
    }
    catch (IException *e)
    {
        StringBuffer s("CSmartSocketFactory::connect_sock ");
        ep.getEndpointHostText(s);
        EXCLOG(e,s.str());
        ss->status=false;
        if (sock)
            sock->Release();
        throw;
    }
    return sock;
}

ISmartSocket *CSmartSocketFactory::connect_timeout(unsigned timeoutms)
{
    SocketEndpoint ep;
    SmartSocketEndpoint *ss = nullptr;
    Owned<ISocket> sock = connect_sock(timeoutms, ss, ep);
    return new CSmartSocket(sock.getClear(), ep, this);
}

ISmartSocket *CSmartSocketFactory::connect()
{
    return connect_timeout(0);
}

ISmartSocket *CSmartSocketFactory::connectNextAvailableSocket()
{
    while(1)
    {
        try 
        {
            return connect_timeout(1000);  // 1 sec
        }
        catch (ISmartSocketException *e)
        {
            throw e;
        }
        catch (IException *e)
        {
            e->Release();   //keep trying
        }
    }
    return NULL;  // should never get here, but make the compiler happy
}

int CSmartSocketFactory::run()
{
    unsigned idx;

    while (retry)
    {
        for(unsigned secs = 0; (secs < retryInterval) && retry; secs++)
            Sleep(1000);

        if(!retry)
            break;

        for (idx = 0; idx < sockArray.ordinality(); idx++)
        {
            SmartSocketEndpoint *ss=sockArray.item(idx);
            if (ss && !ss->status)
            {
                try
                {
                    synchronized block(lock);
                    ss->checkHost(dnsInterval);
                    Owned <ISocket> testSock = ISocket::connect_timeout(ss->ep, 1000);  // 1 sec
                    testSock->close();
                    ss->status = true;
                }
                catch (IException *e)
                {
                    // still bad - keep set to false
                    e->Release();
                }
            }
        }
    }

    return 0;
}


SmartSocketEndpoint *CSmartSocketFactory::findEndpoint(SocketEndpoint &ep)
{
    for (unsigned idx = 0; idx < sockArray.ordinality(); idx++)
    {
        SmartSocketEndpoint *ss=sockArray.item(idx);
        if (ss && ss->ep.equals(ep))
            return ss;
    }
    return NULL;
}


bool CSmartSocketFactory::getStatus(SocketEndpoint &ep)
{
    SmartSocketEndpoint *ss=findEndpoint(ep);
    return (ss && ss->status);
}


void CSmartSocketFactory::setStatus(SocketEndpoint &ep, bool status)
{
    SmartSocketEndpoint *ss=findEndpoint(ep);
    if (ss)
        ss->status=status;
}

StringBuffer & CSmartSocketFactory::getUrlStr(StringBuffer &url, bool useHostName)
{
    SmartSocketEndpoint * sep = nextSmartEndpoint(false);
    if (sep)
    {
        SocketEndpoint ep;
        if(useHostName && sep->name.length())
        {
            url.append(sep->name.str());
            ep = sep->ep;
            if (ep.port)
                url.append(':').append((unsigned)ep.port);
        }
        else
        {
            sep->checkHost(dnsInterval);
            SocketEndpoint ep = sep->ep;
            ep.getEndpointHostText(url);
        }
    }
    return url;
}

ISmartSocketFactory *createSmartSocketFactory(IPropertyTree &service, bool _retry, unsigned _retryInterval, unsigned _dnsInterval)
{
    return new CSmartSocketFactory(service, _retry, _retryInterval, _dnsInterval);
}

ISmartSocketFactory *createSmartSocketFactory(const char *_socklist, bool _retry, unsigned _retryInterval, unsigned _dnsInterval)
{
    return new CSmartSocketFactory(_socklist, nullptr, _retry, _retryInterval, _dnsInterval);
}
