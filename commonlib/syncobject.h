//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _SYNC_OBJECT_H_
 #define _SYNC_OBJECT_H_

#include <windows.h>

//#include "commondefs.h"
#include "timeoutexception.h"
#include "cancelexception.h"
#include "ownershipexception.h"

namespace commonlib {
namespace sync {

class SyncObject;

class SyncObject
{
    //
    // types
    //
public:
    class Locker
    {
    public:
        Locker (SyncObject& sync)
            : m_sync (sync)
        {
            m_sync.lock ();
        }

        ~Locker ()
        {
            m_sync.unlock ();
        }

    protected:
        Locker (const Locker& right) : m_sync (right.m_sync) {};
        Locker& operator= (const Locker& right) { return *this; }

    private:
        SyncObject& m_sync;
    }; // Locker

    enum wait_result_t
    {
        wait_result_ownership_error = -3,
        wait_result_cancel  = -2,
        wait_result_timeout = -1,
        wait_result_ok = 0
    }; // enum wait_result_t

protected:
    typedef CRITICAL_SECTION pthread_mutex_t;
    typedef struct Events
    {
        enum 
        {
            Signal    = 0,
            Broadcast,
            CancelSignal,
            CancelBroadcast,
            MaxEvents
        };

        HANDLE m_events [MaxEvents];
    } pthread_cond_t; // pthread_cond_t

    struct WaitHolder
    {
        WaitHolder (unsigned long& counter)
            : m_counter (counter)
        {
            ++m_counter;
        }

        ~WaitHolder ()
        {
            --m_counter;
        }

        unsigned long& m_counter;
    };

private:

    //
    // methods
    //
public:
    SyncObject ()
        : m_owner (-1),
        m_lockCount (0),
        m_waitCount (0)
    {
        m_cond.m_events [Events::Signal]          = CreateEvent (NULL, FALSE, FALSE, NULL); 
        m_cond.m_events [Events::Broadcast]       = CreateEvent (NULL, TRUE, FALSE, NULL); 
        m_cond.m_events [Events::CancelSignal]    = CreateEvent (NULL, FALSE, FALSE, NULL); 
        m_cond.m_events [Events::CancelBroadcast] = CreateEvent (NULL, TRUE, FALSE, NULL); 
        InitializeCriticalSection (&m_sync);
    } // SyncObject

    virtual ~SyncObject ()
    {
        CloseHandle (m_cond.m_events [Events::Signal]);
        CloseHandle (m_cond.m_events [Events::Broadcast]);
        CloseHandle (m_cond.m_events [Events::CancelSignal]);
        CloseHandle (m_cond.m_events [Events::CancelBroadcast]);
        DeleteCriticalSection (&m_sync);
    } // ~SyncObject

    virtual void lock ()
    {
        EnterCriticalSection (&m_sync);
        m_owner = GetCurrentThreadId ();
        ++m_lockCount;
    } // lock

    virtual void unlock ()
    {
        if (m_owner != GetCurrentThreadId ())
            throw OwnershipException (L"owner error");

        --m_lockCount;
        if (0 == m_lockCount)
            m_owner = -1;
        LeaveCriticalSection (&m_sync);
    } // unlock

    virtual void wait (int timeout)
    {
        wait_result_t wait_res = wait_noexc (timeout);

        switch (wait_res)
        {
            case wait_result_ownership_error:
                throw OwnershipException (L"owner error");
            case wait_result_cancel:
                throw CancelException (L"wait cancel");
            case wait_result_timeout:
                throw TimeoutException (L"wait time out");
        }
    } // wait

    virtual wait_result_t wait_noexc (int timeout)
    {
        if (m_owner != GetCurrentThreadId ())
            return wait_result_ownership_error;

        WaitHolder waitHolder (m_waitCount);

        unlock ();

        DWORD result = WaitForMultipleObjects (Events::MaxEvents, m_cond.m_events, FALSE, timeout); 

        lock ();

        if (1 == m_waitCount && ((WAIT_OBJECT_0 + Events::Signal) <= result && (WAIT_OBJECT_0 + Events::MaxEvents) > result))
            ResetEvent (m_cond.m_events [result - WAIT_OBJECT_0]);

        if ((WAIT_OBJECT_0 + Events::CancelSignal) == result || (WAIT_OBJECT_0 + Events::CancelBroadcast) == result)
            return wait_result_cancel;

        if (WAIT_TIMEOUT == result)
            return wait_result_timeout;

        return wait_result_ok;  
    } // wait_noexc

    virtual void notify ()
    {
        if (m_owner != GetCurrentThreadId ())
            throw OwnershipException (L"owner error");

        if (false == pulseEvent (m_cond.m_events [Events::Signal]))
            throw SyncException (L"pulseEvent error", GetLastError ());
    } // notify

    virtual void notifyAll ()
    {
        if (m_owner != GetCurrentThreadId ())
            throw OwnershipException (L"owner error");

        if (false == pulseEvent (m_cond.m_events [Events::Broadcast]))
            throw SyncException (L"pulseEvent error", GetLastError ());
    } // notifyAll

    virtual void cancel ()
    {
        if (m_owner != GetCurrentThreadId ())
            throw OwnershipException (L"owner error");

        if (false == pulseEvent (m_cond.m_events [Events::CancelSignal]))
            throw SyncException (L"pulseEvent error", GetLastError ());
    } // cancel

    virtual void cancelAll ()
    {
        if (m_owner != GetCurrentThreadId ())
            throw OwnershipException (L"owner error");

        if (false == pulseEvent (m_cond.m_events [Events::CancelBroadcast]))
            throw SyncException (L"pulseEvent error", GetLastError ());
    } // cancelAll

protected:
    bool pulseEvent (HANDLE event)
    {
        //#pragma message (__WARNING__ "SyncObject check pulseEvent for no safe event state signaled")
        BOOL result = TRUE;

        lock ();

        if (0 != m_waitCount)
        {
            //return (TRUE == PulseEvent (event));
            result = SetEvent (event);

            //       if (TRUE == result)
            //         result = (result && ResetEvent (event));
        }

        unlock ();

        return (TRUE == result);
    } // pulseEvent

    SyncObject (const SyncObject& right) {};
    SyncObject& operator= (const SyncObject& right) { return *this; }

private:

    //
    // data
    //
public:
protected:
    pthread_cond_t  m_cond;
    pthread_mutex_t m_sync;
    unsigned long   m_owner;
    unsigned long   m_lockCount;
    unsigned long   m_waitCount;

private:
}; // SyncObject

} // namespace sync {
} // namespace commonlib {

#endif //_SYNC_OBJECT_H_
