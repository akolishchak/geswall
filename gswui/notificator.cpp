//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "notificator.h"

#include "commonlib/commondefs.h"
#include "commonlib/thread.h"

#include "config/configurator.h"
#include "app/application.h"

#include "gswui/attackfilter/attackfilter.h"
#include "gswui/attackfilter/process_manager.h"

#include "gswui/logwnd/log_wnd.h"
#include "gswui/logwnd/notify_wnd.h"
#include "gswui/logwnd/attack_wnd.h"

#include "db/storage.h"

#include "notification.h"

#include "resource1.h"

#include "logcount.h"

#ifndef BOOST_REGEX_NO_LIB
 #define BOOST_REGEX_NO_LIB
#endif // BOOST_REGEX_NO_LIB 
#include <boost/regex.hpp>

namespace gswui {
namespace notificator {

typedef std::wstring                                wstring;

typedef commonlib::thread                           work_thread;
typedef boost::shared_ptr <work_thread>             ptr_to_work_thread;

typedef gswui::logwnd::log_wnd                      log_wnd;
typedef gswui::logwnd::notify_wnd                   notify_wnd;
typedef gswui::logwnd::attack_wnd                   attack_wnd;
typedef boost::shared_ptr <log_wnd>                 ptr_to_log_wnd;
typedef boost::shared_ptr <attack_wnd>              ptr_to_attack_wnd;
typedef gswui::attackfilter::ptr_to_process_manager ptr_to_process_manager;

int                                 work_thread_proc ();
void                                refresh_patterns ();
gswui::attackfilter::pattern_type_t db_pattern_type_to_internal_type (Storage::IdsPatternType db_pattern_type);
gswui::attackfilter::object_type_t  db_object_type_to_internal_type (NtObjectType nt_object_type);
wstring                             cut_string (const wstring& data, size_t length);
wstring                             get_application_name (Notification& drv_notify);
void                                check_reload_setting ();
void                                reload_setting ();


// sample: 2006.08.04 01:05:46 avant.exe READONLY access to \Device\NamedPipe\wkssvc (File) 
//     process: any process name
//     access:  "STOP", "DENY", "READONLY", "REDIRECT", "GRANT"
//     message: "xxx message to", "load", "access to"
//     name:    any object name
//     type:    NtObjectType
//static boost::wregex   m_log_pattern (L".*");
static boost::wregex   m_log_pattern (L"\\d{4}.\\d\\d.\\d\\d\\s\\d\\d:\\d\\d:\\d\\d\\s+(.*)\\s+((?:STOP|DENY|READONLY|REDIRECT|GRANT))\\s+((?:[0-9a-fA-F]+ message to|load|access to))\\s+(.*)\\s+\\(([^\\)]*)\\)\\x0d\\x0a", boost::regex::perl | boost::regex::icase);

HINSTANCE              m_global_instance;
HANDLE                 m_termination_event;
ptr_to_work_thread     m_work_thread;
bool                   m_need_reload_setting        = true;
unsigned int           m_notification_filter        = notification_for_files;
bool                   m_enable_attack_notification = true;

ptr_to_process_manager m_process_manager;
ptr_to_log_wnd         m_notification_window;
ptr_to_attack_wnd      m_attack_window;

void create (HINSTANCE global_instance, HANDLE termination_event)
{
    destroy ();

    m_global_instance   = global_instance;
    m_termination_event = termination_event;
    m_work_thread       = ptr_to_work_thread (new work_thread (&work_thread_proc));
} // create

void destroy ()
{
    if (NULL != m_work_thread.get ())  
        m_work_thread->join ();
} // destroy

bool is_notification_enabled_files ()
{
    check_reload_setting ();
    
    return m_notification_filter & notification_for_files && 
		   !( ( m_notification_filter & notification_for_files_registry ) == notification_for_files_registry ) &&
		   !( ( m_notification_filter & notification_for_all ) == notification_for_all );
} // is_notification_enabled

bool is_notification_enabled_files_registry ()
{
    check_reload_setting ();
    
    return ( ( m_notification_filter & notification_for_files_registry ) == notification_for_files_registry ) && !( ( m_notification_filter & notification_for_all ) == notification_for_all );
} // is_notification_enabled


bool is_notification_enabled_all ()
{
    check_reload_setting ();
    
    return m_notification_filter & notification_for_all;
} // is_notification_enabled

void set_notification_filter (unsigned int notification_filter)
{
    check_reload_setting ();
    
    if (m_notification_filter != notification_filter)
        (config::Configurator::getNotificatorNode ())->setUInt (L"NotificationFilter", notification_filter);
        
    m_notification_filter = notification_filter;
} // set_notification_enabled

int get_notification_exposure_time(void)
{
	if ( m_notification_window == NULL ) return 1;

	int time = m_notification_window->get_stable_time() / 1000;
	if ( time == 0 ) time = 1;

	return time;
}

void set_notification_exposure_time(int exposure_time)
{
	if (m_notification_window == NULL) 
	    return;
	m_notification_window->set_stable_time(exposure_time * 1000);
}

bool is_attack_notification_enabled ()
{
    check_reload_setting ();
    
    return m_enable_attack_notification;
} // is_attack_notification_enabled

termination_type_t get_process_termination_type ()
{
    if (NULL != m_attack_window.get ())
        return m_attack_window->get_process_termination_type ();
        
    return gswui::logwnd::attack_wnd::termination_type_none;    
} // is_auto_process_terminate 

void set_attack_notification_enabled (bool enable_notification)
{
    check_reload_setting ();
    
    if (m_enable_attack_notification != enable_notification)
        (config::Configurator::getNotificatorNode ())->setBool (L"EnableAttackNotification", enable_notification);
        
    m_enable_attack_notification = enable_notification;
} // set_attack_notification_enabled

void set_process_termination_type (termination_type_t term_type)
{
    if (NULL != m_attack_window.get ())
        m_attack_window->set_process_termination_type (term_type);
} // set_auto_process_terminate

void select_bkg_color (notification_type_t notification_type, HWND hwnd)
{
    if (notification_type_notification == notification_type)
    {
        if (NULL != m_notification_window.get ())
        {
            m_notification_window->select_bkg_color (hwnd);
        }
    }
    else if (notification_type_attack == notification_type)
    {
        if (NULL != m_attack_window.get ())
        {
            m_attack_window->select_bkg_color (hwnd);
        }
    }
} // select_bkg_color

NtObjectType get_obj_type(const wstring &obj_type_str, const wstring &obj_name)
{
	if ( obj_type_str == L"File" ) {
		if ( obj_name.find_first_of(L"\\Device\\NamedPipe\\") != 0 )
			return nttFile;
		else
			return nttDevice;
	}
	if ( obj_type_str == L"Registry" ) return nttKey;
	if ( obj_type_str == L"SystemObject" ) return nttSystemObject;
	if ( obj_type_str == L"Process" ) return nttProcess;
	if ( obj_type_str == L"Device" ) return nttDevice;
	if ( obj_type_str == L"Network" ) return nttNetwork;
/*
	if ( obj_type_str == L"Debug" ) return nttDebug;
	if ( obj_type_str == L"Desktop" ) return nttDesktop;
	if ( obj_type_str == L"Directory" ) return nttDirectory;
	if ( obj_type_str == L"Event" ) return nttEvent;
	if ( obj_type_str == L"IoCompletion" ) return nttIoCompletion;
	if ( obj_type_str == L"Job" ) return nttJob;
	if ( obj_type_str == L"KeyedEvent" ) return nttKeyedEvent;
	if ( obj_type_str == L"Mutant" ) return nttMutant;
	if ( obj_type_str == L"Port" ) return nttPort;
	if ( obj_type_str == L"Profile" ) return nttProfile;
	if ( obj_type_str == L"Section" ) return nttSection;
	if ( obj_type_str == L"Semaphore" ) return nttSemaphore;
	if ( obj_type_str == L"SymbolicLink" ) return nttSymbolicLink;
	if ( obj_type_str == L"Thread" ) return nttThread;
	if ( obj_type_str == L"Token" ) return nttToken;
	if ( obj_type_str == L"Timer" ) return nttTimer;
	if ( obj_type_str == L"WaitablePort" ) return nttWaitablePort;
	if ( obj_type_str == L"WindowStation" ) return nttWindowStation;
	if ( obj_type_str == L"Any" ) return nttAny;
*/
	return nttUnknown;
}

bool is_type_match(const wstring &obj_type_str, const wstring &obj_name)
{
	return ( m_notification_filter & ( 1<<get_obj_type(obj_type_str, obj_name) ) );
}

int work_thread_proc ()
{
    m_process_manager = ptr_to_process_manager (new gswui::attackfilter::process_manager ()); 
    if (NULL == m_process_manager.get ())
        return -1;

//#ifdef _CB_TEST_DEBUG_
//    m_process_manager->add_process (L"notepad.exe", 3024);
//    m_process_manager->kill_process (L"notepad.exe");
//#endif // _CB_TEST_DEBUG_    

    m_notification_window = ptr_to_log_wnd (new notify_wnd (m_global_instance));
    m_attack_window       = ptr_to_attack_wnd (new attack_wnd (m_global_instance, m_process_manager));
        
    if (NULL == m_notification_window.get () || NULL == m_attack_window.get ())
    {
        m_notification_window.reset ();
        m_attack_window.reset ();
        m_process_manager.reset ();

        return -1;
    }
    
    gswui::attackfilter::create ();

#ifndef _CB_TEST_DEBUG_
    refresh_patterns ();
#endif // _CB_TEST_DEBUG_    
    
#ifdef _CB_TEST_DEBUG_
    int          count = 0;
    HANDLE       events[] = { m_termination_event };
#else
    Notification drv_notify;
    HANDLE       events[] = { m_termination_event, drv_notify.GetEvent() };    
#endif // _CB_TEST_DEBUG_    
    
    while (true)
    {
#ifdef _CB_TEST_DEBUG_
        DWORD wait_result = ::WaitForMultipleObjects (sizeof (events) / sizeof (events[0]), events, FALSE, 3000);
        if (WAIT_OBJECT_0 == wait_result) 
            break;
        
        const wchar_t* data [] = {
            L"2006.08.04 01:05:46 avant.exe rEADONLY access to |Device|NamedPipe|wkssvc (File)\r\n",
            L"2006.08.04 01:05:46 avant.exe rEADONLY access to \\Device\\NamedPipe\\wkssvc (File)\r\n",
            L"2006.08.04 01:05:46 avant.exe dENY access to \\Device\\Harddisk0\\Partition1 (Device)\r\n",
            L"2006.08.04 01:05:46 process explorer.exe sTOP access to \\Device\\Harddisk0\\Partition1 (Device)\r\n",
            L"2006.08.04 01:07:57 thebat.exe rEADONLY access to C:\\Program Files\\The Bat!\\MAIL\\An Ko - mail.ru\\ACCOUNT.M_R (File)\r\n",
            L"2006.08.04 01:08:05 thebat.exe rEDIRECT access to C:\\Documents and Settings\\andr\\Application Data\\The Bat!\\Gentle - gsw\\Inbox\\MESSAGES.TBB (File)\r\n"
        };
        
        wstring        log_data = data [count % (sizeof (data) / sizeof (data [0]))];
        
        ++count;
        
#else
        if (false == drv_notify.StartWait ())
            break;
            
        DWORD wait_result = ::WaitForMultipleObjects (sizeof (events) / sizeof (events[0]), events, FALSE, INFINITE);
        if (WAIT_OBJECT_0 == wait_result || (WAIT_OBJECT_0 + 1) != wait_result) 
            break;
            
        if (false == drv_notify.check_result ())
            break;
        
        wstring        log_data = drv_notify.get_message ();
#endif // _CB_TEST_DEBUG_

        check_reload_setting ();

        boost::wsmatch what;
        if (true == boost::regex_match (log_data, what, m_log_pattern, boost::match_default))
        {
            wstring  app_name;
            wstring  process_name;
            wstring  access_str;
            wstring  message;
            wstring  obj_name;
            wstring  obj_type_str;

            for (unsigned int i = 0; i < what.size (); ++i)
            {
                switch (i)
                {
                    case 1: // process name
                         process_name.assign (what [i].first, what [i].second);
                         break;
                    case 2: // access
                         access_str.assign (what [i].first, what [i].second);
                         break;     
                    case 3: // message
                         message.assign (what [i].first, what [i].second);
                         break;     
                    case 4: // object name
                         obj_name.assign (what [i].first, what [i].second);
                         break;
                    case 5: // object type
                         obj_type_str.assign (what [i].first, what [i].second);
                         break;     
                }
            } // for (...)
            
#ifdef _CB_TEST_DEBUG_
            app_name.assign (process_name);
#else
            app_name.assign (get_application_name (drv_notify));
#endif // _CB_TEST_DEBUG_
            
            wstring logwnd_message;
			//----Collect logs: Attacks and Notifications----------------------
			wstring result_message;
			bool IsAttack = gswui::attackfilter::is_attack (obj_name, obj_type_str, result_message);
			if (true == IsAttack)
                logcount::CollectNotify(drv_notify, 1);
			else
                logcount::CollectNotify(drv_notify, 2);
			//--------------------------------------
            
            if (true == is_type_match (obj_type_str, obj_name) && false == m_attack_window->is_visible ()) // is_notification_enabled ()
            {
                logwnd_message
                    .append (access_str)
                    .append (L" ")
                    .append (message)
                    .append (L" ")
                    .append (cut_string (obj_name, 32))
                    .append (L" (")
                    .append (obj_type_str)
                    .append (L")");
                m_notification_window->add_message (app_name, logwnd_message); 
            }
                
            if (true == is_attack_notification_enabled ())
            {
                logwnd_message.clear ();
                logwnd_message
                    .append (L".\nResource: ")
                    .append (cut_string (obj_name, 32));
                
#ifdef _CB_TEST_DEBUG_
                wstring result_message = L"attack detected";
                if (0 == (count % 3))
                {
                    m_process_manager->add_process (app_name, 0x1fffffff + count);
                    if (gswui::logwnd::attack_wnd::termination_type_auto == m_attack_window->get_process_termination_type ())
                        m_process_manager->kill_process (0x1fffffff + count);
                    
                    m_notification_window->hide ();
                    m_attack_window->add_message (app_name, result_message + logwnd_message);
                }
#else                
                if (true == IsAttack)
                {
                    m_process_manager->add_process (app_name, HandleToULong (drv_notify.get_process_id ()));
                    if (gswui::logwnd::attack_wnd::termination_type_auto == m_attack_window->get_process_termination_type ())
                        m_process_manager->kill_process (HandleToULong (drv_notify.get_process_id ()));
                    
                    m_notification_window->hide ();
                    m_attack_window->add_message (app_name, result_message + logwnd_message);
                }
#endif // _CB_TEST_DEBUG_                
            }
#ifndef _CB_TEST_DEBUG_
            else
            {
                if (true == IsAttack)
                {
                    m_process_manager->add_process (app_name, HandleToULong (drv_notify.get_process_id ()));
                    if (gswui::logwnd::attack_wnd::termination_type_auto == m_attack_window->get_process_termination_type ())
                        m_process_manager->kill_process (HandleToULong (drv_notify.get_process_id ()));
                }
            }
#endif // _CB_TEST_DEBUG_                                
		} 
		else 
		{
            //----Collect logs: ISOLATE----------------------
            logcount::CollectNotify(drv_notify, 3);
            //-----------------------------------------------
		}
    } // while (false == m_destroy_pending)
    
    gswui::attackfilter::destroy ();
    m_attack_window->destroy ();
    m_notification_window->destroy ();
    
    m_notification_window.reset ();
    m_attack_window.reset ();
    m_process_manager.reset ();
    
    return 0;
} // work_thread_proc

void refresh_patterns ()
{
    try
    {
        gswui::attackfilter::pattern_list patterns;
        Storage::IdsPatternItemList       db_pattern_items;
        
        Storage::GetIdsPatternsList (db_pattern_items);
        
        for (Storage::IdsPatternItemList::iterator i = db_pattern_items.begin(); i != db_pattern_items.end(); ++i) 
        {
            gswui::attackfilter::ptr_to_pattern_info pattern (new gswui::attackfilter::pattern_info ());
            
            if (NULL != pattern.get ())
            {
                pattern->m_pattern      = (*i)->Pattern;
                pattern->m_message      = (*i)->Message;
                pattern->m_pattern_type = db_pattern_type_to_internal_type ((*i)->PatternType);
                pattern->m_object_type  = db_object_type_to_internal_type ((*i)->ResType);
                
                patterns.push_back (pattern);
            }
        } // for (...)
        
        gswui::attackfilter::set_patterns (patterns);
    }
    catch (Storage::StorageException& e)
    {
        debugString ((L"\ngswui::notificator::refresh_patterns () StorageException: %s", e.getMessageAndCode ().c_str ()));
    }
} // refresh_patterns

gswui::attackfilter::pattern_type_t db_pattern_type_to_internal_type (Storage::IdsPatternType db_pattern_type)
{
    switch (db_pattern_type)
    {
        case Storage::ptnUnknown:
            return gswui::attackfilter::pattern_type_unknown;
        case Storage::ptnMacros:
            return gswui::attackfilter::pattern_type_macros;
        case Storage::ptnRegexp:
            return gswui::attackfilter::pattern_type_regexp;
        case Storage::ptnMix:
            return gswui::attackfilter::pattern_type_mix;
    }
    return gswui::attackfilter::pattern_type_unknown;
} // db_pattern_type_to_internal_type

gswui::attackfilter::object_type_t db_object_type_to_internal_type (NtObjectType nt_object_type)
{
    switch (nt_object_type)
    {
        case nttUnknown:   
            return gswui::attackfilter::object_type_unknown;
        case nttDebug:
            return gswui::attackfilter::object_type_debug;
        case nttDesktop:
            return gswui::attackfilter::object_type_desktop;
        case nttDirectory:
            return gswui::attackfilter::object_type_directory;
        case nttEvent:
            return gswui::attackfilter::object_type_event;
        case nttFile:
            return gswui::attackfilter::object_type_file;
        case nttIoCompletion:
            return gswui::attackfilter::object_type_io_completion;
        case nttJob:
            return gswui::attackfilter::object_type_job;
        case nttKey:
            return gswui::attackfilter::object_type_key;
        case nttKeyedEvent:
            return gswui::attackfilter::object_type_keyed_event;
        case nttMutant:
            return gswui::attackfilter::object_type_mutant;
        case nttPort:
            return gswui::attackfilter::object_type_port;
        case nttProcess:
            return gswui::attackfilter::object_type_process;
        case nttProfile:
            return gswui::attackfilter::object_type_profile;
        case nttSection:
            return gswui::attackfilter::object_type_section;
        case nttSemaphore:
            return gswui::attackfilter::object_type_semaphore;
        case nttSymbolicLink:
            return gswui::attackfilter::object_type_symbolic_link;
        case nttThread:
            return gswui::attackfilter::object_type_thread;
        case nttToken:
            return gswui::attackfilter::object_type_token;
        case nttTimer:
            return gswui::attackfilter::object_type_timer;
        case nttWaitablePort:
            return gswui::attackfilter::object_type_waitable_port;
        case nttWindowStation:
            return gswui::attackfilter::object_type_window_station;
        case nttDevice:
            return gswui::attackfilter::object_type_device;
        case nttDriver:
            return gswui::attackfilter::object_type_driver;
        case nttAny:
            return gswui::attackfilter::object_type_any;
        case nttNetwork:
            return gswui::attackfilter::object_type_network;
        case nttSystemObject:
            return gswui::attackfilter::object_type_system_object;
        case nttWindow:
            return gswui::attackfilter::object_type_window;
    }
    
    return gswui::attackfilter::object_type_unknown;
} // db_pattern_type_to_internal_type

wstring cut_string (const wstring& data, size_t length)
{
    if (0 >= length || data.size () <= length)
        return data;
        
    wstring cutted_data;
    size_t  data_length = data.size ();    
    size_t  end_index   = 0;
    
    if (wstring::npos != (end_index = data.rfind (L'\\')) || wstring::npos != (end_index = data.rfind (L'/')))
    {
        cutted_data
            .append (data.substr (0, ((data_length - end_index) > length) ? 0 : (length - (data_length - end_index))))
            .append (L"...")
            .append (data.substr (end_index, wstring::npos));
    }
    else
    {
        cutted_data
            .append (data.substr (0, 3))
            .append (L"...")
            .append (data.substr (data_length - length + 6, wstring::npos));
    }
    
    return cutted_data;
} // cut_string

wstring get_application_name (Notification& drv_notify)
{
	App::Application AppItem;
	App::Application::GetAppItem(drv_notify.get_app_id(), drv_notify.get_rule_id(), drv_notify.get_process_file_name(), AppItem);
	return AppItem.GetDisplayName();
} // get_application_name

void check_reload_setting ()
{
    if (true == m_need_reload_setting)
    {
        reload_setting ();
        m_need_reload_setting = false;
    }
} // check_reload_setting

void reload_setting ()
{
    config::Configurator::PtrToINode params = config::Configurator::getNotificatorNode ();
    if (NULL != params.get ())
    {
        if (true == params->checkValue (L"NotificationFilter"))
            m_notification_filter = params->getUInt (L"NotificationFilter");
        else
            params->setUInt (L"NotificationFilter", m_notification_filter);
            
        if (true == params->checkValue (L"EnableAttackNotification"))
            m_enable_attack_notification = params->getBool (L"EnableAttackNotification");
        else
            params->setBool (L"EnableAttackNotification", m_enable_attack_notification);
    } // if (NULL != params.get ())
} // reload_setting

} // namespace notificator {
} // namespace gswui {

