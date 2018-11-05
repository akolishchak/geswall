//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "attackfilter.h"

#include "commonlib/macro/macroresolver.h"

#ifndef BOOST_REGEX_NO_LIB
 #define BOOST_REGEX_NO_LIB
#endif // BOOST_REGEX_NO_LIB 
#include <boost/regex.hpp>

#include <algorithm>

namespace gswui {
namespace attackfilter {

typedef commonlib::sync::SyncObject::Locker  locker;
typedef commonlib::sync::SyncObject          sync_object;

bool           is_attack (const wstring& obj_name, object_type_t obj_type, wstring& result_message);
object_type_t  string2object_type (const wstring& obj_type_str);

static const wchar_t*  m_object_types_names [] = {
    L"Unknown",
    L"Debug",
    L"Desktop",
    L"Directory",
    L"Event",
    L"File",
    L"IoCompletion",
    L"Job",
    L"Registry",
    L"KeyedEvent",
    L"Mutant",
    L"Port",
    L"Process",
    L"Profile",
    L"Section",
    L"Semaphore",
    L"SymbolicLink",
    L"Thread",
    L"Token",
    L"Timer",
    L"WaitablePort",
    L"WindowStation",
    L"Device",
    L"Driver",
    L"Any",
    L"Network",
    L"SystemObject",
    L"Window"
};

sync_object         m_sync;
pattern_list        m_patterns;

void create ()
{

} // create

void destroy ()
{

} // destroy

void set_patterns (const pattern_list& patterns)
{
    locker sync_guard (m_sync);
    
    m_patterns.clear ();
    m_patterns.assign (patterns.begin (), patterns.end ());
} // set_patterns

bool is_attack (const wstring& obj_name, const wstring& obj_type, wstring& result_message)
{
    return is_attack (obj_name, string2object_type (obj_type), result_message);
} // is_attack

bool is_attack (const wstring& obj_name, object_type_t obj_type, wstring& result_message)
{
    locker sync_guard (m_sync);
    bool   result = false;
    
    for (pattern_list::const_iterator i = m_patterns.begin (); i != m_patterns.end (); ++i)
    {
        if ((*i)->m_object_type == obj_type)
        {
            wstring resolved_pattern;
            
            if (pattern_type_macros == (*i)->m_pattern_type || pattern_type_mix == (*i)->m_pattern_type)
                macro::process (resolved_pattern, (*i)->m_pattern, LongToHandle (GetCurrentProcessId()));
            else
                resolved_pattern.assign ((*i)->m_pattern);
                
            if (pattern_type_regexp == (*i)->m_pattern_type || pattern_type_mix == (*i)->m_pattern_type)
            {
                try
                {
                    boost::wregex compiled_pattern (resolved_pattern.c_str (), boost::regex::perl | boost::regex::icase);
                    wstring       obj_name_low = obj_name;
                    
                    //std::transform (obj_name_low.begin (), obj_name_low.end (), obj_name_low.begin (), tolower);
                    
                    if (true == boost::regex_match (obj_name_low, compiled_pattern, boost::match_default))
                    {
                        //gswui::logwnd::add_message (gswui::logwnd::MessageTypeAttackNotification, process_name, (*i)->m_message + append_message, L"GeSWall's Attacks Prevention");
                        result_message.append ((*i)->m_message);
                        result = true;
						break;
                    }
                }
                catch (...)
                {
                }
            }    
            else
            {
                if (0 == wcsnicmp (resolved_pattern.c_str (), obj_name.c_str (), resolved_pattern.size ()))
                {
                    //gswui::logwnd::add_message (gswui::logwnd::MessageTypeAttackNotification, process_name, (*i)->m_message + append_message, L"GeSWall's Attacks Prevention");
                    result_message.append ((*i)->m_message);
                    result = true;
					break;
                }
            }    
        }
    } // for (...)
    
    return result;
} // is_attack

object_type_t string2object_type (const wstring& obj_type_str)
{
    object_type_t obj_type = object_type_unknown;
    
    for (int i = 0; i < sizeof (m_object_types_names) / sizeof (wchar_t*); ++i)
    {
        if (0 == obj_type_str.compare (m_object_types_names [i]))
        {
            obj_type = static_cast <object_type_t> (i);
            break;
        }    
    } // for (...)
    
    return obj_type;
} // string2object_type


} // namespace attackfilter {
} // namespace gswui {
