//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswui_attackfilter_h__
 #define __gswui_attackfilter_h__

#include <string>
#include <list>

#include "commonlib/commondefs.h"

namespace gswui {
namespace attackfilter {

typedef std::wstring                         wstring;

enum object_type_t
{
    object_type_unknown        = 0,
    object_type_debug          = 1,
    object_type_desktop        = 2,
    object_type_directory      = 3,
    object_type_event          = 4,
    object_type_file           = 5,
    object_type_io_completion  = 6,
    object_type_job            = 7,
    object_type_key            = 8,
    object_type_keyed_event    = 9,
    object_type_mutant         = 10,
    object_type_port           = 11,
    object_type_process        = 12,
    object_type_profile        = 13,
    object_type_section        = 14,
    object_type_semaphore      = 15,
    object_type_symbolic_link  = 16,
    object_type_thread         = 17,
    object_type_token          = 18,
    object_type_timer          = 19,
    object_type_waitable_port  = 20,
    object_type_window_station = 21,
    object_type_device         = 22,
    object_type_driver         = 23,
    object_type_any            = 24,
    object_type_network        = 25,
    object_type_system_object  = 26,
    object_type_window         = 27
}; // enum object_type_t

enum pattern_type_t
{
    pattern_type_unknown  = -1,
    pattern_type_macros   = 0,
    pattern_type_regexp,
    pattern_type_mix
}; // enum pattern_type_t

struct pattern_info
{
    wstring         m_pattern;
    wstring         m_message;
    pattern_type_t  m_pattern_type;
    object_type_t   m_object_type;
}; // struct pattern_info

typedef boost::shared_ptr <pattern_info>     ptr_to_pattern_info;
typedef std::list <ptr_to_pattern_info>      pattern_list;

void create ();
void destroy ();

void set_patterns (const pattern_list& patterns);
bool is_attack (const wstring& obj_name, const wstring& obj_type, wstring& result_message);

} // namespace attackfilter {
} // namespace gswui {

#endif // __gswui_attackfilter_h__