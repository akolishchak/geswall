//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswui_notificator_h__
 #define __gswui_notificator_h__

#include "gswui/logwnd/attack_wnd.h"

namespace gswui {
namespace notificator {

typedef gswui::logwnd::attack_wnd::termination_type_t termination_type_t;

enum notification_type_t
{
    notification_type_text = 1,
    notification_type_notification,
    notification_type_attack
}; // enum notification_type_t

void create (HINSTANCE global_instance, HANDLE termination_event);
void destroy ();

enum {
	notification_for_files = 1<<nttFile,
	notification_for_files_registry = 1<<nttFile | 1<<nttKey,
	notification_for_all = 0xffffffff
};


bool is_notification_enabled_files ();
bool is_notification_enabled_files_registry ();
bool is_notification_enabled_all ();
bool is_attack_notification_enabled ();
termination_type_t get_process_termination_type ();

void set_notification_filter (unsigned int notification_filter);
int  get_notification_exposure_time(void);
void set_notification_exposure_time(int exposure_time);
void set_attack_notification_enabled (bool enable_notification);
void set_process_termination_type (termination_type_t term_type);

void select_bkg_color (notification_type_t notification_type, HWND hwnd);

} // namespace notificator {
} // namespace gswui {

#endif // __gswui_notificator_h__