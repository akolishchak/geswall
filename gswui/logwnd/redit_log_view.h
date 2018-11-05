//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef _interface_gswui_redit_log_view_h_
 #define _interface_gswui_redit_log_view_h_

#include "log_view.h"

#include <list>
 
namespace gswui {
namespace logwnd {

class redit_log_view;

class redit_log_view : public log_view
{
  //
  // types
  //
  public:
  protected:
    typedef boost::shared_ptr <wstring>             ptr_to_wstring;
    typedef std::list <ptr_to_wstring>              string_list;

  private:

  //
  // methods
  //
  public:
            redit_log_view (HINSTANCE global_instance);
   virtual ~redit_log_view ();

   virtual  bool create (HWND parent_window, int control_id);
   virtual  void destroy ();

   virtual  void resize (int x, int y, int width, int height);
   virtual  void repaint ();
   virtual  void set_background_color (COLORREF color);

   virtual  void   set_max_queue_size (size_t max_queue_size);
   virtual  size_t get_max_queue_size ();

   virtual  void add_message (const wstring& app_name, const wstring& message, int font_size_percent, COLORREF font_color);
   virtual  void clean ();

   virtual  LRESULT on_notify (HWND hwnd_parent, NMHDR* nm_hdr);
   
  protected:
               redit_log_view (const redit_log_view& right) {};
   redit_log_view& operator= (const redit_log_view& right) { return *this; }

  private:
  
  //
  // data
  //
  public:
  protected:
   HINSTANCE    m_global_instance;
   HWND         m_parent_window;
   HWND         m_hwnd_control;

   string_list  m_log_queue;
   size_t       m_max_queue_size;

  private:
}; // class redit_log_view

} // namespace logwnd {
} // namespace gswui {

#endif // _interface_gswui_log_view_h__